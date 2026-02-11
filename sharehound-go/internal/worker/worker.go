// Package worker provides worker pool and task management.
package worker

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/specterops/sharehound/internal/collector"
	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/credentials"
	"github.com/specterops/sharehound/internal/graph"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/rules"
	"github.com/specterops/sharehound/internal/smb"
	"github.com/specterops/sharehound/internal/targets"
	"github.com/specterops/sharehound/internal/utils"
	"github.com/specterops/sharehound/pkg/kinds"
	"golang.org/x/sync/semaphore"
)

// Options holds worker configuration options.
type Options struct {
	Creds             *credentials.Credentials
	Timeout           time.Duration
	HostTimeout       time.Duration
	AdvertisedName    string
	MaxWorkersPerHost int
	GlobalMaxWorkers  int
	Depth             int
	Nameserver        string
	Logfile           string
}

// ProcessTarget processes a single target host.
func ProcessTarget(
	target targets.Target,
	opts *Options,
	cfg *config.Config,
	og *graph.OpenGraph,
	parsedRules []rules.Rule,
	results *collector.WorkerResults,
	resultsLock *sync.Mutex,
) {
	log := logger.NewLogger(cfg, opts.Logfile)

	// Resolve FQDN if needed
	host := target.Value
	remoteName := target.Value

	// Track active host (using target.Value as the display name)
	resultsLock.Lock()
	results.ActiveHosts++
	if results.ActiveHostNames == nil {
		results.ActiveHostNames = make(map[string]bool)
	}
	results.ActiveHostNames[target.Value] = true
	resultsLock.Unlock()
	defer func() {
		resultsLock.Lock()
		results.ActiveHosts--
		delete(results.ActiveHostNames, target.Value)
		resultsLock.Unlock()
	}()

	// Set up host timeout FIRST - before any network operations
	var timeoutFlag atomic.Bool
	timeoutFlag.Store(false)
	var hostTimeoutTimer *time.Timer
	var timeoutTicker *time.Ticker

	// Create connection pool early so timeout can close connections
	pool := NewConnectionPool(opts.MaxWorkersPerHost)
	defer pool.CloseAll()

	if opts.HostTimeout > 0 {
		hostTimeoutTimer = time.AfterFunc(opts.HostTimeout, func() {
			timeoutFlag.Store(true)
			// Use stderr directly to ensure visibility (progress bar may overwrite log output)
			fmt.Fprintf(os.Stderr, "\n\n=== HOST TIMEOUT === %s timed out after %v ===\n\n", host, opts.HostTimeout)
			log.Warning(fmt.Sprintf("Host timeout reached for %s, forcing connection closure", host))
			// Force close all connections to unblock any stuck SMB operations
			pool.ForceCloseAll()

			// Keep closing any new connections every 500ms until processing stops
			timeoutTicker = time.NewTicker(500 * time.Millisecond)
			go func() {
				for range timeoutTicker.C {
					pool.ForceCloseAll()
				}
			}()
		})
		defer func() {
			hostTimeoutTimer.Stop()
			if timeoutTicker != nil {
				timeoutTicker.Stop()
			}
		}()
	}

	if target.Type == "fqdn" {
		if opts.Nameserver != "" || opts.Creds.Domain != "" {
			resolved, err := utils.DNSResolve(target.Value, opts.Nameserver, "", opts.Timeout)
			if err != nil || resolved == "" {
				log.Debug("Failed to resolve domain name: " + target.Value)
				resultsLock.Lock()
				results.Errors++
				results.TasksTotal++
				results.TasksFinished++
				resultsLock.Unlock()
				return
			}
			host = resolved
		}
	}

	// Check timeout before port check
	if timeoutFlag.Load() {
		return
	}

	// Check if port 445 is open
	ok, err := utils.IsPortOpen(host, 445, opts.Timeout)
	if !ok {
		log.Debug(fmt.Sprintf("Port 445 is not open on %s: %v", host, err))
		resultsLock.Lock()
		results.Errors++
		results.TasksTotal++
		results.TasksFinished++
		resultsLock.Unlock()
		return
	}

	// Check timeout before connection
	if timeoutFlag.Load() {
		return
	}

	// Get initial connection to discover shares
	conn, err := pool.GetConnection(host, remoteName, opts.Creds, opts.Timeout, opts.AdvertisedName, cfg, log)
	if err != nil {
		log.Debug("Failed to initialize SMB session: " + err.Error())
		resultsLock.Lock()
		results.Errors++
		results.TasksTotal++
		results.TasksFinished++
		resultsLock.Unlock()
		return
	}

	// Check timeout before listing shares
	if timeoutFlag.Load() {
		pool.ReturnConnection(host, conn)
		return
	}

	// List shares
	shares, err := conn.ListShares()
	if err != nil {
		log.Debug("Failed to list shares: " + err.Error())
		pool.ReturnConnection(host, conn)
		resultsLock.Lock()
		results.Errors++
		results.TasksTotal++
		results.TasksFinished++
		resultsLock.Unlock()
		return
	}

	log.Debug(fmt.Sprintf("Found %d shares on %s", len(shares), host))

	// Update task counters
	resultsLock.Lock()
	results.TasksTotal += int64(len(shares))
	results.TasksPending += int64(len(shares))
	results.SharesPending += int64(len(shares))
	resultsLock.Unlock()

	if len(shares) == 0 {
		pool.ReturnConnection(host, conn)
		resultsLock.Lock()
		results.Success++
		results.TasksTotal++
		results.TasksFinished++
		resultsLock.Unlock()
		return
	}

	pool.ReturnConnection(host, conn)

	// Create semaphore for per-host concurrency
	hostSem := semaphore.NewWeighted(int64(opts.MaxWorkersPerHost))

	// Create a cancellable context for semaphore acquisition.
	// When the host timeout fires, cancel this context so goroutines
	// waiting on hostSem.Acquire are immediately unblocked.
	semCtx, semCancel := context.WithCancel(context.Background())
	defer semCancel()

	// done is closed when ProcessTarget returns, so the watcher goroutine exits cleanly
	// even if the host completes before the timeout fires.
	done := make(chan struct{})
	defer close(done)

	// Hook into the timeout to cancel the semaphore context
	if opts.HostTimeout > 0 {
		origTimeoutFlag := &timeoutFlag
		go func() {
			// Wait until either the timeout fires or processing finishes
			for !origTimeoutFlag.Load() {
				select {
				case <-done:
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
			semCancel()
		}()
	}

	// Process shares
	var wg sync.WaitGroup
	startTime := time.Now()

	var totalShareCount, skippedSharesCount int64
	var totalFileCount, skippedFilesCount, processedFilesCount int64
	var totalDirCount, skippedDirsCount, processedDirsCount int64

	for shareName, shareInfo := range shares {
		wg.Add(1)
		go func(name string, info smb.ShareInfo) {
			defer wg.Done()

			// Acquire semaphore — uses cancellable context so host timeout
			// unblocks all waiting goroutines immediately
			if err := hostSem.Acquire(semCtx, 1); err != nil {
				// Context cancelled (host timeout) or other error
				resultsLock.Lock()
				results.TasksPending--
				results.TasksFinished++
				resultsLock.Unlock()
				return
			}
			defer hostSem.Release(1)

			// Check timeout
			if timeoutFlag.Load() {
				resultsLock.Lock()
				results.TasksPending--
				results.TasksFinished++
				resultsLock.Unlock()
				atomic.AddInt64(&skippedSharesCount, 1)
				return
			}

			// Process the share
			counts := processShare(
				name, info, host, remoteName,
				opts, cfg, og, parsedRules,
				pool, results, resultsLock, log, &timeoutFlag,
			)

			atomic.AddInt64(&totalShareCount, 1)
			atomic.AddInt64(&totalFileCount, counts.TotalFiles)
			atomic.AddInt64(&skippedFilesCount, counts.SkippedFiles)
			atomic.AddInt64(&processedFilesCount, counts.ProcessedFiles)
			atomic.AddInt64(&totalDirCount, counts.TotalDirectories)
			atomic.AddInt64(&skippedDirsCount, counts.SkippedDirectories)
			atomic.AddInt64(&processedDirsCount, counts.ProcessedDirectories)

			resultsLock.Lock()
			results.TasksPending--
			results.TasksFinished++
			resultsLock.Unlock()
		}(shareName, shareInfo)
	}

	wg.Wait()

	elapsed := time.Since(startTime)

	// Update results
	resultsLock.Lock()
	results.SharesTotal += totalShareCount + skippedSharesCount
	results.SharesProcessed += totalShareCount
	results.SharesSkipped += skippedSharesCount
	results.SharesPending -= totalShareCount + skippedSharesCount
	results.FilesTotal += totalFileCount + skippedFilesCount
	results.FilesProcessed += processedFilesCount
	results.FilesSkipped += skippedFilesCount
	results.DirectoriesTotal += totalDirCount + skippedDirsCount
	results.DirectoriesProcessed += processedDirsCount
	results.DirectoriesSkipped += skippedDirsCount
	results.Success++
	results.TasksFinished++
	resultsLock.Unlock()

	log.Info(fmt.Sprintf("Target %s completed: %d shares, %d files, %d directories in %s",
		host, totalShareCount, totalFileCount, totalDirCount, utils.DeltaTime(elapsed)))
}

// processShare processes a single share.
func processShare(
	shareName string,
	shareInfo smb.ShareInfo,
	host, remoteName string,
	opts *Options,
	cfg *config.Config,
	og *graph.OpenGraph,
	parsedRules []rules.Rule,
	pool *ConnectionPool,
	results *collector.WorkerResults,
	resultsLock *sync.Mutex,
	log logger.LoggerInterface,
	timeoutFlag *atomic.Bool,
) collector.TraversalCounts {
	counts := collector.TraversalCounts{}

	// Check timeout immediately before doing any work
	if timeoutFlag != nil && timeoutFlag.Load() {
		return counts
	}

	taskLog := logger.NewTaskLogger(log.(*logger.Logger), fmt.Sprintf("%s:%s", remoteName, shareName))

	// Create rules evaluator
	rulesEval := rules.NewEvaluator(parsedRules)

	// Check if share should be explored
	ruleShare := &rules.RuleObjectShare{
		Name:   shareName,
		Hidden: len(shareName) > 0 && shareName[len(shareName)-1] == '$',
	}
	rulesEval.SetShare(ruleShare)

	if !rulesEval.CanExplore(ruleShare) {
		taskLog.Debug("Skipping share: " + shareName)
		return counts
	}

	// Check timeout before getting connection
	if timeoutFlag != nil && timeoutFlag.Load() {
		return counts
	}

	// Get connection
	conn, err := pool.GetConnection(host, remoteName, opts.Creds, opts.Timeout, opts.AdvertisedName, cfg, taskLog)
	if err != nil {
		taskLog.Debug("Failed to get connection: " + err.Error())
		return counts
	}
	defer pool.ReturnConnection(host, conn)

	// Check timeout after getting connection (might have been waiting)
	if timeoutFlag != nil && timeoutFlag.Load() {
		return counts
	}

	// Create OpenGraph context
	ogc := graph.NewOpenGraphContext(og, taskLog)

	// Create host node
	hostNode := graph.NewNode(host, kinds.NodeKindNetworkShareHost).
		SetProperty("name", host)
	ogc.SetHost(hostNode)

	// Create share node
	shareID := fmt.Sprintf("\\\\%s\\%s\\", host, shareName)
	shareNode := graph.NewNode(shareID, kinds.NodeKindNetworkShareSMB).
		SetProperty("displayName", shareName).
		SetProperty("description", shareInfo.Comment).
		SetProperty("hidden", ruleShare.Hidden)
	ogc.SetShare(shareNode)

	// Set share in SMB session
	if err := conn.SetShare(shareName); err != nil {
		taskLog.Debug("Failed to set share: " + err.Error())
		return counts
	}

	// Collect share rights
	shareRights, err := collector.CollectShareRights(conn, shareName, taskLog)
	if err != nil {
		taskLog.Debug("Error collecting share rights: " + err.Error())
	}
	ogc.SetShareRights(shareRights)

	// Check if share should be processed
	if rulesEval.CanProcess(ruleShare) {
		ogc.AddPathToGraph()
	}

	// Collect contents
	counts = collector.CollectContentsInShare(
		conn,
		ogc,
		rulesEval,
		results,
		resultsLock,
		taskLog,
		opts.Depth,
		timeoutFlag,
	)

	return counts
}
