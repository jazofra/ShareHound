// Package collector provides data collection functionality for ShareHound.
package collector

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/specterops/sharehound/internal/graph"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/rules"
	"github.com/specterops/sharehound/internal/smb"
	"github.com/specterops/sharehound/pkg/kinds"
)

// TraversalCounts holds counts of processed items during traversal.
type TraversalCounts struct {
	TotalFiles           int64
	SkippedFiles         int64
	ProcessedFiles       int64
	TotalDirectories     int64
	SkippedDirectories   int64
	ProcessedDirectories int64
}

// Add adds another TraversalCounts to this one.
func (c *TraversalCounts) Add(other TraversalCounts) {
	c.TotalFiles += other.TotalFiles
	c.SkippedFiles += other.SkippedFiles
	c.ProcessedFiles += other.ProcessedFiles
	c.TotalDirectories += other.TotalDirectories
	c.SkippedDirectories += other.SkippedDirectories
	c.ProcessedDirectories += other.ProcessedDirectories
}

// WorkerResults holds shared worker result counters.
type WorkerResults struct {
	Success int64
	Errors  int64

	TasksTotal    int64
	TasksPending  int64
	TasksFinished int64

	SharesTotal     int64
	SharesProcessed int64
	SharesSkipped   int64
	SharesPending   int64

	FilesTotal     int64
	FilesProcessed int64
	FilesSkipped   int64
	FilesPending   int64

	DirectoriesTotal     int64
	DirectoriesProcessed int64
	DirectoriesSkipped   int64
	DirectoriesPending   int64

	// Active tracking for visibility
	ActiveHosts       int64           // Number of hosts currently being processed
	ActiveHostNames   map[string]bool // Names of hosts currently being processed
	ActiveConnections int64           // Number of active SMB connections
}

// CollectContentsInShare collects contents of a share using BFS traversal.
func CollectContentsInShare(
	smbSession *smb.SMBSession,
	ogc *graph.OpenGraphContext,
	rulesEval *rules.Evaluator,
	workerResults *WorkerResults,
	resultsLock *sync.Mutex,
	log logger.LoggerInterface,
	maxDepth int,
	timeoutFlag *atomic.Bool,
) TraversalCounts {
	log.Debug("Collecting contents in share using BFS traversal...")

	return collectContentsAtDepth(
		smbSession,
		ogc,
		rulesEval,
		workerResults,
		resultsLock,
		log,
		0,
		maxDepth,
		timeoutFlag,
	)
}

// collectContentsAtDepth performs recursive BFS traversal.
func collectContentsAtDepth(
	smbSession *smb.SMBSession,
	ogc *graph.OpenGraphContext,
	rulesEval *rules.Evaluator,
	workerResults *WorkerResults,
	resultsLock *sync.Mutex,
	log logger.LoggerInterface,
	depth int,
	maxDepth int,
	timeoutFlag *atomic.Bool,
) TraversalCounts {
	counts := TraversalCounts{}

	// Check timeout
	if timeoutFlag != nil && timeoutFlag.Load() {
		log.Debug("Timeout reached, stopping directory traversal")
		return counts
	}

	// Check depth limit
	if maxDepth > 0 && depth >= maxDepth {
		return counts
	}

	// Set share in SMB session
	shareNode := ogc.GetShare()
	if shareNode == nil {
		return counts
	}
	shareName := shareNode.GetStringProperty("displayName")
	if shareName == "" {
		return counts
	}

	if err := smbSession.SetShare(shareName); err != nil {
		log.Debug("Error setting share: " + err.Error())
		return counts
	}

	// Set depth in rules context
	rulesEval.SetDepth(depth)

	log.IncrementIndent()
	defer log.DecrementIndent()

	// Get path from root
	currentPath := ogc.GetStringPathFromRoot()

	// List contents
	contents, err := smbSession.ListContents(currentPath)
	if err != nil {
		log.Debug(fmt.Sprintf("Error listing contents of '%s': %v", currentPath, err))
		return counts
	}

	// Directories to explore at next level
	var dirsToExplore []struct {
		node   *graph.Node
		rights graph.ShareRights
	}

	hostName := smbSession.GetRemoteName()

	for name, info := range contents {
		// Check timeout periodically within the iteration loop.
		// Without this, a directory with thousands of entries would process
		// all of them even after the host timeout has fired.
		if timeoutFlag != nil && timeoutFlag.Load() {
			log.Debug("Timeout reached, stopping content enumeration")
			break
		}

		// Skip . and ..
		if name == "." || name == ".." {
			continue
		}

		// Build full path
		fullPath := name
		if currentPath != "" {
			fullPath = filepath.Join(currentPath, name)
		}

		// Build UNC path
		uncPath := fmt.Sprintf("\\\\%s\\%s\\%s", hostName, shareName, fullPath)

		// Collect NTFS rights
		elementRights, _ := CollectNTFSRights(smbSession, ogc, fullPath, log)
		ogc.SetElementRights(elementRights)

		if info.IsDir {
			// Directory
			ruleDir := &rules.RuleObjectDirectory{
				Name: name,
				Path: fullPath,
			}

			// Check if we can explore
			if !rulesEval.CanExplore(ruleDir) {
				counts.SkippedDirectories++
				continue
			}

			counts.TotalDirectories++

			// Track pending
			if resultsLock != nil {
				resultsLock.Lock()
				workerResults.DirectoriesPending++
				resultsLock.Unlock()
			}

			// Create directory node
			dirNode := graph.NewNode(
				"DIR:"+uncPath,
				kinds.NodeKindDirectory,
			).SetProperty("name", name).
				SetProperty("Path", fullPath).
				SetProperty("UNCPath", uncPath)

			// Add timestamp properties if available
			if !info.CreatedTime.IsZero() {
				dirNode.SetProperty("createdAt", info.CreatedTime.Unix())
			}
			if !info.ModifiedTime.IsZero() {
				dirNode.SetProperty("modifiedAt", info.ModifiedTime.Unix())
			}

			ogc.SetElement(dirNode)

			// Add directory to graph if rules allow processing
			if rulesEval.CanProcess(ruleDir) {
				ogc.AddPathToGraph()
				counts.ProcessedDirectories++

				// Decrement pending
				if resultsLock != nil {
					resultsLock.Lock()
					workerResults.DirectoriesPending--
					resultsLock.Unlock()
				}
			}

			// Add to list for next level
			dirsToExplore = append(dirsToExplore, struct {
				node   *graph.Node
				rights graph.ShareRights
			}{dirNode, elementRights})

		} else {
			// File
			ext := strings.ToLower(filepath.Ext(name))

			ruleFile := &rules.RuleObjectFile{
				Name:      name,
				Path:      fullPath,
				Size:      info.Size,
				Extension: ext,
			}

			// Check if we can process
			if !rulesEval.CanProcess(ruleFile) {
				counts.SkippedFiles++
				continue
			}

			counts.TotalFiles++

			// Track pending
			if resultsLock != nil {
				resultsLock.Lock()
				workerResults.FilesPending++
				resultsLock.Unlock()
			}

			log.Debug("📄 " + name)

			// Create file node
			fileNode := graph.NewNode(
				"FILE:"+uncPath,
				kinds.NodeKindFile,
			).SetProperty("name", name).
				SetProperty("Path", fullPath).
				SetProperty("UNCPath", uncPath).
				SetProperty("fileSize", info.Size).
				SetProperty("extension", ext)

			// Add timestamp properties if available
			if !info.CreatedTime.IsZero() {
				fileNode.SetProperty("createdAt", info.CreatedTime.Unix())
			}
			if !info.ModifiedTime.IsZero() {
				fileNode.SetProperty("modifiedAt", info.ModifiedTime.Unix())
			}

			ogc.SetElement(fileNode)

			if rulesEval.CanProcess(ruleFile) {
				ogc.AddPathToGraph()
				counts.ProcessedFiles++

				// Decrement pending
				if resultsLock != nil {
					resultsLock.Lock()
					workerResults.FilesPending--
					resultsLock.Unlock()
				}
			}
		}

		ogc.ClearElement()
	}

	// Process directories at next level (BFS)
	for _, dir := range dirsToExplore {
		// Check timeout
		if timeoutFlag != nil && timeoutFlag.Load() {
			log.Debug("Timeout reached, skipping remaining directories")
			break
		}

		log.Debug("📁 " + dir.node.GetStringProperty("name"))

		ogc.PushPath(dir.node, dir.rights)

		subCounts := collectContentsAtDepth(
			smbSession,
			ogc,
			rulesEval,
			workerResults,
			resultsLock,
			log,
			depth+1,
			maxDepth,
			timeoutFlag,
		)

		counts.Add(subCounts)

		// Update worker results
		if resultsLock != nil {
			resultsLock.Lock()
			workerResults.FilesTotal += subCounts.TotalFiles
			workerResults.FilesSkipped += subCounts.SkippedFiles
			workerResults.FilesProcessed += subCounts.ProcessedFiles
			workerResults.DirectoriesTotal += subCounts.TotalDirectories
			workerResults.DirectoriesSkipped += subCounts.SkippedDirectories
			workerResults.DirectoriesProcessed += subCounts.ProcessedDirectories
			workerResults.DirectoriesPending--
			resultsLock.Unlock()
		}

		ogc.PopPath()
	}

	return counts
}
