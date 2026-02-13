// Package status provides progress tracking and display.
package status

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/specterops/sharehound/internal/collector"
)

// ProgressTracker tracks and displays progress.
type ProgressTracker struct {
	results     *collector.WorkerResults
	resultsLock *sync.Mutex
	totalHosts  int
	startTime   time.Time
	done        chan bool
	lastUpdate  time.Time
	lastHosts   int64
}

// NewProgressTracker creates a new ProgressTracker.
func NewProgressTracker(results *collector.WorkerResults, lock *sync.Mutex, totalHosts int) *ProgressTracker {
	return &ProgressTracker{
		results:     results,
		resultsLock: lock,
		totalHosts:  totalHosts,
		startTime:   time.Now(),
		done:        make(chan bool),
	}
}

// Start starts the progress display loop.
func (p *ProgressTracker) Start() {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-p.done:
				return
			case <-ticker.C:
				p.printStatus()
			}
		}
	}()
}

// printStatus prints a single-line status update.
func (p *ProgressTracker) printStatus() {
	p.resultsLock.Lock()
	hostsDone := p.results.Success + p.results.Errors
	hostsActive := p.results.ActiveHosts
	sharesDone := p.results.SharesProcessed
	sharesTotal := p.results.SharesTotal
	filesDone := p.results.FilesProcessed
	dirsDone := p.results.DirectoriesProcessed
	errors := p.results.Errors
	// Copy active host names for display
	var activeHostNames []string
	for name := range p.results.ActiveHostNames {
		activeHostNames = append(activeHostNames, name)
	}
	p.resultsLock.Unlock()

	elapsed := time.Since(p.startTime)

	// Calculate rate
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		rate = float64(hostsDone) / elapsed.Minutes()
	}

	// Calculate ETA
	eta := "calculating..."
	if rate > 0 && hostsDone > 0 {
		remaining := p.totalHosts - int(hostsDone)
		etaMinutes := float64(remaining) / rate
		if etaMinutes < 60 {
			eta = fmt.Sprintf("%.0fm", etaMinutes)
		} else {
			eta = fmt.Sprintf("%.1fh", etaMinutes/60)
		}
	}

	// Build progress bar
	pct := float64(0)
	if p.totalHosts > 0 {
		pct = float64(hostsDone) / float64(p.totalHosts) * 100
	}
	barWidth := 25
	filled := int(pct / 100 * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// Clear line and print status
	fmt.Printf("\r\033[K[%s] %5.1f%% │ Hosts: %d/%d (active: %d) │ Shares: %d │ Files: %d │ Dirs: %d │ Errors: %d │ Rate: %.1f/min │ ETA: %s",
		bar,
		pct,
		hostsDone,
		p.totalHosts,
		hostsActive,
		sharesDone,
		filesDone,
		dirsDone,
		errors,
		rate,
		eta,
	)

	// Check for potential stuck state
	if hostsActive > 0 && hostsDone == p.lastHosts && time.Since(p.lastUpdate) > 30*time.Second {
		// Show which hosts are slow
		if len(activeHostNames) > 0 {
			if len(activeHostNames) <= 3 {
				fmt.Printf(" [!SLOW: %s]", strings.Join(activeHostNames, ", "))
			} else {
				fmt.Printf(" [!SLOW: %s +%d more]", strings.Join(activeHostNames[:3], ", "), len(activeHostNames)-3)
			}
		} else {
			fmt.Printf(" [!SLOW]")
		}
	}

	if hostsDone != p.lastHosts {
		p.lastHosts = hostsDone
		p.lastUpdate = time.Now()
	}

	// Show warning if active hosts is 0 but not done
	if hostsActive == 0 && int(hostsDone) < p.totalHosts && sharesTotal > 0 {
		fmt.Printf(" [IDLE?]")
	}
}

// Stop stops the progress display.
func (p *ProgressTracker) Stop() {
	close(p.done)
	fmt.Println() // New line after progress
}

// PrintFinalSummary prints the final summary.
func PrintFinalSummary(results *collector.WorkerResults, lock *sync.Mutex) {
	lock.Lock()
	defer lock.Unlock()

	fmt.Println("\n" + strings.Repeat("─", 60))
	fmt.Println("                      SCAN COMPLETE")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("  Hosts:       %d successful, %d errors\n",
		results.Success, results.Errors)
	fmt.Printf("  Shares:      %d processed, %d skipped (total: %d)\n",
		results.SharesProcessed, results.SharesSkipped, results.SharesTotal)
	fmt.Printf("  Files:       %d processed, %d skipped (total: %d)\n",
		results.FilesProcessed, results.FilesSkipped, results.FilesTotal)
	fmt.Printf("  Directories: %d processed, %d skipped (total: %d)\n",
		results.DirectoriesProcessed, results.DirectoriesSkipped, results.DirectoriesTotal)
	fmt.Println(strings.Repeat("─", 60))
}

// PrintStatus prints the current status to stdout (for logging).
func PrintStatus(results *collector.WorkerResults, lock *sync.Mutex, elapsed time.Duration) {
	lock.Lock()
	defer lock.Unlock()

	fmt.Printf("[status] Hosts: %d (active: %d) | Shares: %d | Files: %d | Dirs: %d | Errors: %d | Time: %s\n",
		results.Success+results.Errors,
		results.ActiveHosts,
		results.SharesProcessed,
		results.FilesProcessed,
		results.DirectoriesProcessed,
		results.Errors,
		formatDuration(elapsed),
	)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
