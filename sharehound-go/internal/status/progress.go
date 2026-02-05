// Package status provides progress tracking and display.
package status

import (
	"fmt"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/specterops/sharehound/internal/collector"
	"github.com/specterops/sharehound/internal/utils"
)

// ProgressTracker tracks and displays progress.
type ProgressTracker struct {
	results     *collector.WorkerResults
	resultsLock *sync.Mutex
	totalHosts  int
	bars        []*progressbar.ProgressBar
	done        chan bool
}

// NewProgressTracker creates a new ProgressTracker.
func NewProgressTracker(results *collector.WorkerResults, lock *sync.Mutex, totalHosts int) *ProgressTracker {
	return &ProgressTracker{
		results:     results,
		resultsLock: lock,
		totalHosts:  totalHosts,
		done:        make(chan bool),
	}
}

// Start starts the progress display loop.
func (p *ProgressTracker) Start() {
	// Create progress bars
	hostBar := progressbar.NewOptions(p.totalHosts,
		progressbar.OptionSetDescription("Hosts    "),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	shareBar := progressbar.NewOptions(100,
		progressbar.OptionSetDescription("Shares   "),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
	)

	fileBar := progressbar.NewOptions(100,
		progressbar.OptionSetDescription("Files    "),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
	)

	dirBar := progressbar.NewOptions(100,
		progressbar.OptionSetDescription("Dirs     "),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
	)

	p.bars = []*progressbar.ProgressBar{hostBar, shareBar, fileBar, dirBar}

	go func() {
		ticker := time.NewTicker(125 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-p.done:
				return
			case <-ticker.C:
				p.update()
			}
		}
	}()
}

// update updates the progress display.
func (p *ProgressTracker) update() {
	p.resultsLock.Lock()
	hostsDone := p.results.Success + p.results.Errors
	sharesTot := p.results.SharesTotal
	sharesDone := p.results.SharesProcessed + p.results.SharesSkipped
	filesTot := p.results.FilesTotal
	filesDone := p.results.FilesProcessed + p.results.FilesSkipped
	dirsTot := p.results.DirectoriesTotal
	dirsDone := p.results.DirectoriesProcessed + p.results.DirectoriesSkipped
	p.resultsLock.Unlock()

	// Update host bar
	p.bars[0].ChangeMax(p.totalHosts)
	p.bars[0].Set(int(hostsDone))

	// Update share bar
	if sharesTot > 0 {
		p.bars[1].ChangeMax(int(sharesTot))
		p.bars[1].Set(int(sharesDone))
	}

	// Update file bar
	if filesTot > 0 {
		p.bars[2].ChangeMax(int(filesTot))
		p.bars[2].Set(int(filesDone))
	}

	// Update dir bar
	if dirsTot > 0 {
		p.bars[3].ChangeMax(int(dirsTot))
		p.bars[3].Set(int(dirsDone))
	}
}

// Stop stops the progress display.
func (p *ProgressTracker) Stop() {
	close(p.done)
	p.update()

	// Finish all bars
	for _, bar := range p.bars {
		bar.Finish()
	}
	fmt.Println()
}

// PrintStatus prints the current status to stdout.
func PrintStatus(results *collector.WorkerResults, lock *sync.Mutex, elapsed time.Duration) {
	lock.Lock()
	defer lock.Unlock()

	timestamp := utils.NowTimestamp()
	fmt.Printf("[%s] [status] Hosts: %d/%d | Shares: %d | Files: %d | Dirs: %d | Time: %s\n",
		timestamp,
		results.Success+results.Errors,
		results.TasksTotal,
		results.SharesProcessed,
		results.FilesProcessed,
		results.DirectoriesProcessed,
		utils.DeltaTime(elapsed),
	)
}

// PrintFinalSummary prints the final summary.
func PrintFinalSummary(results *collector.WorkerResults, lock *sync.Mutex) {
	lock.Lock()
	defer lock.Unlock()

	fmt.Println("\nFinal Summary:")
	fmt.Printf("  Shares: %d processed, %d skipped (total: %d)\n",
		results.SharesProcessed, results.SharesSkipped, results.SharesTotal)
	fmt.Printf("  Files: %d processed, %d skipped (total: %d)\n",
		results.FilesProcessed, results.FilesSkipped, results.FilesTotal)
	fmt.Printf("  Directories: %d processed, %d skipped (total: %d)\n",
		results.DirectoriesProcessed, results.DirectoriesSkipped, results.DirectoriesTotal)
}
