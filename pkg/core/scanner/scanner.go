// Package scanner provides the core scanning engine for pcilint.
package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/khanhduong95/pcilint/pkg/core/config"
	"github.com/khanhduong95/pcilint/pkg/parser"
	"github.com/khanhduong95/pcilint/pkg/violation"
)

// Scanner orchestrates the scanning process.
type Scanner struct {
	config        *config.Config
	parserFactory parser.Factory
	rules         []parser.Rule
}

// NewScanner creates a new scanner instance.
func NewScanner(cfg *config.Config, factory parser.Factory, rules []parser.Rule) *Scanner {
	return &Scanner{
		config:        cfg,
		parserFactory: factory,
		rules:         rules,
	}
}

// fileJob represents a file to be scanned.
type fileJob struct {
	path    string
	content []byte
	parser  parser.Parser
}

// Scan executes the scan and returns a report.
func (s *Scanner) Scan(ctx context.Context) (*violation.Report, error) {
	start := time.Now()
	report := violation.NewReport()

	// Collect files to scan
	files, err := s.collectFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	report.Summary.TotalFiles = len(files)

	if len(files) == 0 {
		report.Duration = time.Since(start).String()
		return report, nil
	}

	// Determine concurrency
	concurrency := s.config.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	// Create job channel and results channel
	jobs := make(chan fileJob, len(files))
	results := make(chan []violation.Violation, len(files))
	errors := make(chan error, len(files))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, jobs, results, errors)
	}

	// Submit jobs
	filesWithIssues := make(map[string]bool)
	for _, path := range files {
		// Determine parser for file
		ext := filepath.Ext(path)
		p, ok := s.parserFactory.ParserForExtension(ext)
		if !ok {
			// Skip files without a parser
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			// Log warning but continue
			continue
		}

		jobs <- fileJob{
			path:    path,
			content: content,
			parser:  p,
		}
		report.Summary.FilesScanned++
	}
	close(jobs)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// Collect results
	for violations := range results {
		for _, v := range violations {
			report.AddViolation(v)
			filesWithIssues[v.File] = true
		}
	}

	// Check for errors
	for err := range errors {
		if err != nil {
			// Log error but don't fail the scan
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}

	report.Summary.FilesWithIssues = len(filesWithIssues)
	report.Duration = time.Since(start).String()

	return report, nil
}

// worker processes files from the jobs channel.
func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan fileJob, results chan<- []violation.Violation, errors chan<- error) {
	defer wg.Done()

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		violations, err := job.parser.Parse(ctx, job.path, job.content, s.rules)
		if err != nil {
			errors <- fmt.Errorf("failed to parse %s: %w", job.path, err)
			continue
		}

		if len(violations) > 0 {
			results <- violations
		}
	}
}

// collectFiles collects all files to scan based on configuration.
func (s *Scanner) collectFiles() ([]string, error) {
	var files []string
	seen := make(map[string]bool)

	for _, path := range s.config.Paths {
		// Check if path exists
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("path does not exist: %s", path)
		}

		if info.IsDir() {
			// Walk directory
			err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					// Check if directory should be excluded
					if s.shouldExclude(p) {
						return filepath.SkipDir
					}
					return nil
				}

				// Check if file should be excluded
				if s.shouldExclude(p) {
					return nil
				}

				absPath, err := filepath.Abs(p)
				if err != nil {
					return err
				}

				if !seen[absPath] {
					seen[absPath] = true
					files = append(files, absPath)
				}

				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("failed to walk directory %s: %w", path, err)
			}
		} else {
			// Single file
			if !s.shouldExclude(path) {
				absPath, err := filepath.Abs(path)
				if err != nil {
					return nil, err
				}
				if !seen[absPath] {
					seen[absPath] = true
					files = append(files, absPath)
				}
			}
		}
	}

	return files, nil
}

// shouldExclude checks if a path matches any exclude pattern.
func (s *Scanner) shouldExclude(path string) bool {
	for _, pattern := range s.config.Exclude {
		matched, err := matchPattern(pattern, path)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// matchPattern matches a gitignore-style pattern against a path.
func matchPattern(pattern, path string) (bool, error) {
	// Handle ** patterns
	if strings.Contains(pattern, "**") {
		// Convert to regex-like matching
		pattern = strings.ReplaceAll(pattern, "**", "*")
	}

	// Try matching against the full path
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		return false, err
	}
	if matched {
		return true, nil
	}

	// Try matching against just the filename
	matched, err = filepath.Match(pattern, filepath.Base(path))
	if err != nil {
		return false, err
	}
	if matched {
		return true, nil
	}

	// Try matching against path components
	parts := strings.Split(path, string(filepath.Separator))
	for i := range parts {
		subpath := filepath.Join(parts[i:]...)
		matched, err = filepath.Match(pattern, subpath)
		if err != nil {
			continue
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}
