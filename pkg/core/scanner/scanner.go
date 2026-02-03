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
			fmt.Fprintf(os.Stderr, "Warning: failed to read %s: %v\n", path, err)
			continue
		}

		report.Summary.FilesScanned++
		jobs <- fileJob{
			path:    path,
			content: content,
			parser:  p,
		}
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
	// Handle ** (globstar) patterns by checking if any path suffix matches
	// the non-globstar portion. E.g., "vendor/**" matches anything under vendor/.
	if strings.Contains(pattern, "**") {
		return matchGlobstar(pattern, path), nil
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

	// Try matching against path suffixes (for patterns like "vendor/*")
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := range parts {
		subpath := strings.Join(parts[i:], string(filepath.Separator))
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

// matchGlobstar handles ** patterns by splitting on ** and checking if the
// path contains a directory that matches the prefix and a file that matches the suffix.
func matchGlobstar(pattern, path string) bool {
	slashPath := filepath.ToSlash(path)
	slashPattern := filepath.ToSlash(pattern)

	// Split pattern on "**"
	parts := strings.SplitN(slashPattern, "**", 2)
	prefix := parts[0] // e.g., "vendor/"
	suffix := ""
	if len(parts) > 1 {
		suffix = parts[1] // e.g., "/*.go"
	}

	// Remove trailing/leading slashes for cleaner matching
	prefix = strings.TrimSuffix(prefix, "/")
	suffix = strings.TrimPrefix(suffix, "/")

	// Check all path components
	pathParts := strings.Split(slashPath, "/")
	for i := range pathParts {
		subpath := strings.Join(pathParts[:i+1], "/")

		// Check if this directory matches the prefix
		prefixMatch := false
		if prefix == "" {
			prefixMatch = true // "**/*.go" matches any directory
		} else {
			matched, err := filepath.Match(prefix, subpath)
			if err == nil && matched {
				prefixMatch = true
			}
			// Also check just the directory name
			if !prefixMatch {
				for _, part := range pathParts[:i+1] {
					matched, err := filepath.Match(prefix, part)
					if err == nil && matched {
						prefixMatch = true
						break
					}
				}
			}
		}

		if !prefixMatch {
			continue
		}

		// If no suffix, any file under the matching prefix is a match
		if suffix == "" {
			return true
		}

		// Check remaining path against suffix
		remaining := strings.Join(pathParts[i+1:], "/")
		if remaining == "" {
			continue
		}
		matched, err := filepath.Match(suffix, remaining)
		if err == nil && matched {
			return true
		}
		// Also match against just the filename
		matched, err = filepath.Match(suffix, pathParts[len(pathParts)-1])
		if err == nil && matched {
			return true
		}
	}

	return false
}
