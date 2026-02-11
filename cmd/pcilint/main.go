// Package main is the entry point for the pcilint CLI.
package main

import (
	"os"

	"github.com/khanhduong95/pcilint/cmd/pcilint/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
