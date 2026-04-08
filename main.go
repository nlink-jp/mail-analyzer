package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/nlink-jp/mail-analyzer/internal/analyzer"
	"github.com/nlink-jp/mail-analyzer/internal/config"
	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

var version = "dev"

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: mail-analyzer [--offline] <file.eml|file.msg>\n")
		os.Exit(1)
	}

	offline := false
	var filePath string

	for _, arg := range os.Args[1:] {
		switch arg {
		case "--offline":
			offline = true
		case "--version":
			fmt.Println(version)
			os.Exit(0)
		default:
			filePath = arg
		}
	}

	if filePath == "" {
		fmt.Fprintf(os.Stderr, "Error: no input file specified\n")
		os.Exit(1)
	}

	email, err := parser.ParseFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing email: %v\n", err)
		os.Exit(1)
	}

	var result *analyzer.Result

	if offline {
		result = analyzer.AnalyzeOffline(email)
	} else {
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		result, err = analyzer.Analyze(context.Background(), email, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding output: %v\n", err)
		os.Exit(1)
	}
}
