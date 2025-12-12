package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	sshage "github.com/Mic92/ssh-to-age"
)

var version = "dev"

type options struct {
	out, in     string
	showVersion bool
}

func parseFlags(args []string) options {
	var opts options
	f := flag.NewFlagSet(args[0], flag.ExitOnError)
	f.StringVar(&opts.in, "i", "-", "Input path. Reads by default from standard input")
	f.StringVar(&opts.out, "o", "-", "Output path. Prints by default to standard output")
	f.BoolVar(&opts.showVersion, "version", false, "show version and exit")
	// Ignore errors as ExitOnError is set
	_ = f.Parse(args[1:])
	return opts
}

func main() {
	if err := convertKeys(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func convertKeys(args []string) error {
	opts := parseFlags(args)

	if opts.showVersion {
		fmt.Println(version)
		return nil
	}

	var inputData []byte
	var err error
	if opts.in == "-" {
		inputData, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("error reading stdin: %w", err)
		}
	} else {
		inputData, err = ioutil.ReadFile(opts.in)
		if err != nil {
			return fmt.Errorf("error reading %s: %w", opts.in, err)
		}
	}

	var writer io.Writer
	if opts.out == "-" {
		writer = os.Stdout
	} else {
		f, err := os.Create(opts.out)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", opts.out, err)
		}
		defer f.Close()
		writer = f
	}

	scanner := bufio.NewScanner(strings.NewReader(string(inputData)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		keys, err := sshage.AgeToSSH(line)
		if err != nil {
			fmt.Printf("skipped key: %v\n", err)
			continue
		}
		for i, key := range keys {
			if _, err := fmt.Fprintf(writer, "%s candidate %d\n", key, i+1); err != nil {
				return fmt.Errorf("failed to write key: %w", err)
			}
		}
	}
	return nil
}
