// Command tadori is the CLI entry point for the connectivity diagnostic tool.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/yohnark/tadori/internal/orchestrate"
	"github.com/yohnark/tadori/internal/report"
)

// overallTimeout bounds the complete diagnostic run, independent of the
// per-probe timeout applied inside orchestrate.Run.
const overallTimeout = 30 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: tadori diagnose <url> [--json]")
		return 2
	}

	switch args[0] {
	case "diagnose":
		return runDiagnose(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		fmt.Fprintln(stderr, "usage: tadori diagnose <url> [--json]")
		return 2
	}
}

func runDiagnose(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "emit the diagnostic report as canonical JSON")

	// flag.Parse stops at the first non-flag argument, but the positional URL
	// naturally comes before --json in the documented usage. Separating flags
	// from positional arguments here lets both orderings work.
	var flagArgs, positional []string
	for _, arg := range args {
		if len(arg) > 1 && arg[0] == '-' {
			flagArgs = append(flagArgs, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: tadori diagnose <url> [--json]")
		return 2
	}

	target, err := orchestrate.ParseTarget(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "tadori: %v\n", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, overallTimeout)
	defer cancelTimeout()

	diagnosticReport := orchestrate.Run(ctx, target, orchestrate.Options{})

	if *jsonOutput {
		if err := report.WriteJSON(stdout, diagnosticReport); err != nil {
			fmt.Fprintf(stderr, "tadori: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout)
		return 0
	}

	if err := report.WriteHuman(stdout, diagnosticReport); err != nil {
		fmt.Fprintf(stderr, "tadori: %v\n", err)
		return 1
	}
	return 0
}
