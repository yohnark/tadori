// Command tadori is the CLI entry point for the connectivity diagnostic tool.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/yohnark/tadori/internal/orchestrate"
	"github.com/yohnark/tadori/internal/report"
	"github.com/yohnark/tadori/internal/web"
)

// overallTimeout bounds the complete diagnostic run, independent of the
// per-probe timeout applied inside orchestrate.Run.
const overallTimeout = 30 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "diagnose":
		return runDiagnose(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "usage: tadori diagnose <url|host:port> [--json]")
	fmt.Fprintln(w, "       tadori serve [-addr 127.0.0.1:8080]")
}

func runServe(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	address := fs.String("addr", "127.0.0.1:8080", "loopback address for the local UI")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: tadori serve [-addr 127.0.0.1:8080]")
		return 2
	}
	if err := web.ValidateLoopbackAddress(*address); err != nil {
		fmt.Fprintf(stderr, "tadori: %v\n", err)
		return 2
	}

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		fmt.Fprintf(stderr, "tadori: listen on %s: %v\n", *address, err)
		return 1
	}

	server := &http.Server{
		Handler:           web.NewHandler(web.HandlerOptions{}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()
	fmt.Fprintf(stdout, "tadori: serving diagnose UI at http://%s/\n", listener.Addr())

	select {
	case err := <-serveErrors:
		if err == http.ErrServerClosed {
			return 0
		}
		fmt.Fprintf(stderr, "tadori: serve: %v\n", err)
		return 1
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "tadori: shutdown: %v\n", err)
			return 1
		}
		return 0
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
		printUsage(stderr)
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
