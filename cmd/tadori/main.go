// Command tadori is the CLI entry point for the connectivity diagnostic tool.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/environment"
	"github.com/yohnark/tadori/internal/model"
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
	case "environment":
		return runEnvironment(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "usage: tadori diagnose <url|hostname|ip|unc> [--service id] [--port port] [--json]")
	fmt.Fprintln(w, "       tadori environment [--json]")
	fmt.Fprintln(w, "       tadori serve [--listen 127.0.0.1] [--port 8080] [--no-open]")
	fmt.Fprintln(w, "       tadori serve [--addr 127.0.0.1:8080] [--no-open]")
}

func runEnvironment(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("environment", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "emit the environment snapshot as canonical JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		printUsage(stderr)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, overallTimeout)
	defer cancelTimeout()
	snapshot, err := environment.Collect(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "tadori: %v\n", err)
		return 1
	}
	if *jsonOutput {
		if err := report.WriteEnvironmentJSON(stdout, snapshot); err != nil {
			fmt.Fprintf(stderr, "tadori: %v\n", err)
			return 1
		}
		return 0
	}
	_, _ = stdout.WriteString(report.RenderEnvironmentHuman(snapshot))
	return 0
}

func runServe(args []string, stdout, stderr *os.File) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServeContext(ctx, args, stdout, stderr, openBrowserURL)
}

func runServeContext(ctx context.Context, args []string, stdout, stderr *os.File, openBrowser func(string) error) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	address := fs.String("addr", "", "complete loopback listen address (for example 127.0.0.1:8080)")
	listenHost := fs.String("listen", "127.0.0.1", "literal loopback IP to listen on")
	port := fs.Int("port", 8080, "TCP port; use 0 to select a free port")
	noOpen := fs.Bool("no-open", false, "do not open the local UI in a browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: tadori serve [--listen 127.0.0.1] [--port 8080] [--no-open]")
		return 2
	}

	resolvedAddress, err := resolveServeAddress(*address, *listenHost, *port, fs)
	if err != nil {
		fmt.Fprintf(stderr, "tadori: %v\n", err)
		return 2
	}

	listener, err := net.Listen("tcp", resolvedAddress)
	if err != nil {
		fmt.Fprintf(stderr, "tadori: listen on %s: %v\n", resolvedAddress, err)
		return 1
	}
	defer listener.Close()

	handler := web.NewHandler(web.HandlerOptions{})
	defer handler.Close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      web.DefaultOverallTimeout + 10*time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()
	serverURL := "http://" + listener.Addr().String() + "/"
	fmt.Fprintf(stdout, "tadori: serving diagnose UI at %s\n", serverURL)
	if !*noOpen && openBrowser != nil {
		if err := openBrowser(serverURL); err != nil {
			fmt.Fprintf(stderr, "tadori: open browser: %v\n", err)
		}
	}

	select {
	case err := <-serveErrors:
		handler.Close()
		if err == http.ErrServerClosed {
			return 0
		}
		fmt.Fprintf(stderr, "tadori: serve: %v\n", err)
		return 1
	case <-ctx.Done():
		handler.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "tadori: shutdown: %v\n", err)
			return 1
		}
		return 0
	}
}

func resolveServeAddress(address, listenHost string, port int, fs *flag.FlagSet) (string, error) {
	if address != "" {
		if flagWasSet(fs, "listen") || flagWasSet(fs, "port") {
			return "", errors.New("--addr cannot be combined with --listen or --port")
		}
		if err := web.ValidateLoopbackAddress(address); err != nil {
			return "", err
		}
		return address, nil
	}
	if port < 0 || port > 65535 {
		return "", errors.New("port must be between 0 and 65535")
	}
	listenHost = strings.TrimSpace(listenHost)
	if strings.HasPrefix(listenHost, "[") && strings.HasSuffix(listenHost, "]") {
		listenHost = strings.TrimSuffix(strings.TrimPrefix(listenHost, "["), "]")
	}
	resolved := net.JoinHostPort(listenHost, strconv.Itoa(port))
	if err := web.ValidateLoopbackAddress(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	wasSet := false
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == name {
			wasSet = true
		}
	})
	return wasSet
}

func openBrowserURL(rawURL string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command = "open"
		args = []string{rawURL}
	case "windows":
		command = "rundll32.exe"
		args = []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		command = "xdg-open"
		args = []string{rawURL}
	}
	cmd := exec.Command(command, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func runDiagnose(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "emit the diagnostic report as canonical JSON")
	service := fs.String("service", "", "service profile (http, https, smb, rdp, ssh, dns, custom_tcp, custom_tls)")
	port := fs.Uint("port", 0, "override the service port")

	// flag.Parse stops at the first non-flag argument, but the positional URL
	// naturally comes before --json in the documented usage. Separating flags
	// from positional arguments here lets both orderings work.
	var flagArgs, positional []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--service" || arg == "-service" || arg == "--port" || arg == "-port" {
			flagArgs = append(flagArgs, arg)
			if index+1 >= len(args) {
				flagArgs = append(flagArgs, "")
				continue
			}
			index++
			flagArgs = append(flagArgs, args[index])
		} else if len(arg) > 1 && arg[0] == '-' {
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

	var portOverride *uint16
	if flagWasSet(fs, "port") {
		if *port > 65535 {
			fmt.Fprintln(stderr, "tadori: port must be between 1 and 65535")
			return 2
		}
		value := uint16(*port)
		portOverride = &value
	}
	target, err := model.ParseTarget(model.TargetIntent{Input: positional[0], Service: model.ServiceProfileID(*service), Port: portOverride})
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
