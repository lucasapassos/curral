// Command curral serves DuckDB queries over REST with authentication and
// Rego-based authorization.
package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"golang.org/x/term"

	"curral/internal/auth"
	"curral/internal/config"
	"curral/internal/engine"
	"curral/internal/policy"
	"curral/internal/server"
)

const usage = `curral - REST proxy for DuckDB with auth and Rego policies

Usage:
  curral serve          [flags]   start the HTTP server
  curral check          [flags]   validate catalog, users and policy, then exit
  curral hash-password            read a password and print its bcrypt hash
  curral install-extensions --extension-dir DIR NAME...
                                  install DuckDB extensions (e.g. at image build time)
  curral healthcheck    [URL]     GET URL (default http://127.0.0.1:8080/healthz), exit 0 if 200
  curral version                  print version information

Every flag can also be set with an environment variable CURRAL_<FLAG>,
e.g. --max-concurrency -> CURRAL_MAX_CONCURRENCY. Repeatable flags take a
comma-separated list from the environment.

Run 'curral serve -h' for the flag list.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:], false)
	case "check":
		err = runServe(os.Args[2:], true)
	case "hash-password":
		err = runHash()
	case "install-extensions":
		err = runInstallExtensions(os.Args[2:])
	case "healthcheck":
		err = runHealthcheck(os.Args[2:])
	case "version", "--version":
		err = runVersion()
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "curral:", err)
		os.Exit(1)
	}
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

type serveFlags struct {
	listen         string
	catalog        string
	users          string
	policies       listFlag
	policyQuery    string
	maxConcurrency int
	queueTimeout   time.Duration
	queryTimeout   time.Duration
	maxRows        int64
	maxBody        int64
	threads        int
	memoryLimit    string
	tempDir        string
	maxTempSize    string
	extensionDir   string
	externalAccess bool
	allowedPaths   listFlag
	authCacheTTL   time.Duration
	logLevel       string
	logFormat      string
}

func parseFlags(args []string) (*serveFlags, error) {
	f := &serveFlags{}
	fs := flag.NewFlagSet("curral serve", flag.ContinueOnError)
	fs.StringVar(&f.listen, "listen", ":8080", "HTTP listen address")
	fs.StringVar(&f.catalog, "catalog", "", "catalog file: extensions, secrets, databases to ATTACH (required)")
	fs.StringVar(&f.users, "users", "", "users file with bcrypt password hashes and roles (required)")
	fs.Var(&f.policies, "policy", "Rego policy file, or JSON/YAML data file exposed as data.* (repeatable, required)")
	fs.StringVar(&f.policyQuery, "policy-query", "data.curral.allow", "Rego decision that must evaluate to true")
	fs.IntVar(&f.maxConcurrency, "max-concurrency", 8, "queries executing at the same time")
	fs.DurationVar(&f.queueTimeout, "queue-timeout", 5*time.Second, "how long a query waits for a free slot before 503")
	fs.DurationVar(&f.queryTimeout, "query-timeout", 60*time.Second, "maximum query duration (0 = none)")
	fs.Int64Var(&f.maxRows, "max-rows", 0, "maximum rows returned per query (0 = unlimited)")
	fs.Int64Var(&f.maxBody, "max-body", 1<<20, "maximum request body size in bytes")
	fs.IntVar(&f.threads, "threads", 0, "DuckDB threads (0 = DuckDB default)")
	fs.StringVar(&f.memoryLimit, "memory-limit", "", "DuckDB memory_limit, e.g. 8GB")
	fs.StringVar(&f.tempDir, "temp-dir", "", "DuckDB temp_directory for spilling")
	fs.StringVar(&f.maxTempSize, "max-temp-size", "", "DuckDB max_temp_directory_size, e.g. 20GB")
	fs.StringVar(&f.extensionDir, "extension-dir", "", "DuckDB extension_directory (for offline/preinstalled extensions)")
	fs.BoolVar(&f.externalAccess, "external-access", false, "keep enable_external_access on (lets queries read files/URLs)")
	fs.Var(&f.allowedPaths, "allowed-path", "path or URL prefix still reachable with external access off (repeatable)")
	fs.DurationVar(&f.authCacheTTL, "auth-cache-ttl", 5*time.Minute, "cache successful password checks for this long (0 = off)")
	fs.StringVar(&f.logLevel, "log-level", "info", "debug, info, warn or error")
	fs.StringVar(&f.logFormat, "log-format", "text", "text or json")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if err := applyEnv(fs); err != nil {
		return nil, err
	}
	var missing []string
	if f.catalog == "" {
		missing = append(missing, "--catalog")
	}
	if f.users == "" {
		missing = append(missing, "--users")
	}
	if len(f.policies) == 0 {
		missing = append(missing, "--policy")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}
	return f, nil
}

// applyEnv fills flags not given on the command line from CURRAL_* variables.
func applyEnv(fs *flag.FlagSet) error {
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	var err error
	fs.VisitAll(func(fl *flag.Flag) {
		if set[fl.Name] || err != nil {
			return
		}
		env := "CURRAL_" + strings.ToUpper(strings.ReplaceAll(fl.Name, "-", "_"))
		v, ok := os.LookupEnv(env)
		if !ok {
			return
		}
		if _, isList := fl.Value.(*listFlag); isList {
			for item := range strings.SplitSeq(v, ",") {
				if item = strings.TrimSpace(item); item != "" {
					if err = fl.Value.Set(item); err != nil {
						return
					}
				}
			}
			return
		}
		if e := fl.Value.Set(v); e != nil {
			err = fmt.Errorf("%s: %w", env, e)
		}
	})
	return err
}

func newLogger(level, format string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lv}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
}

func runServe(args []string, checkOnly bool) error {
	f, err := parseFlags(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	log, err := newLogger(f.logLevel, f.logFormat)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cat, err := config.LoadCatalog(f.catalog)
	if err != nil {
		return err
	}
	users, err := config.LoadUsers(f.users)
	if err != nil {
		return err
	}
	pol, err := policy.Load(ctx, f.policyQuery, f.policies)
	if err != nil {
		return err
	}
	eng, err := engine.Open(ctx, cat, engine.Options{
		MaxConcurrency: f.maxConcurrency,
		QueueTimeout:   f.queueTimeout,
		QueryTimeout:   f.queryTimeout,
		Threads:        f.threads,
		MemoryLimit:    f.memoryLimit,
		TempDir:        f.tempDir,
		MaxTempSize:    f.maxTempSize,
		ExtensionDir:   f.extensionDir,
		ExternalAccess: f.externalAccess,
		AllowedPaths:   f.allowedPaths,
	}, log)
	if err != nil {
		return err
	}
	defer eng.Close()

	dbs := make([]string, 0, len(eng.Databases()))
	for _, d := range eng.Databases() {
		dbs = append(dbs, d.Name)
	}
	if checkOnly {
		fmt.Printf("ok: %d database(s) [%s], %d user(s), policy %s\n",
			len(dbs), strings.Join(dbs, ", "), len(users.Users), f.policyQuery)
		return nil
	}

	srv := &server.Server{
		Engine:  eng,
		Auth:    auth.New(users, f.authCacheTTL),
		Policy:  pol,
		Log:     log,
		MaxRows: f.maxRows,
		MaxBody: f.maxBody,
	}
	httpSrv := &http.Server{
		Addr:              f.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.ListenAndServe() }()
	log.Info("curral listening", "addr", f.listen, "databases", dbs, "max_concurrency", f.maxConcurrency)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutCtx)
}

// Set at build time: -ldflags "-X main.version=... -X main.commit=..."
var (
	version = "dev"
	commit  = "unknown"
)

func runVersion() error {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return err
	}
	defer db.Close()
	var duck string
	if err := db.QueryRow("SELECT version()").Scan(&duck); err != nil {
		return err
	}
	fmt.Printf("curral %s (commit %s, %s, DuckDB %s)\n", version, commit, runtime.Version(), duck)
	return nil
}

func runInstallExtensions(args []string) error {
	fs := flag.NewFlagSet("curral install-extensions", flag.ContinueOnError)
	dir := fs.String("extension-dir", "", "directory to install into (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() == 0 {
		return errors.New("usage: curral install-extensions --extension-dir DIR NAME...")
	}
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("SET extension_directory = '" + strings.ReplaceAll(*dir, "'", "''") + "'"); err != nil {
		return err
	}
	for _, name := range fs.Args() {
		if !config.ValidIdent(name) {
			return fmt.Errorf("invalid extension name %q", name)
		}
		// LOAD as well, so a broken download fails the build, not the boot.
		for _, q := range []string{"INSTALL " + name, "LOAD " + name} {
			if _, err := db.Exec(q); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
		fmt.Println("installed", name)
	}
	return nil
}

func runHealthcheck(args []string) error {
	url := "http://127.0.0.1:8080/healthz"
	if len(args) > 0 {
		url = args[0]
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return nil
}

func runHash() error {
	var pass string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pass = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		pass = strings.TrimRight(line, "\r\n")
	}
	if pass == "" {
		return errors.New("empty password")
	}
	h, err := auth.Hash(pass)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}
