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
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"golang.org/x/term"

	"curral/internal/audit"
	"curral/internal/auth"
	"curral/internal/config"
	"curral/internal/engine"
	"curral/internal/metrics"
	"curral/internal/policy"
	"curral/internal/rls"
	"curral/internal/server"
)

const usage = `curral - REST proxy for DuckDB with auth and Rego policies

Usage:
  curral serve          [flags]   start the HTTP server
  curral check          [flags]   validate catalog, users and policy, then exit
  curral hash-password            read a password and print its bcrypt hash
  curral query          [flags] [SQL]  run a statement on a curral server (client)
  curral gen-api-key NAME [ROLE...]
                                  create an API key; prints the key once and the users-file entry
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
	case "gen-api-key":
		err = runGenAPIKey(os.Args[2:])
	case "query":
		err = runQuery(os.Args[2:])
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
	limitsQuery    string
	masksQuery     string
	rowFilters     string
	maxConcurrency int
	perUserConc    int64
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
	auditLog       string
	auditSQL       string
	auditQueue     int
	metricsListen  string
	oidcIssuer     string
	oidcAudience   string
	oidcUserClaim  string
	oidcRolesClaim string
	oidcSkew       time.Duration
	oidcVerified   bool
	oidcDomains    listFlag
	tlsCert        string
	tlsKey         string
	trustedProxies listFlag
	ipMaxFail      int
	userMaxFail    int
	failWindow     time.Duration
	lockout        time.Duration
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
	fs.StringVar(&f.masksQuery, "policy-masks-query", "", "optional Rego rule with column masks per table, e.g. data.curral.masks")
	fs.StringVar(&f.rowFilters, "row-filters", "", "row-level security file (per table, which rows matching users see); reloaded on SIGHUP")
	fs.StringVar(&f.limitsQuery, "policy-limits-query", "", "optional Rego rule with per-request limits {timeout, max_rows}, e.g. data.curral.limits")
	fs.IntVar(&f.maxConcurrency, "max-concurrency", 8, "queries executing at the same time")
	fs.Int64Var(&f.perUserConc, "max-concurrency-per-user", 0, "queries one user may run at once when the policy sets no max_concurrency (0 = no limit)")
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
	fs.StringVar(&f.auditLog, "audit-log", "", "audit log file (JSON lines), '-' for stdout; empty disables auditing. Queries are refused while it cannot be written; SIGHUP reopens it")
	fs.StringVar(&f.auditSQL, "audit-sql", server.AuditSQLRedacted, "SQL text in audit events: redacted (literals become ?), full or hash")
	fs.IntVar(&f.auditQueue, "audit-queue", 4096, "audit events buffered in memory")
	fs.StringVar(&f.metricsListen, "metrics-listen", "", "serve Prometheus /metrics on this separate address (e.g. 127.0.0.1:9090); empty disables")
	fs.StringVar(&f.oidcIssuer, "oidc-issuer", "", "accept bearer JWTs from this OIDC issuer (discovery + JWKS); empty disables")
	fs.StringVar(&f.oidcAudience, "oidc-audience", "", "required audience (aud) of JWTs")
	fs.StringVar(&f.oidcUserClaim, "oidc-user-claim", "sub", "JWT claim used as the user name (e.g. email, preferred_username)")
	fs.StringVar(&f.oidcRolesClaim, "oidc-roles-claim", "roles", "JWT claim with the roles; dotted paths allowed (realm_access.roles)")
	fs.DurationVar(&f.oidcSkew, "oidc-skew", 30*time.Second, "clock skew tolerated when validating JWT times")
	fs.BoolVar(&f.oidcVerified, "oidc-require-email-verified", true, "with --oidc-user-claim email, reject tokens without email_verified=true (disable for providers that never send it, e.g. Entra ID)")
	fs.Var(&f.oidcDomains, "oidc-hosted-domain", "only accept Google tokens whose hd claim is this Workspace domain (repeatable)")
	fs.StringVar(&f.tlsCert, "tls-cert", "", "serve HTTPS with this certificate (PEM, full chain); reloaded on SIGHUP")
	fs.StringVar(&f.tlsKey, "tls-key", "", "private key for --tls-cert (PEM)")
	fs.Var(&f.trustedProxies, "trusted-proxy", "CIDR or IP of a reverse proxy allowed to set X-Forwarded-For (repeatable)")
	fs.IntVar(&f.ipMaxFail, "auth-ip-max-failures", 10, "failed logins from one client IP within the window before it is locked out (0 = off)")
	fs.IntVar(&f.userMaxFail, "auth-user-max-failures", 30, "failed logins for one user name within the window before it is locked out (0 = off)")
	fs.DurationVar(&f.failWindow, "auth-failure-window", 5*time.Minute, "window in which failed logins are counted")
	fs.DurationVar(&f.lockout, "auth-lockout", 15*time.Minute, "how long a lockout lasts")
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
	if (f.tlsCert == "") != (f.tlsKey == "") {
		return nil, fmt.Errorf("--tls-cert and --tls-key go together")
	}
	switch f.auditSQL {
	case server.AuditSQLRedacted, server.AuditSQLFull, server.AuditSQLHash:
	default:
		return nil, fmt.Errorf("--audit-sql must be redacted, full or hash")
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
	loadPolicy := func(ctx context.Context) (*policy.Policy, error) {
		return policy.LoadQueries(ctx, f.policies, policy.Queries{
			Allow: f.policyQuery, Limits: f.limitsQuery, Masks: f.masksQuery,
		})
	}
	pol, err := loadPolicy(ctx)
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
	// The catalog's credentials now live inside DuckDB; keep them out of the
	// process environment so nothing that can read it later finds them.
	for _, name := range cat.EnvRefs {
		os.Unsetenv(name)
	}

	dbs := make([]string, 0, len(eng.Databases()))
	for _, d := range eng.Databases() {
		dbs = append(dbs, d.Name)
	}
	rowRules, err := loadRowFilters(ctx, f.rowFilters, eng)
	if err != nil {
		return err
	}
	if checkOnly {
		fmt.Printf("ok: %d database(s) [%s], %d user(s), %d api key(s), %d identit(ies), %d table(s) with row filters, policy %s\n",
			len(dbs), strings.Join(dbs, ", "), len(users.Users), len(users.APIKeys), len(users.Identities), rowRules.Len(), f.policyQuery)
		return nil
	}

	var aw *audit.Writer
	if f.auditLog != "" {
		if aw, err = audit.Open(f.auditLog, f.auditQueue, log); err != nil {
			return fmt.Errorf("audit log: %w", err)
		}
		log.Info("audit log enabled", "path", f.auditLog, "sql", f.auditSQL)
	} else {
		log.Warn("audit log disabled (--audit-log not set)")
	}

	var mtr *metrics.Metrics
	var metricsSrv *http.Server
	if f.metricsListen != "" {
		src := metrics.Sources{
			Load:       eng.Load,
			CacheStats: eng.CacheStats,
			CachedDBs:  eng.CachedDatabases(),
			BuildLabels: map[string]string{
				"version": version, "commit": commit, "duckdb": eng.DuckDBVersion(ctx),
			},
		}
		if aw != nil {
			src.AuditStats = func() (int64, int64, bool) {
				return aw.Written.Load(), aw.Dropped.Load(), aw.Healthy() == nil
			}
		}
		mtr = metrics.New(src)
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", mtr.Handler())
		metricsSrv = &http.Server{Addr: f.metricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server", "err", err)
			}
		}()
		log.Info("metrics enabled", "addr", f.metricsListen)
	}

	var oidc *auth.OIDC
	if f.oidcIssuer != "" {
		oidc, err = auth.NewOIDC(ctx, auth.OIDCConfig{
			Issuer: f.oidcIssuer, Audience: f.oidcAudience,
			UserClaim: f.oidcUserClaim, RolesClaim: f.oidcRolesClaim, Skew: f.oidcSkew,
			RequireEmailVerified: f.oidcVerified && f.oidcUserClaim == "email",
			HostedDomains:        f.oidcDomains,
		})
		if err != nil {
			return err
		}
		log.Info("oidc enabled", "issuer", f.oidcIssuer, "audience", f.oidcAudience,
			"user_claim", f.oidcUserClaim, "roles_claim", f.oidcRolesClaim,
			"require_email_verified", f.oidcVerified && f.oidcUserClaim == "email", "hosted_domains", f.oidcDomains)
	}

	srv := &server.Server{
		OIDC:     oidc,
		Metrics:  mtr,
		Engine:   eng,
		Log:      log,
		MaxRows:  f.maxRows,
		MaxBody:  f.maxBody,
		Audit:    aw,
		AuditSQL: f.auditSQL,
		Version:  version,
	}
	srv.SetAuth(auth.New(users, f.authCacheTTL))
	srv.SetPolicy(pol)
	srv.SetRowFilters(rowRules)
	if rowRules.Len() > 0 {
		log.Info("row filters enabled", "file", f.rowFilters, "tables", rowRules.Len())
	}
	if mtr != nil {
		mtr.SetPolicySource(func() string { return srv.Policy().SHA256 })
	}

	var certs *server.CertLoader
	if f.tlsCert != "" {
		if certs, err = server.NewCertLoader(f.tlsCert, f.tlsKey); err != nil {
			return err
		}
	}

	// SIGHUP: reopen the audit log (logrotate) and reload users and policy.
	// A broken file keeps the previous version in effect. The catalog is
	// locked into DuckDB at boot and needs a restart.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if aw != nil {
				if err := aw.Reopen(); err != nil {
					log.Error("audit log reopen failed", "err", err)
				}
			}
			if certs != nil {
				if err := certs.Reload(); err != nil {
					log.Error("tls certificate reload failed; keeping the current one", "err", err)
				} else {
					log.Info("tls certificate reloaded")
				}
			}
			users, err := config.LoadUsers(f.users)
			var newPol *policy.Policy
			if err == nil {
				newPol, err = loadPolicy(context.Background())
			}
			var newRules *rls.Rules
			if err == nil {
				newRules, err = loadRowFilters(context.Background(), f.rowFilters, eng)
			}
			if err != nil {
				srv.Reload(nil, nil, err) // users, policy and row filters all stay as they were
				continue
			}
			srv.SetRowFilters(newRules)
			srv.Reload(auth.New(users, f.authCacheTTL), newPol, nil)
		}
	}()

	proxies, err := parsePrefixes(f.trustedProxies)
	if err != nil {
		return err
	}
	srv.TrustedProxies = proxies
	srv.MaxConcurrencyPerUser = f.perUserConc
	limiterCfg := func(n int) auth.LimiterConfig {
		return auth.LimiterConfig{MaxFailures: n, Window: f.failWindow, Lockout: f.lockout}
	}
	srv.IPLimiter = auth.NewLimiter(limiterCfg(f.ipMaxFail))
	srv.UserLimiter = auth.NewLimiter(limiterCfg(f.userMaxFail))
	go func() {
		for range time.Tick(time.Minute) {
			srv.IPLimiter.Sweep()
			srv.UserLimiter.Sweep()
		}
	}()

	httpSrv := &http.Server{
		Addr:              f.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	if certs != nil {
		httpSrv.TLSConfig = certs.TLSConfig()
		go func() { errc <- httpSrv.ListenAndServeTLS("", "") }()
	} else {
		go func() { errc <- httpSrv.ListenAndServe() }()
		log.Warn("serving plain HTTP: credentials travel unencrypted unless a TLS proxy is in front (--tls-cert/--tls-key)")
	}
	log.Info("curral listening", "addr", f.listen, "tls", certs != nil, "trusted_proxies", f.trustedProxies, "databases", dbs, "max_concurrency", f.maxConcurrency,
		"version", version, "policy_sha256", pol.SHA256)

	select {
	case err = <-errc:
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = httpSrv.Shutdown(shutCtx)
	}
	if metricsSrv != nil {
		metricsSrv.Close()
	}
	// After HTTP shutdown no handler can still write events.
	if aw != nil {
		if cerr := aw.Close(); cerr != nil {
			log.Error("audit log close", "err", cerr)
		}
	}
	return err
}

// Set at build time: -ldflags "-X main.version=... -X main.commit=..."
var (
	version = "dev"
	commit  = "unknown"
)

// loadRowFilters reads the RLS file and prepares every rule against its
// table, so a typo fails startup (or a reload) instead of every query.
func loadRowFilters(ctx context.Context, path string, eng *engine.Engine) (*rls.Rules, error) {
	if path == "" {
		return nil, nil
	}
	r, err := rls.Load(path)
	if err != nil {
		return nil, err
	}
	err = r.Each(func(table string, rule rls.Rule) error {
		return eng.CheckProtection(ctx, table, engine.Protection{Filter: rule.Where})
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// parsePrefixes accepts CIDRs and single addresses.
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("--trusted-proxy %q: not an IP or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

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
	fmt.Printf("curral %s (commit %s, %s, DuckDB %s, arrow %v)\n", version, commit, runtime.Version(), duck, engine.ArrowAvailable)
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

func runGenAPIKey(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: curral gen-api-key NAME [ROLE...]")
	}
	key, hash, err := auth.NewAPIKey()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "API key for %s (shown only now; store it in a secret manager):\n", args[0])
	fmt.Println(key)
	fmt.Fprintln(os.Stderr, "\nAdd to the users file under api_keys:")
	roles := "[]"
	if len(args) > 1 {
		roles = "[" + strings.Join(args[1:], ", ") + "]"
	}
	fmt.Fprintf(os.Stderr, "  - name: %s\n    key_sha256: %s\n    roles: %s\n    # expires: 2027-12-31\n", args[0], hash, roles)
	return nil
}

func readPassword(fd int) ([]byte, error) { return term.ReadPassword(fd) }

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
