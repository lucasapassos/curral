// Package config loads the catalog and users files.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Catalog describes everything mounted into DuckDB at startup.
type Catalog struct {
	Extensions []string       `yaml:"extensions"`
	Settings   map[string]any `yaml:"settings"`
	Secrets    []Secret       `yaml:"secrets"`
	Databases  []Database     `yaml:"databases"`
	Default    string         `yaml:"default"`
	InitSQL    []string       `yaml:"init_sql"`

	// EnvRefs lists the environment variables the file referenced, so the
	// server can drop them from its environment once they are consumed.
	EnvRefs []string `yaml:"-"`
}

// Secret becomes CREATE SECRET name (TYPE type, key value, ...).
type Secret struct {
	Name   string         `yaml:"name"`
	Type   string         `yaml:"type"`
	Params map[string]any `yaml:"params"`
}

// Database becomes ATTACH 'path' AS name (key value, ...).
type Database struct {
	Name    string         `yaml:"name"`
	Path    string         `yaml:"path"`
	Schema  string         `yaml:"schema"` // schema for unqualified names; default main
	Options map[string]any `yaml:"options"`
	// CacheTTL enables curral's catalog metadata cache (Iceberg REST only),
	// e.g. "30s". Readers may see other writers' commits up to TTL late.
	CacheTTL string `yaml:"cache_ttl"`
}

// CacheDuration parses CacheTTL; zero means disabled.
func (d Database) CacheDuration() time.Duration {
	ttl, _ := time.ParseDuration(d.CacheTTL)
	return ttl
}

// Endpoint returns the ENDPOINT option, if any.
func (d Database) Endpoint() string {
	s, _ := lookupFold(d.Options, "ENDPOINT").(string)
	return s
}

// DefaultSchema is the schema USE selects for this database.
func (d Database) DefaultSchema() string {
	if d.Schema != "" {
		return d.Schema
	}
	return "main"
}

// Type returns the ATTACH TYPE option, defaulting to duckdb.
func (d Database) Type() string {
	if t, ok := lookupFold(d.Options, "TYPE").(string); ok && t != "" {
		return strings.ToLower(t)
	}
	return "duckdb"
}

// ReadOnly reports whether the database is attached READ_ONLY.
func (d Database) ReadOnly() bool {
	switch v := lookupFold(d.Options, "READ_ONLY").(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

func lookupFold(m map[string]any, key string) any {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// Users is the content of the users file.
type Users struct {
	Users []User `yaml:"users"`
}

type User struct {
	Name         string   `yaml:"name"`
	PasswordHash string   `yaml:"password_hash"`
	Roles        []string `yaml:"roles"`
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidIdent reports whether s is a plain SQL identifier/keyword.
func ValidIdent(s string) bool { return identRe.MatchString(s) }

// LoadCatalog reads and validates a catalog file, expanding ${VAR} references
// in string values from the environment.
func LoadCatalog(path string) (*Catalog, error) {
	var c Catalog
	if err := loadYAML(path, &c); err != nil {
		return nil, err
	}
	refs := map[string]bool{}
	expandHook = func(name string) { refs[name] = true }
	err := c.expand()
	expandHook = nil
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for name := range refs {
		c.EnvRefs = append(c.EnvRefs, name)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Catalog) expand() error {
	var err error
	for i := range c.Secrets {
		if err = expandMap(c.Secrets[i].Params); err != nil {
			return fmt.Errorf("secret %q: %w", c.Secrets[i].Name, err)
		}
	}
	for i := range c.Databases {
		d := &c.Databases[i]
		if d.Path, err = ExpandEnv(d.Path); err != nil {
			return fmt.Errorf("database %q: %w", d.Name, err)
		}
		if d.Schema, err = ExpandEnv(d.Schema); err != nil {
			return fmt.Errorf("database %q: %w", d.Name, err)
		}
		if d.CacheTTL, err = ExpandEnv(d.CacheTTL); err != nil {
			return fmt.Errorf("database %q: %w", d.Name, err)
		}
		if err = expandMap(d.Options); err != nil {
			return fmt.Errorf("database %q: %w", d.Name, err)
		}
	}
	if err = expandMap(c.Settings); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	for i := range c.InitSQL {
		if c.InitSQL[i], err = ExpandEnv(c.InitSQL[i]); err != nil {
			return fmt.Errorf("init_sql[%d]: %w", i, err)
		}
	}
	return nil
}

func (c *Catalog) validate() error {
	for _, e := range c.Extensions {
		if !ValidIdent(e) {
			return fmt.Errorf("invalid extension name %q", e)
		}
	}
	for k := range c.Settings {
		if !ValidIdent(k) {
			return fmt.Errorf("invalid setting name %q", k)
		}
	}
	for _, s := range c.Secrets {
		if !ValidIdent(s.Name) || !ValidIdent(s.Type) {
			return fmt.Errorf("secret %q: name and type must be identifiers", s.Name)
		}
		for k := range s.Params {
			if !ValidIdent(k) {
				return fmt.Errorf("secret %q: invalid param %q", s.Name, k)
			}
		}
	}
	if len(c.Databases) == 0 {
		return fmt.Errorf("no databases defined")
	}
	seen := map[string]bool{}
	for _, d := range c.Databases {
		if !ValidIdent(d.Name) {
			return fmt.Errorf("invalid database name %q", d.Name)
		}
		if seen[strings.ToLower(d.Name)] {
			return fmt.Errorf("duplicate database %q", d.Name)
		}
		seen[strings.ToLower(d.Name)] = true
		if d.Path == "" {
			return fmt.Errorf("database %q: path is required", d.Name)
		}
		for k := range d.Options {
			if !ValidIdent(k) {
				return fmt.Errorf("database %q: invalid option %q", d.Name, k)
			}
		}
		if d.CacheTTL != "" {
			ttl, err := time.ParseDuration(d.CacheTTL)
			if err != nil || ttl < 0 {
				return fmt.Errorf("database %q: invalid cache_ttl %q", d.Name, d.CacheTTL)
			}
			if ttl > 0 && (d.Type() != "iceberg" || d.Endpoint() == "") {
				return fmt.Errorf("database %q: cache_ttl needs TYPE iceberg with an ENDPOINT", d.Name)
			}
		}
	}
	if c.Default == "" {
		c.Default = c.Databases[0].Name
	}
	if !seen[strings.ToLower(c.Default)] {
		return fmt.Errorf("default database %q is not defined", c.Default)
	}
	return nil
}

// LoadUsers reads and validates a users file.
func LoadUsers(path string) (*Users, error) {
	var u Users
	if err := loadYAML(path, &u); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, usr := range u.Users {
		if usr.Name == "" || usr.PasswordHash == "" {
			return nil, fmt.Errorf("%s: users need name and password_hash", path)
		}
		if seen[usr.Name] {
			return nil, fmt.Errorf("%s: duplicate user %q", path, usr.Name)
		}
		seen[usr.Name] = true
	}
	return &u, nil
}

func loadYAML(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// expandHook, when set, sees every variable name ExpandEnv resolves.
var expandHook func(name string)

var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// ExpandEnv replaces ${VAR} and ${VAR:-default}. A missing variable without a
// default is an error, so a typo never silently becomes an empty credential.
func ExpandEnv(s string) (string, error) {
	var missing []string
	out := envRe.ReplaceAllStringFunc(s, func(m string) string {
		g := envRe.FindStringSubmatch(m)
		if expandHook != nil {
			expandHook(g[1])
		}
		if v, ok := os.LookupEnv(g[1]); ok {
			return v
		}
		if g[2] != "" {
			return g[3]
		}
		missing = append(missing, g[1])
		return ""
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("environment variable(s) not set: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

func expandMap(m map[string]any) error {
	for k, v := range m {
		nv, err := expandValue(v)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		m[k] = nv
	}
	return nil
}

func expandValue(v any) (any, error) {
	switch t := v.(type) {
	case string:
		return ExpandEnv(t)
	case []any:
		for i := range t {
			nv, err := expandValue(t[i])
			if err != nil {
				return nil, err
			}
			t[i] = nv
		}
	case map[string]any:
		return t, expandMap(t)
	}
	return v, nil
}
