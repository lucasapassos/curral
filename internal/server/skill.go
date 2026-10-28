package server

import (
	"net/http"
	"net/netip"
	"path"
	"strings"

	"github.com/lucasapassos/curral/skills"
)

// The agent skill is served unauthenticated, like /healthz: it is public
// documentation (the same files as skills/curral in the repository) and an
// agent that knows only the server's URL needs it before it has
// credentials. GET / tells such an agent where everything is.
//
// Documentation and code are different trust levels. Whoever runs the server
// is trusted with the data; serving scripts the agent executes would also
// trust them, and anyone who can tamper with the connection, with code
// execution on the agent's machine, and the scripts read the credentials
// file. So by default (SkillDocs) the server serves SKILL.md and the API
// reference only and points at the scripts in the repository, pinned to its
// own version; SkillAll also serves the scripts, for networks without access
// to GitHub, and only over TLS or to loopback.

// Skill modes, for Server.ServeSkill.
const (
	SkillDocs = "docs" // SKILL.md and references (default)
	SkillAll  = "all"  // also the scripts and install.sh
	SkillOff  = "off"  // neither GET / nor GET /skill
)

// repoURL is where the scripts come from when the server does not serve them.
const repoURL = "https://github.com/lucasapassos/curral"

// skillFiles maps the paths under /skill/ to their content type and whether
// they are code (served in SkillAll only).
var skillFiles = map[string]struct {
	ctype string
	code  bool
}{
	"SKILL.md":           {"text/markdown; charset=utf-8", false},
	"references/api.md":  {"text/markdown; charset=utf-8", false},
	"scripts/curral.sh":  {"text/x-shellscript; charset=utf-8", true},
	"scripts/curral.ps1": {"text/plain; charset=utf-8", true},
	"scripts/install.sh": {"text/x-shellscript; charset=utf-8", true},
}

func (s *Server) skillRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /skill", s.skillFile)
	mux.HandleFunc("GET /skill/{file...}", s.skillFile)
}

// skillRef is the repository ref holding this server's skill: its release
// tag, or main for development builds.
func (s *Server) skillRef() string {
	if strings.HasPrefix(s.Version, "v") {
		return s.Version
	}
	return "main"
}

// rawURL is the base URL the skill's files are downloaded from in SkillDocs
// mode: the repository at the server's version.
func (s *Server) rawURL() string {
	return "https://raw.githubusercontent.com/lucasapassos/curral/" + s.skillRef() + "/skills/curral"
}

// index describes the server to a client that has only its URL.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	endpoints := map[string]string{
		"health":       "GET /healthz (no authentication)",
		"capabilities": "GET /v1/capabilities",
		"databases":    "GET /v1/databases",
		"schema":       "GET /v1/schema",
		"query":        "POST /v1/query {sql, params?, database?, format?, max_rows?, dry_run?}",
	}
	if s.Docs != nil {
		endpoints["docs"] = "GET /v1/docs, GET /v1/docs/{id}, POST /v1/docs/search"
	}
	agents := map[string]string{
		"start_here": "/skill/SKILL.md",
		"api":        "/skill/references/api.md",
	}
	if s.ServeSkill == SkillAll {
		agents["client"] = "/skill/scripts/curral.sh (Windows: /skill/scripts/curral.ps1)"
		agents["install"] = "/skill/scripts/install.sh: sh install.sh [DIR] downloads the skill from this server into DIR (default ./curral)"
	} else {
		agents["client"] = s.rawURL() + "/scripts/curral.sh (Windows: .../curral.ps1); this server serves documentation only, the scripts come from the repository at its version"
		agents["install"] = "curl -fsSL " + s.rawURL() + "/scripts/install.sh -o install.sh && CURRAL_SKILL_REF=" + s.skillRef() + " sh install.sh ./curral"
		agents["scripts_source"] = repoURL + "/tree/" + s.skillRef() + "/skills/curral"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":        "curral",
		"version":        s.Version,
		"about":          "SQL gateway for DuckDB: one statement per POST /v1/query, under this server's access policy",
		"agents":         agents,
		"authentication": "Authorization: Basic user:password, or Bearer with an API key (curral_...) or an OIDC JWT, on every /v1 endpoint",
		"endpoints":      endpoints,
		"source":         repoURL,
	})
}

// skillFile serves one file of the skill; /skill alone is SKILL.md.
func (s *Server) skillFile(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(r.PathValue("file"), "/")
	if name == "" {
		name = "SKILL.md"
	}
	f, ok := skillFiles[name]
	if !ok {
		writeError(w, http.StatusNotFound, "no such file; see GET /skill/SKILL.md")
		return
	}
	if f.code {
		switch {
		case s.ServeSkill != SkillAll:
			writeError(w, http.StatusNotFound, "this server serves the skill's documentation only; get "+name+" from "+s.rawURL()+"/"+name+" (see GET /)")
			return
		case !s.secureTransport(r):
			writeError(w, http.StatusForbidden, "scripts are served over TLS or to loopback only; get "+name+" from "+s.rawURL()+"/"+name)
			return
		}
	}
	data, err := skills.Curral.ReadFile(path.Join("curral", name))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such file; see GET /skill/SKILL.md")
		return
	}
	w.Header().Set("Content-Type", f.ctype)
	w.Header().Set("Cache-Control", "no-store")
	if name == "scripts/install.sh" {
		// The installer downloads the rest from this server.
		data = []byte(strings.Replace(string(data), "\nset -eu\n",
			"\nset -eu\nCURRAL_SKILL_SOURCE=${CURRAL_SKILL_SOURCE:-"+baseURL(r)+"/skill}\n", 1))
	}
	w.Write(data)
}

// secureTransport reports whether code may be served on this request: over
// TLS (terminated here, or at a trusted proxy that says so) or to the local
// machine. Over plain HTTP anyone on the path could replace the script.
func (s *Server) secureTransport(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr := peer.Addr().Unmap()
	if addr.IsLoopback() {
		return true
	}
	return s.trusted(addr) && r.Header.Get("X-Forwarded-Proto") == "https"
}

// baseURL is the URL this request reached the server by, for the installer
// to download the rest of the skill from. The caller's own headers decide
// it, which only affects the response that caller gets.
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
