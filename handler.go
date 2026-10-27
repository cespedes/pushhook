package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	maxBodySize = 25 << 20 // GitHub's payload cap
	runTimeout  = 10 * time.Minute
)

// Handler receives webhooks, verifies them and runs the configured commands.
type Handler struct {
	cfg *Config
	now func() time.Time

	// run executes a repo's command; replaced in tests.
	run func(r Repo, env []string)

	mu    sync.Mutex
	locks map[repoKey]*sync.Mutex
}

func NewHandler(cfg *Config) *Handler {
	h := &Handler{cfg: cfg, now: time.Now, locks: make(map[repoKey]*sync.Mutex)}
	h.run = runCommand
	return h
}

// push is the provider-independent view of a push event.
type push struct {
	Provider string
	Repo     string
	Ref      string
	Commit   string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodySize))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusRequestEntityTooLarge)
		return
	}

	var p push
	var ok bool
	switch {
	case req.Header.Get("X-Hub-Signature-256") != "":
		if h.cfg.GitHubSecret == nil || !verifyGitHub(h.cfg.GitHubSecret, body, req.Header.Get("X-Hub-Signature-256")) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		switch req.Header.Get("X-GitHub-Event") {
		case "push":
			p, ok = parseGitHub(body)
		case "ping":
			io.WriteString(w, "pong\n")
			return
		default:
			io.WriteString(w, "ignored\n")
			return
		}
	case req.Header.Get("webhook-signature") != "":
		if h.cfg.GitLabSecret == nil || !verifyGitLab(h.cfg.GitLabSecret, body,
			req.Header.Get("webhook-id"), req.Header.Get("webhook-timestamp"),
			req.Header.Get("webhook-signature"), h.now()) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		p, ok = parseGitLab(body)
		if !ok && isGitLabNonPush(body) {
			io.WriteString(w, "ignored\n")
			return
		}
	default:
		http.Error(w, "missing signature", http.StatusUnauthorized)
		return
	}
	if !ok {
		http.Error(w, "malformed payload", http.StatusBadRequest)
		return
	}

	r, found := h.cfg.Repos[repoKey{p.Provider, strings.ToLower(p.Repo)}]
	if !found {
		log.Printf("%s push to unconfigured repo %q", p.Provider, p.Repo)
		io.WriteString(w, "ignored\n")
		return
	}
	env := append(os.Environ(),
		"PUSHHOOK_PROVIDER="+p.Provider,
		"PUSHHOOK_REPO="+p.Repo,
		"PUSHHOOK_REF="+p.Ref,
		"PUSHHOOK_COMMIT="+p.Commit,
	)
	go h.runSerial(repoKey{p.Provider, strings.ToLower(p.Repo)}, r, env)
	w.WriteHeader(http.StatusAccepted)
	io.WriteString(w, "accepted\n")
}

// runSerial makes sure a repo's command never runs concurrently with itself.
func (h *Handler) runSerial(k repoKey, r Repo, env []string) {
	h.mu.Lock()
	l := h.locks[k]
	if l == nil {
		l = new(sync.Mutex)
		h.locks[k] = l
	}
	h.mu.Unlock()
	l.Lock()
	defer l.Unlock()
	h.run(r, env)
}

func runCommand(r Repo, env []string) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Command[0], r.Command[1:]...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("%s: %v\n%s", r.Name, err, out)
		return
	}
	log.Printf("%s: ok\n%s", r.Name, out)
}

func parseGitHub(body []byte) (push, bool) {
	var v struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if json.Unmarshal(body, &v) != nil || v.Repository.FullName == "" {
		return push{}, false
	}
	return push{providerGitHub, v.Repository.FullName, v.Ref, v.After}, true
}

func parseGitLab(body []byte) (push, bool) {
	var v struct {
		ObjectKind  string `json:"object_kind"`
		Ref         string `json:"ref"`
		CheckoutSHA string `json:"checkout_sha"`
		Project     struct {
			Path string `json:"path_with_namespace"`
		} `json:"project"`
	}
	if json.Unmarshal(body, &v) != nil || v.ObjectKind != "push" || v.Project.Path == "" {
		return push{}, false
	}
	return push{providerGitLab, v.Project.Path, v.Ref, v.CheckoutSHA}, true
}

// isGitLabNonPush reports whether body is a valid GitLab event other than a push.
func isGitLabNonPush(body []byte) bool {
	var v struct {
		ObjectKind string `json:"object_kind"`
	}
	return json.Unmarshal(body, &v) == nil && v.ObjectKind != "" && v.ObjectKind != "push"
}
