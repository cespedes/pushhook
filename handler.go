package main

import (
	"context"
	"encoding/json"
	"fmt"
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

// request wraps the ResponseWriter to remember the status and a note about
// the outcome, so that ServeHTTP can log one line per request.
type request struct {
	http.ResponseWriter
	status int
	note   string
}

func (r *request) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// fail replies with an error. The client only sees msg; why is what gets
// logged.
func (r *request) fail(code int, msg, why string) {
	r.note = why
	http.Error(r, msg, code)
}

// clientAddr returns the address of the client as seen by the reverse proxy in
// front of us: the last entry of X-Forwarded-For (the one that proxy added),
// or the address of the connection if the header is absent.
func clientAddr(req *http.Request) string {
	if v := req.Header.Values("X-Forwarded-For"); len(v) > 0 {
		last := v[len(v)-1]
		if i := strings.LastIndexByte(last, ','); i >= 0 {
			last = last[i+1:]
		}
		if last = strings.TrimSpace(last); last != "" {
			return last
		}
	}
	return req.RemoteAddr
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r := &request{ResponseWriter: w}
	defer func() {
		if r.status == 0 {
			r.status = http.StatusOK
		}
		log.Printf("%s %s %d %s", clientAddr(req), req.Method, r.status, r.note)
	}()
	h.serve(r, req)
}

func (h *Handler) serve(w *request, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.fail(http.StatusMethodNotAllowed, "method not allowed", "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodySize))
	if err != nil {
		w.fail(http.StatusRequestEntityTooLarge, "cannot read body", "cannot read body: "+err.Error())
		return
	}

	var p push
	var ok bool
	var signed map[repoKey]bool
	switch {
	case req.Header.Get("X-Hub-Signature-256") != "":
		signed = h.signedBy(providerGitHub, func(secret []byte) bool {
			return verifyGitHub(secret, body, req.Header.Get("X-Hub-Signature-256"))
		})
		if len(signed) == 0 {
			w.fail(http.StatusUnauthorized, "invalid signature", "invalid GitHub signature")
			return
		}
		switch ev := req.Header.Get("X-GitHub-Event"); ev {
		case "push":
			p, ok = parseGitHub(body)
		case "ping":
			w.note = "github ping"
			io.WriteString(w, "pong\n")
			return
		default:
			w.note = fmt.Sprintf("ignored github event %q", ev)
			io.WriteString(w, "ignored\n")
			return
		}
	case req.Header.Get("webhook-signature") != "":
		signed = h.signedBy(providerGitLab, func(secret []byte) bool {
			return verifyGitLab(secret, body,
				req.Header.Get("webhook-id"), req.Header.Get("webhook-timestamp"),
				req.Header.Get("webhook-signature"), h.now())
		})
		if len(signed) == 0 {
			w.fail(http.StatusUnauthorized, "invalid signature", "invalid GitLab signature")
			return
		}
		p, ok = parseGitLab(body)
		if !ok && isGitLabNonPush(body) {
			w.note = "ignored gitlab event"
			io.WriteString(w, "ignored\n")
			return
		}
	default:
		w.fail(http.StatusUnauthorized, "missing signature", "missing signature")
		return
	}
	if !ok {
		w.fail(http.StatusBadRequest, "malformed payload", "malformed payload")
		return
	}

	// The repository name comes from the payload, so it only counts if the
	// signature was made with that repository's own secret.
	key := repoKey{p.Provider, strings.ToLower(p.Repo)}
	if !signed[key] {
		why := fmt.Sprintf("%s repo %q: signed with another repo's secret", p.Provider, p.Repo)
		if _, configured := h.cfg.Repos[key]; !configured {
			why = fmt.Sprintf("unconfigured %s repo %q", p.Provider, p.Repo)
		}
		w.fail(http.StatusUnauthorized, "invalid signature", why)
		return
	}
	r := h.cfg.Repos[key]
	env := append(os.Environ(),
		"PUSHHOOK_PROVIDER="+p.Provider,
		"PUSHHOOK_REPO="+p.Repo,
		"PUSHHOOK_REF="+p.Ref,
		"PUSHHOOK_COMMIT="+p.Commit,
	)
	go h.runSerial(key, r, env)
	w.note = fmt.Sprintf("accepted %s %q %q", p.Provider, p.Repo, p.Ref)
	w.WriteHeader(http.StatusAccepted)
	io.WriteString(w, "accepted\n")
}

// signedBy returns the configured repos of a provider whose secret satisfies
// check. Every secret is tried, so the time taken does not reveal which one
// matched.
func (h *Handler) signedBy(provider string, check func(secret []byte) bool) map[repoKey]bool {
	signed := make(map[repoKey]bool)
	for k, r := range h.cfg.Repos {
		if k.Provider == provider && check(r.Secret) {
			signed[k] = true
		}
	}
	return signed
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
		After       string `json:"after"`
		CheckoutSHA string `json:"checkout_sha"`
		Project     struct {
			Path string `json:"path_with_namespace"`
		} `json:"project"`
	}
	if json.Unmarshal(body, &v) != nil || (v.ObjectKind != "push" && v.ObjectKind != "tag_push") || v.Project.Path == "" {
		return push{}, false
	}
	// checkout_sha is null when the push deletes the ref; report the all-zeros
	// "after" instead, as GitHub does.
	commit := v.CheckoutSHA
	if isZeroSHA(v.After) {
		commit = v.After
	}
	return push{providerGitLab, v.Project.Path, v.Ref, commit}, true
}

// isZeroSHA reports whether s is the all-zeros object name that Git uses for
// "no object", as in the "after" of a push that deletes a ref.
func isZeroSHA(s string) bool {
	return s != "" && strings.Trim(s, "0") == ""
}

// isGitLabNonPush reports whether body is a valid GitLab event other than a
// branch or tag push.
func isGitLabNonPush(body []byte) bool {
	var v struct {
		ObjectKind string `json:"object_kind"`
	}
	return json.Unmarshal(body, &v) == nil && v.ObjectKind != "" && v.ObjectKind != "push" && v.ObjectKind != "tag_push"
}
