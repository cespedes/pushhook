package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testConf = `
# comment
github-secret ghsecret
gitlab-secret whsec_c2VjcmV0a2V5
repo github Example/Site /bin/deploy -x
repo gitlab grp/proj /bin/other
`

var gitlabKey = []byte("secretkey")

func newTestHandler(t *testing.T) (*Handler, *[]Repo, *[]string, *sync.WaitGroup) {
	t.Helper()
	cfg, err := ParseConfig(strings.NewReader(testConf))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(cfg)
	var mu sync.Mutex
	var ran []Repo
	var envs []string
	wg := new(sync.WaitGroup)
	h.run = func(r Repo, env []string) {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, r)
		envs = append(envs, strings.Join(env[len(env)-4:], " "))
	}
	return h, &ran, &envs, wg
}

func ghReq(body, event string, secret []byte) *http.Request {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-GitHub-Event", event)
	return r
}

func glReq(body string, key []byte, ts time.Time) *http.Request {
	id := "msg_1"
	t := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + t + "." + body))
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("webhook-id", id)
	r.Header.Set("webhook-timestamp", t)
	r.Header.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return r
}

func do(h http.Handler, r *http.Request) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestGitHub(t *testing.T) {
	h, ran, envs, wg := newTestHandler(t)
	body := `{"ref":"refs/heads/main","after":"abc","repository":{"full_name":"example/site"}}`

	if c := do(h, ghReq(body, "push", []byte("wrong"))); c != 401 {
		t.Errorf("bad secret: got %d", c)
	}
	if c := do(h, ghReq(body, "ping", []byte("ghsecret"))); c != 200 {
		t.Errorf("ping: got %d", c)
	}
	wg.Add(1)
	if c := do(h, ghReq(body, "push", []byte("ghsecret"))); c != 202 {
		t.Fatalf("push: got %d", c)
	}
	wg.Wait()
	if len(*ran) != 1 || (*ran)[0].Command[0] != "/bin/deploy" || (*ran)[0].Command[1] != "-x" {
		t.Errorf("ran = %v", *ran)
	}
	if (*envs)[0] != "PUSHHOOK_PROVIDER=github PUSHHOOK_REPO=example/site PUSHHOOK_REF=refs/heads/main PUSHHOOK_COMMIT=abc" {
		t.Errorf("env = %q", (*envs)[0])
	}
	other := `{"repository":{"full_name":"x/y"}}`
	if c := do(h, ghReq(other, "push", []byte("ghsecret"))); c != 200 || len(*ran) != 1 {
		t.Errorf("unconfigured repo: got %d, ran %d", c, len(*ran))
	}
}

func TestGitLab(t *testing.T) {
	h, ran, _, wg := newTestHandler(t)
	body := `{"object_kind":"push","ref":"refs/heads/main","checkout_sha":"abc","project":{"path_with_namespace":"grp/proj"}}`
	now := time.Now()

	if c := do(h, glReq(body, []byte("wrong"), now)); c != 401 {
		t.Errorf("bad key: got %d", c)
	}
	if c := do(h, glReq(body, gitlabKey, now.Add(-time.Hour))); c != 401 {
		t.Errorf("old timestamp: got %d", c)
	}
	if c := do(h, glReq(`{"object_kind":"issue"}`, gitlabKey, now)); c != 200 {
		t.Errorf("non-push: got %d", c)
	}
	wg.Add(1)
	if c := do(h, glReq(body, gitlabKey, now)); c != 202 {
		t.Fatalf("push: got %d", c)
	}
	wg.Wait()
	if len(*ran) != 1 || (*ran)[0].Command[0] != "/bin/other" {
		t.Errorf("ran = %v", *ran)
	}
}

func TestRejects(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	if c := do(h, httptest.NewRequest("POST", "/", strings.NewReader("{}"))); c != 401 {
		t.Errorf("unsigned: got %d", c)
	}
	if c := do(h, httptest.NewRequest("GET", "/", nil)); c != 405 {
		t.Errorf("GET: got %d", c)
	}
	// A GitHub-signed request with the GitLab secret must not pass.
	if c := do(h, ghReq("{}", "push", gitlabKey)); c != 401 {
		t.Errorf("cross secret: got %d", c)
	}
}

func TestConfigErrors(t *testing.T) {
	for _, c := range []string{
		"repo github a/b cmd\n",              // missing github-secret
		"gitlab-secret abc\n",                // no whsec_ prefix
		"gitlab-secret whsec_!!!\n",          // bad base64
		"repo bitbucket a/b cmd\n",           // unknown provider
		"github-secret s\nrepo github a/b\n", // missing command
		"bogus x\n",                          // unknown directive
		"github-secret s\nrepo github a/b c\nrepo github A/B d\n", // duplicate
	} {
		if _, err := ParseConfig(strings.NewReader(c)); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}
