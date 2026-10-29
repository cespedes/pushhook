package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testConf = `
# comment
listen :8080
github Example/Site ghsecret /bin/deploy -x
github example/shared1 sharedsecret /bin/s1
github example/shared2 sharedsecret /bin/s2
github example/other othersecret /bin/other-gh
gitlab grp/proj whsec_c2VjcmV0a2V5 /bin/other
gitlab grp/proj2 whsec_b3RoZXJrZXk= /bin/other2
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
	// Another repo's secret must not trigger this repo's command.
	if c := do(h, ghReq(body, "push", []byte("othersecret"))); c != 401 || len(*ran) != 1 {
		t.Errorf("other repo's secret: got %d, ran %d", c, len(*ran))
	}
	unconfigured := `{"repository":{"full_name":"x/y"}}`
	if c := do(h, ghReq(unconfigured, "push", []byte("ghsecret"))); c != 401 || len(*ran) != 1 {
		t.Errorf("unconfigured repo: got %d, ran %d", c, len(*ran))
	}
}

func TestGitHubSharedSecret(t *testing.T) {
	h, ran, _, wg := newTestHandler(t)
	wg.Add(1)
	body := `{"ref":"refs/heads/main","after":"abc","repository":{"full_name":"example/shared2"}}`
	if c := do(h, ghReq(body, "push", []byte("sharedsecret"))); c != 202 {
		t.Fatalf("push: got %d", c)
	}
	wg.Wait()
	if len(*ran) != 1 || (*ran)[0].Command[0] != "/bin/s2" {
		t.Errorf("ran = %v", *ran)
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
	tag := `{"object_kind":"tag_push","ref":"refs/tags/v1","checkout_sha":"def","project":{"path_with_namespace":"grp/proj"}}`
	wg.Add(1)
	if c := do(h, glReq(tag, gitlabKey, now)); c != 202 {
		t.Fatalf("tag push: got %d", c)
	}
	wg.Wait()
	if len(*ran) != 2 {
		t.Errorf("tag push ran = %v", *ran)
	}
	// Another project's signing token must not trigger this project's command.
	if c := do(h, glReq(body, []byte("otherkey"), now)); c != 401 || len(*ran) != 2 {
		t.Errorf("other project's key: got %d, ran %d", c, len(*ran))
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
	if _, err := ParseConfig(strings.NewReader("github-secret s\n")); err == nil {
		t.Error("expected error for missing listen")
	}
	for _, c := range []string{
		"gitlab-secret abc\n",              // global secrets no longer exist
		"github a/b s\n",                   // missing command
		"gitlab a/b abc cmd\n",             // no whsec_ prefix
		"gitlab a/b whsec_!!! cmd\n",       // bad base64
		"bitbucket a/b s cmd\n",            // unknown provider
		"bogus x\n",                        // unknown directive
		"github a/b s c\ngithub A/B s d\n", // duplicate
	} {
		if _, err := ParseConfig(strings.NewReader("listen :8080\n" + c)); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestLogLines(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(os.Stderr); log.SetFlags(log.LstdFlags) })

	h, _, _, wg := newTestHandler(t)
	push := `{"ref":"refs/heads/main","after":"abc","repository":{"full_name":"example/site"}}`
	wg.Add(1)
	do(h, ghReq(push, "push", []byte("ghsecret")))
	wg.Wait()
	do(h, ghReq(push, "push", []byte("wrong")))
	do(h, ghReq(push, "push", []byte("othersecret")))
	do(h, ghReq(`{"repository":{"full_name":"x/y"}}`, "push", []byte("ghsecret")))
	do(h, ghReq(push, "ping", []byte("ghsecret")))
	do(h, httptest.NewRequest("GET", "/", nil))
	do(h, httptest.NewRequest("POST", "/", strings.NewReader("{}")))
	fwd := httptest.NewRequest("GET", "/", nil)
	fwd.Header.Add("X-Forwarded-For", "198.51.100.1, 203.0.113.7")
	fwd.Header.Add("X-Forwarded-For", "10.0.0.1,  203.0.113.9 ")
	do(h, fwd)

	want := []string{
		`192.0.2.1:1234 POST 202 accepted github "example/site" "refs/heads/main"`,
		`192.0.2.1:1234 POST 401 invalid GitHub signature`,
		`192.0.2.1:1234 POST 401 github repo "example/site": signed with another repo's secret`,
		`192.0.2.1:1234 POST 401 unconfigured github repo "x/y"`,
		`192.0.2.1:1234 POST 200 github ping`,
		`192.0.2.1:1234 GET 405 method not allowed`,
		`192.0.2.1:1234 POST 401 missing signature`,
		`203.0.113.9 GET 405 method not allowed`,
	}
	if got := strings.Split(strings.TrimSpace(buf.String()), "\n"); !slices.Equal(got, want) {
		t.Errorf("log lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
