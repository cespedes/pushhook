package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	providerGitHub = "github"
	providerGitLab = "gitlab"
)

// Config is the parsed configuration file.
type Config struct {
	Listen       string
	GitHubSecret []byte // HMAC key for X-Hub-Signature-256
	GitLabSecret []byte // decoded signing token for webhook-signature
	Repos        map[repoKey]Repo
}

type repoKey struct {
	Provider string
	Name     string // lowercased "owner/name" or "group/project"
}

// Repo describes what to run when a push to a repository is received.
type Repo struct {
	Name    string
	Command []string
}

// ParseConfig reads the configuration format documented in the README:
//
//	listen :8080
//	github-secret <secret>
//	gitlab-secret whsec_<base64>
//	repo github owner/name /path/to/command [args...]
//	repo gitlab group/project /path/to/command [args...]
//
// Blank lines and lines starting with '#' are ignored.
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := &Config{Listen: ":8080", Repos: make(map[repoKey]Repo)}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if err := cfg.directive(f); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for k := range cfg.Repos {
		if k.Provider == providerGitHub && cfg.GitHubSecret == nil {
			return nil, fmt.Errorf("repo %s %s: github-secret is not set", k.Provider, k.Name)
		}
		if k.Provider == providerGitLab && cfg.GitLabSecret == nil {
			return nil, fmt.Errorf("repo %s %s: gitlab-secret is not set", k.Provider, k.Name)
		}
	}
	return cfg, nil
}

func (c *Config) directive(f []string) error {
	switch f[0] {
	case "listen":
		if len(f) != 2 {
			return fmt.Errorf("usage: listen ADDRESS")
		}
		c.Listen = f[1]
	case "github-secret":
		if len(f) != 2 {
			return fmt.Errorf("usage: github-secret SECRET")
		}
		c.GitHubSecret = []byte(f[1])
	case "gitlab-secret":
		if len(f) != 2 {
			return fmt.Errorf("usage: gitlab-secret whsec_SIGNING_TOKEN")
		}
		key, err := decodeSigningToken(f[1])
		if err != nil {
			return err
		}
		c.GitLabSecret = key
	case "repo":
		if len(f) < 4 {
			return fmt.Errorf("usage: repo github|gitlab NAME COMMAND [ARGS...]")
		}
		if f[1] != providerGitHub && f[1] != providerGitLab {
			return fmt.Errorf("unknown provider %q (want github or gitlab)", f[1])
		}
		k := repoKey{f[1], strings.ToLower(f[2])}
		if _, dup := c.Repos[k]; dup {
			return fmt.Errorf("duplicate repo %s %s", f[1], f[2])
		}
		c.Repos[k] = Repo{Name: f[2], Command: f[3:]}
	default:
		return fmt.Errorf("unknown directive %q", f[0])
	}
	return nil
}

// decodeSigningToken extracts the HMAC key from a GitLab signing token
// ("whsec_" followed by base64).
func decodeSigningToken(s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, "whsec_")
	if !ok {
		return nil, fmt.Errorf("gitlab-secret must start with whsec_")
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("gitlab-secret is not valid base64")
	}
	return key, nil
}
