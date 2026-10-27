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
	Listen string
	Repos  map[repoKey]Repo
}

type repoKey struct {
	Provider string
	Name     string // lowercased "owner/name" or "group/project"
}

// Repo describes what to run when a push to a repository is received.
type Repo struct {
	Name    string
	Secret  []byte // HMAC key: GitHub secret, or decoded GitLab signing token
	Command []string
}

// ParseConfig reads the configuration format documented in the README:
//
//	listen :8080
//	github owner/name <secret> /path/to/command [args...]
//	gitlab group/project whsec_<base64> /path/to/command [args...]
//
// listen is required, and every repo has its own secret. Blank lines and lines starting with '#' are ignored.
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := &Config{Repos: make(map[repoKey]Repo)}
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
	if cfg.Listen == "" {
		return nil, fmt.Errorf("listen is not set")
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
	case providerGitHub, providerGitLab:
		if len(f) < 4 {
			return fmt.Errorf("usage: %s NAME SECRET COMMAND [ARGS...]", f[0])
		}
		k := repoKey{f[0], strings.ToLower(f[1])}
		if _, dup := c.Repos[k]; dup {
			return fmt.Errorf("duplicate %s repo %s", f[0], f[1])
		}
		secret := []byte(f[2])
		if f[0] == providerGitLab {
			var err error
			if secret, err = decodeSigningToken(f[2]); err != nil {
				return err
			}
		}
		c.Repos[k] = Repo{Name: f[1], Secret: secret, Command: f[3:]}
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
		return nil, fmt.Errorf("GitLab signing token must start with whsec_")
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("GitLab signing token is not valid base64")
	}
	return key, nil
}
