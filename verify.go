package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// maxTimestampSkew is the tolerated difference between the webhook-timestamp
// header and the local clock, as recommended by the Standard Webhooks spec.
const maxTimestampSkew = 5 * time.Minute

// verifyGitHub checks an X-Hub-Signature-256 header ("sha256=<hex>") against
// the HMAC-SHA256 of the body.
func verifyGitHub(secret, body []byte, header string) bool {
	h, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	got, err := hex.DecodeString(h)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// verifyGitLab checks a Standard Webhooks signature, as sent by GitLab when
// a signing token is configured. The signed content is
// "<webhook-id>.<webhook-timestamp>.<body>"; the webhook-signature header is a
// space-separated list of "v1,<base64 HMAC-SHA256>" entries.
func verifyGitLab(key, body []byte, id, timestamp, signature string, now time.Time) bool {
	if id == "" || signature == "" {
		return false
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxTimestampSkew || d < -maxTimestampSkew {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, s := range strings.Fields(signature) {
		v, ok := strings.CutPrefix(s, "v1,")
		if !ok {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(v)
		if err == nil && hmac.Equal(got, want) {
			return true
		}
	}
	return false
}
