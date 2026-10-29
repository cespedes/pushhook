# pushhook

A small webhook receiver: when a GitHub or GitLab repository gets a push, it
runs a command you configured for that repository. Requests are only accepted
if their signature is valid. Standard library only.

## Build and run

    go build
    ./pushhook -config pushhook.conf

The configuration file contains secrets, so keep it readable only by the
user running the service (`chmod 600`).

## Configuration

See `pushhook.conf.example`. One directive per line; blank lines and lines
starting with `#` are ignored.

| Directive | Meaning |
|---|---|
| `listen ADDRESS` | Address to listen on (required, no default). |
| `github OWNER/NAME SECRET COMMAND [ARGS...]` | Command to run on push to a GitHub repo; `SECRET` is the webhook's "Secret". |
| `gitlab GROUP/PROJECT whsec_... COMMAND [ARGS...]` | Command to run on push to a GitLab project; `whsec_...` is the webhook's "Signing token". |

Commands are executed directly (no shell); arguments are split on whitespace.
Every repository has its own secret, and a request is only accepted for a
repository if it is signed with that repository's secret, so a repository
cannot trigger another one's command. Repositories may share a secret on
purpose (for example, an organization-level webhook), by repeating it.
Repository names are matched case-insensitively.

## Webhook setup

Point the webhook at the server's URL (any path), as a POST of JSON.

- **GitHub**: content type `application/json`, set the *Secret*, event
  "Just the push event". The `X-Hub-Signature-256` header is verified
  (HMAC-SHA256 of the body).
- **GitLab**: enable *Push events* and *Tag push events* and set a
  *Signing token*. The `webhook-signature`, `webhook-id` and `webhook-timestamp` headers are
  verified following the Standard Webhooks scheme; timestamps more than five
  minutes off are rejected.

## Other systems (self-hosted Git, Subversion)

Anything that can send a GitHub-style push request works: a POST with
`X-GitHub-Event: push`, an `X-Hub-Signature-256` header and a JSON body with
`ref`, `after` and `repository.full_name`. Configure it with a `github` line.
Two hook scripts that do exactly that (they need `sh`, `openssl` and `curl`)
are in `examples/`:

- `examples/git/post-receive`: one request per pushed ref (deleted refs are
  skipped).
- `examples/svn/post-commit`: one request per commit, with `ref` set to `svn`
  and the commit set to `r<revision>`.

## Running behind a proxy

pushhook is meant to run behind a reverse proxy (nginx, Caddy, ...) that
terminates TLS and forwards requests to it. It speaks plain HTTP only, so
have `listen` bind to a loopback address (for example `127.0.0.1:9000`) and
do not expose it directly.

The client address in the log is the last entry of the `X-Forwarded-For`
header, that is, the one added by the proxy closest to pushhook; without the
header it is the address of the connection. This is only trustworthy if
every request goes through the proxy and the proxy appends to
`X-Forwarded-For`: a client that reaches pushhook directly can write
anything there.

## Behaviour

- Missing or invalid signature, or a push for a repository that is not
  configured or whose secret did not sign the request: `401`.
- Validly signed but not a push event: `200`, nothing is run. GitHub `ping`
  replies `200 pong`.
- Valid push to a configured repository: `202`, the command runs in the
  background (10 minute timeout). Runs for the same repository are serialised.
  Output is logged to stderr; when running under systemd with the output sent
  to the journal, the program's own timestamps are left out.

Every request is logged with one line: client address, method, status code
and what happened. For rejected requests this is the reason (for example
`invalid GitHub signature` or `unconfigured github repo "owner/name"`), which
is more detailed than the message sent back to the client.

The command's environment is inherited from the server plus:

- `PUSHHOOK_PROVIDER` (`github` or `gitlab`)
- `PUSHHOOK_REPO`
- `PUSHHOOK_REF` (e.g. `refs/heads/main`)
- `PUSHHOOK_COMMIT`

The command is run for pushes to any branch or tag; check `PUSHHOOK_REF` in the
command if you only care about one.
