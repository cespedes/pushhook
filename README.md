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
- **GitLab**: enable *Push events* and set a *Signing token*. The
  `webhook-signature`, `webhook-id` and `webhook-timestamp` headers are
  verified following the Standard Webhooks scheme; timestamps more than five
  minutes off are rejected.

## Behaviour

- Missing or invalid signature, or a push for a repository that is not
  configured or whose secret did not sign the request: `401`.
- Validly signed but not a push event: `200`, nothing is run. GitHub `ping`
  replies `200 pong`.
- Valid push to a configured repository: `202`, the command runs in the
  background (10 minute timeout). Runs for the same repository are serialised.
  Output is logged.

The command's environment is inherited from the server plus:

- `PUSHHOOK_PROVIDER` (`github` or `gitlab`)
- `PUSHHOOK_REPO`
- `PUSHHOOK_REF` (e.g. `refs/heads/main`)
- `PUSHHOOK_COMMIT`

The command is run for pushes to any branch; check `PUSHHOOK_REF` in the
command if you only care about one.
