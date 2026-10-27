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
| `listen ADDRESS` | Address to listen on (default `:8080`). |
| `github-secret SECRET` | The webhook's "Secret" in GitHub. |
| `gitlab-secret whsec_...` | The webhook's "Signing token" in GitLab. |
| `repo github OWNER/NAME COMMAND [ARGS...]` | Command to run on push to a GitHub repo. |
| `repo gitlab GROUP/PROJECT COMMAND [ARGS...]` | Command to run on push to a GitLab project. |

Commands are executed directly (no shell); arguments are split on whitespace.
A `repo` line for a provider requires the matching secret to be set.
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

- Missing or invalid signature: `401`.
- Valid but not a push event, or a push to a repository that is not
  configured: `200`, nothing is run. GitHub `ping` replies `200 pong`.
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
