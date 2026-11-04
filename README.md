# FALCON

```
███████  ███████  ██       ███████  ███████  ██   ██
██       ██   ██  ██       ██       ██   ██  ███  ██
█████    ███████  ██       ██       ██   ██  ██ █ ██
██       ██   ██  ██       ██       ██   ██  ██  ███
██       ██   ██  ███████  ███████  ███████  ██   ██
```

**Open-source authenticated API fuzzer. Finds IDOR, broken auth, and skip-the-token bugs in minutes — no $4K/yr Burp licence required.**

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: authorized testing only](https://img.shields.io/badge/use-authorized%20testing%20only-critical)](#legal--ethics)

Point falcon at an OpenAPI 3.x spec and **two test user accounts**, and it fires every endpoint as each identity in parallel, diffs the response matrix, and names what's wrong.

---

## Why falcon exists

Every pentester knows the pattern: you've already discovered the endpoints (hellhound, katana, the API docs themselves), the questions that actually matter are **authorization** questions — can user B read user A's data, does the server actually validate tokens, is this endpoint accidentally public — and answering them by hand is tedious. The only serious tool for this is **Burp Suite Professional's authenticated scanner**, which costs ~$4K/year and only helps if you already use Burp.

Falcon is the open-source version of that capability. One YAML of credentials, one OpenAPI spec, one command, and you get a severity-ranked list of auth bugs.

---

## What it detects

| Pattern | Severity | How it's identified |
|---|---|---|
| **broken-authentication** | HIGH | No-auth request returns success with the *same body shape* as an authenticated one — the endpoint doesn't enforce auth |
| **invalid-token-accepted** | HIGH | An obviously-garbage bearer token returns the same body as a real-user request — middleware checks "header is present" but not "token is valid" |
| **cross-user-access** (IDOR) | HIGH / MEDIUM | Two distinct users get success responses with the same body shape — user B sees user A's resource. HIGH when the path has `{id}`; MEDIUM on list endpoints (might be an intentional shared list) |
| **role-differential** | INFO | Users receive different authorization outcomes on the *same* non-ownership-scoped request — review whether this is intended RBAC or a vertical-privilege leak |
| **auth-server-error** | LOW | 5xx under adversarial auth input — often an uncaught exception in auth middleware worth inspecting manually |

Body comparison uses SimHash (same approach as [hellhound](https://github.com/securewithharshitrajput/hellhound)), so per-request CSRF tokens, timestamps, and request IDs don't mask real IDOR matches.

---

## Install

```bash
go install github.com/securewithharshitrajput/falcon/cmd/falcon@v0.1.0
```

Drops a `falcon` binary into `$(go env GOBIN)` (usually `~/go/bin`).

**From source:**

```bash
git clone https://github.com/securewithharshitrajput/falcon.git
cd falcon
go install ./cmd/falcon
```

---

## Quick start

```bash
# Minimum useful invocation: spec + two authenticated users
falcon --spec openapi.json \
       --auth-a bearer:eyJhbGciOi.USER_A_TOKEN \
       --auth-b bearer:eyJhbGciOi.USER_B_TOKEN

# Override a spec base URL (e.g. hit staging instead of what the spec says)
falcon --spec openapi.json -u https://staging.example.com \
       --auth-a bearer:TOKA --auth-b bearer:TOKB

# Fill a {id} path param with a value that exists in your test environment
falcon --spec openapi.json \
       --auth-a bearer:TOKA --auth-b bearer:TOKB \
       --resource id=42

# Cookie auth instead of bearer
falcon --spec openapi.json \
       --auth-a "cookie:session=aaa..." \
       --auth-b "cookie:session=bbb..."

# Custom header (e.g. X-API-Key)
falcon --spec openapi.json \
       --auth-a "header:X-API-Key=KEY-A" \
       --auth-b "header:X-API-Key=KEY-B"

# Route through Burp for inspection
falcon --spec openapi.json -x http://127.0.0.1:8080 -k \
       --auth-a bearer:TOKA --auth-b bearer:TOKB

# CI output — SARIF uploads to GitHub code scanning
falcon --spec openapi.json --auth-a bearer:TOKA --auth-b bearer:TOKB \
       --json out.json --sarif out.sarif
```

Sample output against a deliberately-vulnerable API:

```
falcon: 9 finding(s) for http://127.0.0.1:9980

  [HIGH  ] broken-authentication    GET /public/stats
        no-auth request returned success with the same body shape as an authenticated request — the endpoint does not enforce authentication
        - user-a           status=200 len=61
        - no-auth          status=200 len=61
        - invalid-token    status=200 len=61

  [HIGH  ] cross-user-access        GET /users/{id}
        two distinct user identities received success responses with the same body shape — same resource visible to both (IDOR if the path addresses a specific resource)
        - user-a           status=200 len=102
        - user-b           status=200 len=102
        - no-auth          status=401 len=20

  [HIGH  ] invalid-token-accepted   GET /me
        a request with an obviously invalid bearer token returned the same success body as a real-user request — token validation is not actually performed

  [LOW   ] auth-server-error        GET /crash
        identity "no-auth" triggered a 5xx response — a server error under adversarial auth input often indicates an exception path in middleware worth inspecting

  [INFO  ] role-differential        GET /admin/panel
        test identities received materially different authorization outcomes for the same non-ownership-scoped request — review whether this reflects intended RBAC or a vertical-privilege leak
```

---

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--spec` | *(required)* | Path to OpenAPI 3.x JSON spec |
| `-u` | *(from spec)* | Target base URL; overrides the spec's `servers:` entry |
| `--auth-a` | — | Auth for identity A (see auth formats below). At least one of `-a` / `-b` is required |
| `--auth-b` | — | Auth for identity B — needed to detect cross-user access/IDOR |
| `--anon` | `true` | Also run every request with no auth (catches missing-auth endpoints) |
| `--invalid-token` | `true` | Also run every request with an obviously-invalid bearer (catches middleware that doesn't actually validate) |
| `--resource` | — | Fill a spec parameter with a concrete value, repeatable: `--resource id=42 --resource slug=abc` |
| `-c` | `10` | Concurrent requests across all identities |
| `-timeout` | `15s` | Per-request timeout |
| `-k` | `false` | Skip TLS verification (self-signed dev/staging certs only) |
| `-x` | — | Route all requests through an HTTP proxy (e.g. `http://127.0.0.1:8080` for Burp/ZAP) |
| `--json` | — | Write findings as JSON to this path |
| `--sarif` | — | Write findings as SARIF 2.1.0 to this path (for GitHub code scanning) |
| `--no-banner` | `false` | Suppress the startup banner |

**Auth formats:** `bearer:<token>` | `cookie:<name=val; name=val>` | `basic:<user>:<pass>` | `header:<Name>=<Value>`

---

## How it works

Falcon's differential model is deliberately small and explicit. For every operation in the spec, it fires the same request as each configured identity (user-A, user-B, no-auth, invalid-token), captures the response matrix, and matches it against a fixed set of patterns:

```
                ┌─────────────┐
   OpenAPI ──►  │   spec      │  parse + build request templates
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │  identity   │  user-a, user-b, anon, invalid
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │   engine    │  fire N identities × M operations in parallel
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │   diff      │  SimHash-based body comparison +
                │             │  pattern matching → named findings
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │  report     │  text / JSON / SARIF
                └─────────────┘
```

**Why SimHash for body comparison?** A naive byte-equality check misses IDOR when the server embeds a per-request CSRF token or timestamp into the response. A hash that ignores volatile tokens but preserves the content shape catches identity leaks across responses that aren't identical.

---

## Testing

```bash
go test ./...
go test -race ./...
```

Unit tests cover every classifier pattern with explicit response matrices, plus the critical **false-positive** invariant: a normal owner-only `/users/{id}` endpoint (user-A gets 200, user-B gets 403) must produce **zero** findings.

---

## Legal & ethics

Falcon sends real HTTP requests with real authentication credentials to real APIs. **Only point it at targets you are explicitly authorized to test.** Unauthorized authenticated scanning against systems you don't own or have permission to test is almost certainly illegal and almost certainly a breach of the API's terms of service even if the data isn't yours.

Use test accounts you created specifically for this purpose. Don't scan production with your real credentials.

---

## Contributing

Issues and PRs welcome. If you're adding a classifier pattern, add the response-matrix test that proves (a) it fires when the bug is real and (b) does NOT fire on the common legitimate scenario that looks superficially similar.

## License

[MIT](LICENSE)
