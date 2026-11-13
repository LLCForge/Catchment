# Security Policy

Catchment runs close to network infrastructure, so we take security reports seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| `main` branch | Yes (best effort) |
| Older releases | No, please upgrade |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for security problems.**

Report privately through GitHub Security Advisories:

1. Go to [https://github.com/LLCForge/Catchment/security/advisories/new](https://github.com/LLCForge/Catchment/security/advisories/new).
2. Describe the issue, affected version or commit, and steps to reproduce.
3. Include a proof of concept if you have one. Strip any real customer data, IP addresses or credentials from captures and logs.

What to expect:

- Acknowledgement within **3 business days**.
- An initial assessment and severity rating within **10 business days**.
- A fix or mitigation plan, coordinated disclosure date, and credit in the advisory (unless you prefer to stay anonymous).

## In scope

- Ways to make Catchment (controller or agent) send measurement traffic to anything other than the configured target, or to make an agent probe outside its `allowed_targets`.
- Bypassing the agent's mutual TLS (client certificate verification), or reaching its HTTP handler without a valid certificate.
- Malformed DNS, ICMP, HTTP, RIPE Atlas, agent or Pathology input that crashes Catchment, exhausts memory or is counted as a reply to one of our probes.
- Injection through measurement data into HTML reports (including the map and its embedded JSON), terminal output, alerts or CSV (formula injection).
- Unauthenticated access to `/v1/silences` or `POST /v1/reload`.
- Leakage of the RIPE Atlas API key, alert sink secrets or the Pathology token.
- Dependency vulnerabilities that are reachable from Catchment's code paths.

## Attack surface

| Surface | Exposure | Protection |
|---|---|---|
| `/metrics`, `/healthz`, `/readyz` | read-only, unauthenticated | bind to loopback / management network (default `127.0.0.1:9184`) |
| `/v1/silences`, `POST /v1/reload` | mounted only when `[silences] api_token_env` / `[health] admin_token_env` are set | bearer token from the environment, constant-time comparison, 16 KiB bodies, strict validation |
| `catchment agent` (`POST /v1/probe`) | network-facing | TLS 1.2/1.3 (rustls) with mandatory client certificates from a dedicated CA, bounded handshakes (64 in flight, 10 s), 16 KiB request limit, local target allowlist, traceroute opt-in, concurrency limit (429) |
| Raw sockets (local traceroute) | needs CAP_NET_RAW / root / Administrator | opt-in, only own probes are matched, fixed-size buffers; without privileges it is skipped |
| HTML report | opened in a browser | all values escaped, embedded JSON escapes `<>&`, CSP pins the four bundled scripts by SHA-256, no remote resources |
| Outbound HTTP (Atlas, RIPEstat, agents, Pathology, HTTP identification) | client | size limits, timeouts, no redirects for agents / Pathology / HTTP identification, plain `http://` to Pathology only on loopback |

## Out of scope

- Vulnerabilities in third-party services or protocols themselves (report those upstream).
- Issues that require an attacker to already control the host or the config file.
- Denial of service by volumetric flooding of the network the tool runs on.

## Hardening recommendations

- Run as an unprivileged user; grant `CAP_NET_RAW` only when the local traceroute is enabled.
- Bind the metrics/health listener to localhost or a management network; set admin tokens only if you need the silence / reload API.
- Use a dedicated CA for agents (not your web PKI), keep `allowed_targets` as narrow as your anycast prefixes and leave `allow_traceroute` off unless needed.
- Set RIPE Atlas `budget` caps so a misconfiguration cannot drain your credits.
- Keep secrets in environment variables or your secret manager, never in the config file or in version control.
