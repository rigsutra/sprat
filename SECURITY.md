# Security policy

## Reporting a vulnerability in SPRAT

Please don't open a public issue. Report it privately through GitHub:
[Report a vulnerability](https://github.com/rigsutra/sprat/security/advisories/new).

Include what an attacker can do, the steps to reproduce, and the SPRAT version.
You should get a reply within 7 days. Once a fix is released you'll be credited in
the advisory unless you'd rather not be.

## Supported versions

Only the latest release gets security fixes.

## What counts

Problems in SPRAT itself, for example:

- secrets (tokens, passwords, `${NAME}` values) leaking into reports, logs, exports
  or the web UI
- the web UI letting another machine or web page run tests or read data
- path traversal or code execution through a spec, config file or project import

Findings that SPRAT reports about *your* API are not vulnerabilities in SPRAT.

## Using SPRAT safely

SPRAT is an attack tool. Run it only against APIs you own or have written
permission to test, and against staging, never production. The web UI binds to
`127.0.0.1` by default. Don't expose it on a network without authentication in
front, because it sends requests to any URL it's given.
