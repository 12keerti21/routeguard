# routeguard

Static checker that maps an Express API's routes to their auth and role checks and flags
OWASP API Security Top 10 authorisation risks (BOLA first) that general SAST tools miss.

```bash
cd tool && npm install
node bin/cli.js <path-to-express-project>          # table + findings
node bin/cli.js <path-to-express-project> --json   # for CI
```

Exit code 2 when there are findings; `--fail-on HIGH` fails only on HIGH ones. `--sarif` writes
SARIF 2.1.0 for GitHub code scanning.

## GitHub Action

```yaml
name: routeguard
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 20
      - id: routeguard
        uses: 12keerti21/routeguard@main
        with:
          path: .
          fail-on: HIGH
      - uses: github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        if: always()
        with:
          sarif_file: ${{ steps.routeguard.outputs.sarif-file }}
```

Findings then show in the PR and under Security → Code scanning.

## Status

- Route mapper: Express `app`/`router` routes, nested mounts, `router.use` middleware
- Rules: BOLA (API1), BFLA (API5), mass assignment and excessive data exposure (API3),
  missing rate limits on login, OTP and reset flows (API4/API2), SSRF (API7)
- BOLA follows the URL id from the handler into the services it calls (up to 4 calls deep) and
  needs the caller to limit it on the way: in the query, in a guard that compares the caller with
  the record, or in a check call such as `canUpdate(user, course)`
- Suppress a reviewed finding with a comment in the three lines above the route:
  `// routeguard-ignore BOLA` (or `// routeguard-ignore` for every rule)
- Resolves `require`, ES imports and package.json subpath imports (`#modules/x.js`)
- Tests: `npm test` (fixture app with vulnerable and safe routes)
- Benchmark against Semgrep and Bearer: [benchmark.md](benchmark.md)

Test targets go in `labs/` (ignored): VAmPI, APIGOAT, vulnerable-rest-api.
