# routeguard

Static checker that maps an Express API's routes to their auth and role checks and flags
OWASP API Security Top 10 authorisation risks (BOLA first) that general SAST tools miss.

```bash
cd tool && npm install
node bin/cli.js <path-to-express-project>          # table + findings
node bin/cli.js <path-to-express-project> --json   # for CI
```

Exit code 2 when there are findings.

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
