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
- Rules: BOLA (API1), BFLA (API5), mass assignment (API3)
- Tests: `npm test` (fixture app with vulnerable and safe routes)
- Benchmark against Semgrep and Bearer: [benchmark.md](benchmark.md)

Test targets go in `labs/` (ignored): VAmPI, APIGOAT, vulnerable-rest-api.
