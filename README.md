# routeguard

**Find broken authorisation in Express APIs before attackers do.**

routeguard reads your Express code without running it. It maps every route to the checks that protect
it, then flags the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
risks that general code scanners miss. The biggest of these is one user reaching another user's data.

```
$ routeguard ./my-api

METHOD  PATH                 MIDDLEWARE   AUTH  ROLE  WHERE
GET     /api/orders/:id      auth         ✅     ❌     routes/orders.js:12
DELETE  /api/users/:id       auth, admin  ✅     ✅     routes/users.js:40
...

[HIGH] BOLA  GET /api/orders/:id  (services/order.service.js:18)
  API1:2023 Broken Object Level Authorization
  findById via getOrder uses an id from the URL, and nothing on the way checks it against the caller.
  Fix: scope the query to the caller: findOne({ _id: id, owner: req.user._id }).
```

## Why

Tools like Semgrep and Bearer are good at injection and secrets. Authorisation bugs are different:
the code looks fine line by line, and the flaw is a check that is *missing*. On a deliberately
vulnerable API, Semgrep found 1 of 9 bugs and Bearer found none ([benchmark](https://github.com/12keerti21/routeguard/blob/main/benchmark.md)).

## What it checks

| OWASP API 2023 | Check |
|---|---|
| API1 Broken Object Level Authorization | A record is loaded or changed by a URL id, and nothing on the way checks it belongs to the caller. Follows the id into service functions. |
| API2 Broken Authentication | JWT algorithm confusion, `alg: none`, ignored expiry, signing keys in the code |
| API3 Broken Object Property Level Authorization | Whole request bodies written to records (`new User(req.body)`), `isAdmin` taken from the client, whole user records sent back |
| API4 Unrestricted Resource Consumption | Login, OTP, reset and sign-up routes with no rate limit |
| API5 Broken Function Level Authorization | Admin, debug, metrics and log routes with no role check; shared data any user can change |
| API6 Unrestricted Access to Sensitive Business Flows | Checkout, coupon, booking and review flows with nothing against bots |
| API7 Server Side Request Forgery | The server fetches a URL the client chose |
| API8 Security Misconfiguration | CORS open to any origin with credentials, stack traces in responses, missing security headers |
| API9 Improper Inventory Management | Old or development copies of an endpoint with weaker checks, routes missing from the OpenAPI spec |
| API10 Unsafe Consumption of APIs | Third-party responses stored, run or redirected to without validation; plain-http calls; API keys in URLs |

## Use it

```bash
npx routeguard-cli <path-to-express-app>
```

Or install it with `npm install -g routeguard-cli` and run `routeguard`. From a clone of this repo:

```bash
cd tool && npm install
node bin/cli.js <path-to-express-app>                 # table and findings
node bin/cli.js <path-to-express-app> --json          # machine-readable
node bin/cli.js <path-to-express-app> --sarif         # for GitHub code scanning
node bin/cli.js <path-to-express-app> --fail-on HIGH  # exit 2 only on HIGH findings
```

Requires Node 20 or later. Works with JavaScript and TypeScript, `require` and `import`, monorepos and
package.json `#imports`.

### In GitHub Actions

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
        uses: 12keerti21/routeguard@v1
        with:
          path: .
          fail-on: HIGH
      - uses: github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        if: always()
        with:
          sarif_file: ${{ steps.routeguard.outputs.sarif-file }}
```

Findings appear on the pull request and under **Security → Code scanning**.

### Silence a reviewed finding

Put a comment in the three lines above the route:

```js
// the share id is unguessable and is the key
// routeguard-ignore BOLA
router.get("/shared/:shareId", getSharedNote)
```

Leave out the rule name to silence every rule for that route.

## How it works

1. **Map the routes.** Parses every source file and follows `app.use` and `router.use` mounts, so each
   route gets its full path and every middleware in front of it, including middleware applied to a
   whole path or router.
2. **Read the handlers.** Finds each route's handler, even in another file, a controller object or a
   wrapper like `catchAsync(...)`.
3. **Follow the data.** For object-level checks, traces the URL id from the handler into the
   services it calls. It looks for the caller (`req.user`) limiting that id along the way: in the
   query, in a comparison, or in a check such as `canEdit(user, course)`.
4. **Report.** Each finding has a severity, the OWASP category, the file and line, and a fix.

## Limits

- routeguard trusts what a check returns. If `canEdit()` itself has a logic bug, it won't see it.
- Static analysis cannot know an id is unguessable. Capability links need a `routeguard-ignore` comment.
- Express only for now.

## Results

Tested on deliberately vulnerable APIs and 14 open-source Express apps (1,400+ routes). See
[benchmark.md](https://github.com/12keerti21/routeguard/blob/main/benchmark.md).

## Development

```bash
cd tool && npm test
```

Tests run every check against a small fixture app that has a vulnerable and a safe version of each
pattern.
