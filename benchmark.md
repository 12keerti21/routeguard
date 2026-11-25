# Benchmark: what existing scanners catch

Target: [VAmPI](https://github.com/erev0s/VAmPI) (Flask), `vulnerable=1`.
Semgrep rulesets: `p/security-audit`, `p/owasp-top-ten` (233 rules, run 2026-11-25).

| # | Vulnerability | OWASP API 2023 | Location | Exploited by hand | Semgrep | Bearer | Our tool |
|---|---|---|---|---|---|---|---|
| 1 | Book secret readable by any user | API1 BOLA | `api_views/books.py:51` | ✅ | ❌ | ❌ | |
| 2 | Register as admin via `"admin": true` | API3 Mass assignment | `api_views/users.py:60` | ✅ | ❌ | ❌ | |
| 3 | Change another user's password | API1 BOLA | `api_views/users.py:186` | ✅ | ❌ | ❌ | |
| 4 | SQL injection in user lookup | API8 Misconfig / injection | `models/user_model.py:72` | | ❌ | ❌ | |
| 5 | `/users/v1/_debug` leaks all user data | API3 Excessive data exposure | `api_views/users.py:24` | ✅ | ❌ | ❌ | |
| 6 | User and password enumeration | API2 Broken authentication | `api_views/users.py:101` | | ❌ | ❌ | |
| 7 | Regex DoS on email update | API4 Resource consumption | `api_views/users.py:143` | | ❌ | ❌ | |
| 8 | No rate limiting on login | API4 Resource consumption | `api_views/users.py` (login) | | ❌ | ❌ | |
| 9 | Weak JWT signing key | API2 Broken authentication | `config.py:13` | | ✅ (hard-coded `SECRET_KEY`) | ❌ | |

**Semgrep: 1 of 9.** Its other 6 findings were Dockerfile and CI hygiene, not API flaws.

**Bearer (v0.48.4, 88 Python rules): 0 of 9.** Its one finding, a weak PRNG in the seed's book titles, is a false positive.

## Express: our BOLA rule (v0.1)

Target: [vulnerable-rest-api](https://github.com/bnematzadeh/vulnerable-rest-api), ground truth in its `vulnerabilities/vulnerabilities.md`.

| Route | Ground truth | Our tool |
|---|---|---|
| GET /api/users/:name | API1 BOLA | ✅ MEDIUM |
| PUT /api/users/:id | API1 BOLA | ✅ HIGH |
| PUT, DELETE /api/books/:id | API5 BFLA (should be admin-only) | ✅ flagged, labelled BOLA |
| PUT, DELETE /api/authors/:id | API5 BFLA | ✅ flagged, labelled BOLA |
| DELETE /api/users/:id | not listed, but any user can delete anyone | ✅ HIGH (real bug) |
| POST /api/books, /api/authors | API5 BFLA | ✅ BFLA MEDIUM (v0.2) |
| POST /api/users (`new User(req.body)`) | API3 Mass assignment | ✅ HIGH (v0.3) |
| GET /api/logs, /api/system/key | not listed, but logs and a key are open to anyone | ✅ BFLA HIGH (v0.2) |

APIGOAT: API1 (both file routes) ✅, API3 `GET /users/:userId` ✅, API5 `POST /books` and `PATCH /books/:bookId` ✅, API3 `POST /signup` (`isAdmin: req.body.isAdmin`) ✅, API8 `GET /debug/info` ✅ (labelled BFLA; really misconfiguration). `POST /bookings` in API6 is flagged because bookings aren't tied to the user, which is a real gap, though API6's intended bug is the unthrottled flow.

False positives: 0 across both targets.

## SSRF, data exposure and rate limits (v0.6)

| Target | Ground truth | Our tool |
|---|---|---|
| vulnerable-rest-api `PUT /api/users/:id` (`needle('get', req.body.url)`) | API7 SSRF | ✅ HIGH |
| vulnerable-rest-api dev vhost `GET /api/users` | API9 old endpoint, every user | ✅ DATA_EXPOSURE HIGH |
| vulnerable-rest-api `POST /api/auth`, `POST /api/users` | not listed: both return the whole user, password hash included | ✅ DATA_EXPOSURE HIGH |
| APIGOAT API3 `GET /users/:userId` | API3 excessive data exposure | ✅ MEDIUM |
| APIGOAT API7 `/weather` | API7 | ✅ MEDIUM: input inside a fixed host's URL |
| Juice Shop `POST /profile/image/url` | known SSRF challenge | ✅ HIGH |
| Juice Shop `POST /rest/user/login` | known brute-force exposure | ✅ RATE_LIMIT |
| node-express-boilerplate `/v1/auth/*` | limited by `app.use('/v1/auth', authLimiter)` in another file | ✅ no finding, once array-registered routes and cross-file path guards were mapped |

## Misconfiguration and inventory (v0.7)

| Target | Ground truth | Our tool |
|---|---|---|
| vulnerable-rest-api dev vhost `GET /api/users`, no auth, next to the admin-only copy | API9 improper inventory | ✅ SHADOW_ROUTE HIGH |
| vulnerable-rest-api `jwt.verify(…, { algorithms: ['RS256', 'HS256'] })` | not listed: algorithm confusion | ✅ JWT HIGH |
| APIGOAT API8 `app.use(cors())` | API8 permissive CORS | ✅ CORS LOW (no credentials) |
| APIGOAT API1–8 `res.status(500).json({ err })` | raw errors in responses | ✅ ERROR_LEAK LOW |

Real apps: only LOW CORS and header notes, no HIGH. Noise removed on the way: CORS headers are paired
per function (Uptime Kuma's `allowAllOrigin` sends no credentials), shadows compare only routes whose
full path is known, and a partial spec (Juice Shop's B2B swagger) is checked under its own base path.

## Business flows and API consumption (v0.8)

| Target | Ground truth | Our tool |
|---|---|---|
| APIGOAT API6 `POST /bookings` | API6 unrestricted business flow | ✅ BUSINESS_FLOW LOW |
| APIGOAT API10 `/weather` | API10: the provider's answer is relayed as is | ✅ UNSAFE_CONSUMPTION LOW |
| APIGOAT API10 `appid=2ee846af…` in the URL | not listed: an API key in the code | ✅ SECRET_IN_URL HIGH |
| Juice Shop `PUT /rest/basket/:id/coupon/:coupon` | known Forged Coupon challenge | ✅ BUSINESS_FLOW MEDIUM |
| hackathon-starter Steam profile call | not a planted bug: `http://` with the API key in the query | ✅ UNSAFE_CONSUMPTION LOW |

Noise removed: flows match whole path segments ("books" and "facebook" are not bookings,
"tokenTransfer" is not money), `robots()` is not anti-automation, a token in the path gates a flow,
third-party data is tracked per function (two functions' `message` never mix), and a value that
went through `schema.parse()` counts as validated.

## Round 2: five large production apps (v0.9)

[Ghost](https://github.com/TryGhost/Ghost), [Overleaf](https://github.com/overleaf/overleaf),
[Verdaccio](https://github.com/verdaccio/verdaccio), [mongo-express](https://github.com/mongo-express/mongo-express)
and [HedgeDoc 1.x](https://github.com/hedgedoc/hedgedoc): 983 routes, scanned in about 10 seconds in all.

| | First run | After fixes |
|---|---|---|
| Verdaccio routes mapped | 8 | 55 (paths are enum constants in another workspace package) |
| Findings, all five apps | 82 | 33 |
| HIGH | 27 | 2 |
| MEDIUM | 28 | 5 |

What was left after the fixes, read by hand:
- HIGH, Overleaf `GET /debug/events` (real-time service) and `GET /metrics` (metrics library): real, unauthenticated
  debug and metrics endpoints on internal services. Safe only while those services stay off the public network.
- MEDIUM, Overleaf `/launchpad/register_admin` (and LDAP and SAML variants): no limiter on first-admin setup. Low risk,
  since it works once.
- MEDIUM, Overleaf `GET /dev/csrf`: a health check under `/dev` that hands out a CSRF token. By design.
- MEDIUM, HedgeDoc: redirects to the URL GitHub's gist API returns. Fair, though GitHub is a trusted provider.
- No clear false positives left at HIGH or MEDIUM. LOWs (security headers, CORS notes, raw errors) were not
  reviewed one by one.

False positives found and fixed (each now has a test):
- test and vendored code scanned: Ghost's `e2e/` fake Stripe and Mailgun servers, `.yarn/releases/*.cjs` (hidden
  folders, test and mock folders, and files over 512 KB are skipped now)
- route paths as constants: `router.get(STAGE_API_ENDPOINTS.list)` from an `enum` in another workspace package,
  `` `${PREFIX}/users` ``, `Object.freeze({...})`, `export * from` (unresolvable ones stay visible as `<NAME>`)
- `requireGroupMemberManagement('group')`, `ensureProjectAccess`: role checks named for the right they check
- words, not substrings: `flushProjectToTpds` holds no "otp", and `adminAuth` is a login (a new true positive in
  vulnerable-rest-api)
- `/stage`, `/temp`, `/flush/old` and `/login/legacy` are feature names; only `dev`, `test`, `staging`, `sandbox` and
  `deprecated` near the top of a path count as non-production
- `key` in a path is an identifier (`/key/:key`, npm's public `/keys`), not a secret
- `/labels/transfer` is not money; a transfer needs a wallet, fund, balance or payment word next to it
- admin-only flows are not bot targets
- `getHistory(req.user.id, (err, history) => …)`: the callback's result is the caller's, and `history[noteId]` picks
  inside it
- controllers written as object methods (`const C = { getMessages(req, res) {…} }`)
- shadow routes are compared only within one app of a monorepo, and not for catch-alls
- `/-/v1/login_cli/:sessionId`: a session id in the URL is its own key

## Real-world apps (false-positive check)

Nine open-source Express apps, 438 routes, run 2026-11-25.

| App | Routes | Findings | Verdict |
|---|---|---|---|
| [hackathon-starter](https://github.com/sahat/hackathon-starter) | 101 | 0 | ✅ |
| [node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate) | 15 | 0 | ✅ |
| [express-rest-boilerplate](https://github.com/danielfsousa/express-rest-boilerplate) | 15 | 2 LOW | ✅ fair: `new User(req.body)` behind `authorize(...)` |
| [RealWorld example](https://github.com/gothinkster/node-express-realworld-example-app) (TS) | 20 | 0 | ✅ |
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | 59 | 1 LOW | ✅ `/metrics` behind an API key |
| [Kutt](https://github.com/thedevs-network/kutt) | 63 | 1 LOW | ✅ admin creates users from the whole body |
| [Etherpad](https://github.com/ether/etherpad-lite) (TS) | 35 | 2 LOW, 1 HIGH | ⚠️ LOWs are the public admin UI; HIGH is a public spec of the admin API (debatable) |
| [bulletproof-nodejs](https://github.com/santiq/bulletproof-nodejs) (TS) | 6 | 0 | ✅ |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (TS, deliberately vulnerable) | 124 | 6 | see below |

**Juice Shop**, where real bugs are expected:
- ✅ `GET /rest/basket/:id`: the known "View Basket" BOLA challenge
- ✅ `GET /metrics`: the known "Exposed Metrics" challenge
- ✅ `PUT /api/BasketItems/:id`: the item is fetched by id alone; the caller is read only for a challenge check
- ✅ `POST /rest/basket/:id/checkout`: checks out any basket by id and empties it; the caller is used only for the order's email (found once BOLA followed calls)
- ⚠️ `GET /rest/admin/application-configuration` and `/application-version`: public by design, but they expose config under an admin path

**False positives fixed along the way** (each now has a test):
- `router.route(path).get().post()` chains, controllers in other files, `catchAsync(...)` wrappers, handler factories (`asyncHandler(retrieveBasket())`)
- auth matched on the function's own name: `lusca.xssProtection`, `auth.featureAccess`, `helpers.verify`, `verify.jwtChallenges()` and `updateAuthenticatedUsers()` are not auth checks; `asyncHandler(auth.jwt)` and `auth.required` are
- `passport.session()` and `auth.optional` don't enforce anything
- `isAuthorized()` means signed in; `authorize(ADMIN)`, `auth('manageUsers')` and `isAccounting()` are role checks
- path-scoped guards: `app.use('/rest/basket', isAuthorized())`
- caller identity from `const { user } = req`, helpers like `authenticatedUsers.from(req)`, and `appendUserId()` middleware
- BOLA needs the caller in the query or an `if`, not just read somewhere
- role checks inside the handler (`requireAdmin(req, res)`), a secret in the URL (`/reset/:token`) or in the body (a link password)
- following calls into services: `if (!user)` checks login, not ownership, so a guard must compare the caller with what the id reached
- callbacks passed as arguments (`solveIf(() => user.bid != id)`) are not values
- reading a public parent to create the caller's own record (RealWorld's add-comment) is fine; an unscoped write next to it is not

## Next

- [ ] Repeat on crAPI (multi-service, more realistic)
