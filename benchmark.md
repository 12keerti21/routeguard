# Benchmark

How well routeguard finds real authorisation bugs, and how much noise it makes on well-built apps.

## 1. Existing scanners miss authorisation bugs

[VAmPI](https://github.com/erev0s/VAmPI) is a deliberately vulnerable API with nine documented bugs.
Each was checked by hand, then scanned with Semgrep (`p/security-audit` and `p/owasp-top-ten`, 233 rules)
and Bearer (88 rules).

| Bug | OWASP API 2023 | Semgrep | Bearer |
|---|---|---|---|
| Any user reads another user's book secret | API1 BOLA | ❌ | ❌ |
| Register as admin with `"admin": true` | API3 Mass assignment | ❌ | ❌ |
| Change another user's password | API1 BOLA | ❌ | ❌ |
| SQL injection in user lookup | API8 Injection | ❌ | ❌ |
| Debug endpoint lists every user and password | API3 Data exposure | ❌ | ❌ |
| User and password enumeration | API2 Broken authentication | ❌ | ❌ |
| Regex denial of service on email update | API4 Resource consumption | ❌ | ❌ |
| No rate limit on login | API4 Resource consumption | ❌ | ❌ |
| Weak JWT signing key | API2 Broken authentication | ✅ | ❌ |
| **Found** | | **1 of 9** | **0 of 9** |

VAmPI is written in Python, so routeguard (Express only) was measured on the Express targets below.

## 2. routeguard on vulnerable Express APIs

Bugs documented by each project, and whether routeguard reports them.

| Target | Documented bug | Found |
|---|---|---|
| [vulnerable-rest-api](https://github.com/bnematzadeh/vulnerable-rest-api) | BOLA on `GET /api/users/:name` and `PUT /api/users/:id` | ✅ |
| | Function-level authorisation on book and author create, edit and delete | ✅ |
| | Mass assignment on `POST /api/users` | ✅ |
| | SSRF on `PUT /api/users/:id` | ✅ |
| | Old development copy of `GET /api/users` without auth | ✅ |
| [APIGOAT](https://yusufarbc.github.io/apigoat) | API1 BOLA on file routes | ✅ |
| | API3 property-level authorisation and `isAdmin` from the body | ✅ |
| | API5 function-level authorisation on books | ✅ |
| | API6 unthrottled bookings | ✅ |
| | API7 SSRF on `/weather` | ✅ |
| | API8 open CORS and a debug endpoint | ✅ |
| | API10 third-party data relayed unchecked | ✅ |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | View another user's basket | ✅ |
| | Exposed metrics | ✅ |
| | SSRF through the profile image URL | ✅ |
| | Forged coupons (no limit on coupon redemption) | ✅ |
| | Brute-forceable login | ✅ |

Bugs routeguard also found that the projects do not list:

- vulnerable-rest-api: any signed-in user can delete any user; logs and a key are served without auth;
  login and sign-up return the password hash; JWT verification accepts both RS256 and HS256 (algorithm
  confusion); the admin login has no rate limit.
- APIGOAT: an API key written into a URL.
- Juice Shop: checking out another user's basket, and editing another user's basket items.

## 3. Static findings confirmed at runtime

`routeguard verify` against a live OWASP Juice Shop (Docker), with two ordinary customer accounts:

| Route | Verdict |
|---|---|
| `GET /rest/basket/:id` | CONFIRMED: the second user reads the first user's basket (static BOLA finding confirmed) |
| `GET /api/Users/:id` | CONFIRMED: the second user reads the first user's account (missed by static analysis: generic handler) |
| `GET /metrics`, `/rest/admin/application-configuration`, `/rest/admin/application-version` | CONFIRMED: reachable with no credentials (static BFLA findings confirmed) |
| `GET /api/Addresss/:id`, `GET /api/Cards/:id` | PROTECTED: the second user is refused (static analysis agreed) |
| Product reviews, delivery methods, order tracking, recycling | PUBLIC: open by design |

Fourteen routes replayed, including the static scan, in under a second.

## 4. Noise on real applications

Eighteen open-source Express apps, most of them well maintained. A good result here is few findings,
and HIGH findings that hold up when read by hand.

| App | Routes | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| [Overleaf](https://github.com/overleaf/overleaf) | 502 | 2 | 4 | 13 |
| [Ghost](https://github.com/TryGhost/Ghost) | 336 | 0 | 0 | 4 |
| [Directus](https://github.com/directus/directus) | 307 | 0 | 0 | 4 |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (vulnerable on purpose) | 124 | 8 | 9 | 6 |
| [NodeBB](https://github.com/NodeBB/NodeBB) | 118 | 1 | 4 | 2 |
| [hackathon-starter](https://github.com/sahat/hackathon-starter) | 103 | 0 | 1 | 1 |
| [Actual Budget](https://github.com/actualbudget/actual) (sync server) | 70 | 1 | 2 | 4 |
| [Kutt](https://github.com/thedevs-network/kutt) | 63 | 0 | 0 | 2 |
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | 56 | 0 | 0 | 3 |
| [HedgeDoc 1.x](https://github.com/hedgedoc/hedgedoc) | 56 | 0 | 1 | 5 |
| [Verdaccio](https://github.com/verdaccio/verdaccio) | 55 | 0 | 0 | 3 |
| [Etherpad](https://github.com/ether/etherpad-lite) | 40 | 1 | 0 | 8 |
| [mongo-express](https://github.com/mongo-express/mongo-express) | 32 | 0 | 0 | 1 |
| [AfterAcademy backend](https://github.com/afteracademy/nodejs-backend-architecture-typescript) | 30 | 0 | 0 | 2 |
| [RealWorld example](https://github.com/gothinkster/node-express-realworld-example-app) | 20 | 0 | 1 | 3 |
| [node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate) | 15 | 0 | 0 | 1 |
| [express-rest-boilerplate](https://github.com/danielfsousa/express-rest-boilerplate) | 15 | 0 | 4 | 3 |
| [bulletproof-nodejs](https://github.com/santiq/bulletproof-nodejs) | 6 | 0 | 2 | 2 |
| **Total** | **1,948** | **13** | **28** | **67** |

Every HIGH and MEDIUM outside Juice Shop was read by hand:

| Finding | Verdict |
|---|---|
| Overleaf: `/debug/events` and `/metrics` without auth on internal services | Real. Safe only while those services stay off the public network. |
| Actual: `/metrics` (memory and uptime) without auth | Real, low impact |
| Etherpad: the admin API's OpenAPI spec is public | Real, low impact |
| Boilerplates and RealWorld: login, sign-up and reset routes with no rate limit | Real |
| hackathon-starter: a search term placed into a fixed API host's URL | Real, low impact |
| Overleaf: first-admin setup with no rate limit | Real, low impact: it works once |
| NodeBB: error objects returned by the asset minifier | Real, low impact |
| NodeBB: `/api/config` is public | By design: the browser client needs it |
| NodeBB: login and registration with no rate limiter | Arguable: NodeBB locks accounts after failed attempts instead |
| Actual: bank-sync steps any signed-in user can run | Arguable: depends on multi-user mode |
| Overleaf and NodeBB: development routes (Overleaf's `/dev/csrf`, a NodeBB debug route) | By design: development only |
| HedgeDoc: redirect to the URL GitHub's API returns | Fair, though the provider is trusted |

No HIGH or MEDIUM finding was a plain false positive. Scanning all 18 apps (1,948 routes) takes about 12 seconds on a laptop.

Not included: Wiki.js 3 is built on Fastify, and routeguard says so and stops trusting its own results
there; Habitica registers its routes through its own framework, so only a handful are visible.
