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

## Next

- [ ] Repeat on crAPI (multi-service, more realistic)
