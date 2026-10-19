# Work 1: Secure REST API Development with CI/CD and CVE Analysis

Author: zhuhe, HDU number 23320116.

Repository: https://github.com/AlaIchhe/hdu-is-work1-secure-api

[![Secure API CI](https://github.com/AlaIchhe/hdu-is-work1-secure-api/actions/workflows/ci.yml/badge.svg)](https://github.com/AlaIchhe/hdu-is-work1-secure-api/actions/workflows/ci.yml)

This repository contains the complete Work 1 implementation:

- a Flask REST API with JWT authentication, password hashing, parameterized
  SQL, output encoding, and security headers;
- automated tests;
- a GitHub Actions pipeline with Bandit SAST, pip-audit SCA, tests, and a
  container build;
- a reproducible Vulhub environment for CVE-2022-22947;
- a fixed Spring Cloud Gateway build and a regression/verification script.

## Project structure

~~~text
app.py                         Flask entry point
secure_api/                    application package
tests/                         API tests
scripts/smoke_test.py          curl-based authentication/security smoke test
scripts/render_terminal.py     evidence screenshot renderer
.github/workflows/ci.yml       CI pipeline
vulnerable-environment/        vulnerable and fixed CVE-2022-22947 images
screenshots/                   reproduced evidence screenshots
~~~

## API

Base URL in the container: http://127.0.0.1:5000

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| POST | /api/auth/login | No | Authenticate with username and password and receive a JWT |
| GET | /api/data | Bearer JWT | Read the protected post feed |
| POST | /api/posts | Bearer JWT | Create a post (the third endpoint chosen for this work) |
| GET | /health | No | Container health check |

The API stores users and posts in SQLite. The schema is created automatically
on startup. When both demo password variables are present, the entrypoint seeds
an admin user, an alice user, and two demonstration posts once.

### Run with Docker

~~~bash
cp .env.example .env
# Replace the three placeholder values in .env with strong local values.
docker compose up --build -d
curl http://127.0.0.1:5000/health
~~~

### Run the tests

~~~bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
~~~

### Call the API

The smoke test invokes curl and checks the full authentication and injection
flow without exposing a shell token-extraction command:

~~~bash
python3 scripts/smoke_test.py
~~~

The generic curl flow is:

~~~bash
curl -sS -X POST http://127.0.0.1:5000/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"YOUR_PASSWORD"}'

curl -sS http://127.0.0.1:5000/api/data -H "Authorization: Bearer YOUR_JWT"

curl -sS -X POST http://127.0.0.1:5000/api/posts -H "Content-Type: application/json" -H "Authorization: Bearer YOUR_JWT" -d '{"title":"A title","body":"A body"}'
~~~

## Implemented security measures

### SQL injection prevention

Every database operation uses SQLite placeholders and a separate parameter
list. No SQL statement is built by concatenating user input. Login lookup,
post insertion, and post selection all follow this pattern:

~~~python
connection.execute(
    "SELECT id, username, password_hash FROM users WHERE username = ?",
    (username,),
)
~~~

The test suite submits both an authentication bypass string and a destructive
post body containing DROP TABLE. The login remains denied, the table remains
available, and the malicious text is stored and returned as inert data.

### XSS prevention

All user-controlled fields returned by the API pass through
html.escape(value, quote=True). This includes usernames, post titles, and post
bodies. JSON responses use application/json, and every response also receives
the following defensive headers:

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: no-referrer
- Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
- Cache-Control: no-store on API responses

The XSS test stores a script and event-handler payload, then verifies that the
GET response contains HTML entities instead of executable markup.

### Authentication

- Passwords are hashed with scrypt through Werkzeug's password-hashing helper.
  The stored format uses N=32768, r=8, p=1, a random 16-byte salt, and a
  64-byte derived key. Plaintext passwords are never stored.
- Successful login issues a signed HS256 JWT with sub, username, iat, nbf,
  exp, iss, aud, and jti claims.
- Tokens expire after 15 minutes and are validated for signature, issuer,
  audience, required claims, and time bounds.
- The authentication helper compares against a dummy scrypt hash when a user
  does not exist, reducing username-enumeration timing differences.
- Protected endpoints require the Authorization: Bearer header and return a
  generic 401 response for missing, malformed, expired, or tampered tokens.

Evidence:

![Authentication and protected data](screenshots/01-api-auth-and-data.png)

![SQL injection and XSS defenses](screenshots/02-api-injection-defenses.png)

![Automated tests](screenshots/03-pytest.png)

## CI/CD pipeline

The workflow in .github/workflows/ci.yml runs on every push and pull request:

1. installs Python 3.12 dependencies;
2. runs the pytest suite;
3. runs Bandit SAST against the application package;
4. runs pip-audit SCA against runtime dependencies;
5. builds the Docker image;
6. uploads JSON and text security reports as a workflow artifact.

The local equivalent of the security stages was executed successfully:

~~~text
bandit -r app.py secure_api -f txt
  No issues identified.

pip-audit -r requirements.txt
  No known vulnerabilities found.
~~~

![Bandit SAST report](screenshots/04-bandit-sast.png)

![pip-audit SCA report](screenshots/05-pip-audit-sca.png)

During development, pip-audit initially reported 17 advisories in Flask 3.1.2
and PyJWT 2.10.1. The dependencies were upgraded to Flask 3.1.3 and PyJWT
2.15.1, and the repeated audit reported no known vulnerabilities.

The public repository is live, and the GitHub Actions run for this CVE update
completed successfully. The workflow took 38 seconds end to end, including the
container build. The latest runs are available on the workflow page:

- Repository: https://github.com/AlaIchhe/hdu-is-work1-secure-api
- CI workflow: https://github.com/AlaIchhe/hdu-is-work1-secure-api/actions/workflows/ci.yml
- Verified successful run: https://github.com/AlaIchhe/hdu-is-work1-secure-api/actions/runs/39236852801

![GitHub Actions run](screenshots/09-github-actions.png)

## CVE analysis: CVE-2022-22947

### Vulnerability summary

CVE-2022-22947 is a Spring Expression Language (SpEL) injection vulnerability
in Spring Cloud Gateway before 3.1.1 and 3.0.7. NVD rates it CVSS 3.1 10.0
(Critical): AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H. If the Gateway Actuator
endpoint is enabled, exposed, and unsecured, a crafted route definition can
make the server evaluate attacker-controlled SpEL during filter binding. This
allows unauthenticated remote code execution.

The vulnerable environment follows the Vulhub configuration:

- base image: `vulhub/spring-cloud-gateway:3.1.0`;
- the Gateway Actuator endpoint is exposed without authentication;
- an example gateway route is configured;
- port 8080 is published for the lab.

### Reproduction

Start the vulnerable image:

~~~bash
docker compose -f vulnerable-environment/CVE-2022-22947/vulnerable/docker-compose.yml up -d
~~~

The exact commands are:

~~~bash
curl -sS http://127.0.0.1:8080/actuator/health
curl -sS http://127.0.0.1:8080/actuator/gateway/routes
~~~

The supplied script records the full request sequence:

~~~bash
python3 vulnerable-environment/CVE-2022-22947/exploit.py http://127.0.0.1:8080
~~~

Observed result:

- creating the route returned HTTP 201;
- refreshing the gateway returned HTTP 200 and evaluated the injected
  expression;
- reading the route returned the command output `uid=0(root) gid=0(root)
  groups=0(root)` in the filter value.

![Vulnerable and fixed gateway versions](screenshots/06-cve-vulnerable-version.png)

![CVE reproduction](screenshots/07-cve-reproduction.png)

### Root cause

Spring Cloud Gateway allows route filter arguments to contain SpEL. In version
3.1.0, `ShortcutConfigurable` evaluates those values with a
`StandardEvaluationContext`. That context supports type references,
constructors, and general method invocation. Because a route definition is
accepted from the Actuator API, an attacker can supply an expression that
references application classes and invokes arbitrary methods.

The vulnerable design crosses a trust boundary: untrusted HTTP input is treated
as executable expression text. Actuator exposure is a precondition, but the
code-level defect is the use of an unrestricted evaluation context for route
configuration data. The upstream fix commit replaces it with a restricted
`SimpleEvaluationContext`, which removes type resolution and the expression
features required by the exploit.

### Applied fix

The fixed image in `vulnerable-environment/CVE-2022-22947/fixed` builds the
same application with three hardening changes:

1. It upgrades `spring-cloud-gateway-server` from 3.1.0 to 3.1.1, which contains
   the restricted expression context.
2. It keeps the Actuator endpoint exposed during the test so the result shows
   that the code-level fix, not merely endpoint removal, blocks the attack.
3. It runs the service as the unprivileged `app` user as defense in depth.

For production, the Actuator endpoint should also be protected by network
policy and authentication. That reduces attack surface but is not a substitute
for the 3.1.1 dependency upgrade.

### Fix verification and regression test

~~~bash
docker compose -f vulnerable-environment/CVE-2022-22947/fixed/docker-compose.yml up -d --build
python3 vulnerable-environment/CVE-2022-22947/verify-fix.py http://127.0.0.1:8081
~~~

The fixed service reports `3.1.1` in its image label and packaged gateway JAR.
The malicious route is accepted by the create endpoint but is not loaded during
refresh; reading it returns HTTP 404, and no `uid=` output appears. At the same
time, the service health endpoint returns `UP`, the preconfigured index route
remains available, and a benign route filter still retains `fixed-ok`. The
container runs as `uid=999(app)`, not root.

![Fixed build verification](screenshots/08-cve-fix-verification.png)

### References

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-22947
- VMware advisory: https://tanzu.vmware.com/security/cve-2022-22947
- Upstream fix: https://github.com/spring-cloud/spring-cloud-gateway/commit/d8c255eddf4eb5f80ba027329227b0d9e2cd9698
- Vulhub: https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22947

## Reproduce the full validation

~~~bash
python -m pytest
python3 scripts/smoke_test.py
python3 vulnerable-environment/CVE-2022-22947/exploit.py http://127.0.0.1:8080
python3 vulnerable-environment/CVE-2022-22947/verify-fix.py http://127.0.0.1:8081
python3 scripts/render_terminal.py
~~~

## Submission checklist

- Public git repository: https://github.com/AlaIchhe/hdu-is-work1-secure-api
- Successful pipeline run: https://github.com/AlaIchhe/hdu-is-work1-secure-api/actions/runs/39236852801
- CI workflow page: https://github.com/AlaIchhe/hdu-is-work1-secure-api/actions/workflows/ci.yml
- README: this file.
- Fixes folder: vulnerable-environment/CVE-2022-22947/fixed.
- SAST/SCA screenshots: screenshots/04-bandit-sast.png and
  screenshots/05-pip-audit-sca.png.
- GitHub Actions screenshot: screenshots/09-github-actions.png.
- CVE reproduction and elimination screenshots: screenshots/07-cve-reproduction.png
  and screenshots/08-cve-fix-verification.png.
