![img](../../assets/banner.png)



<img src='../../assets/htb.png' style='zoom: 70%;' align=left /><font size='10'>Le paradis et l'enfer</font>

25<sup>th</sup> April 2026

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='red'>Hard</font>

<br><br>
<br><br>


# Synopsis

Le paradis et l'enfer is a secure coding challenge that exposes a cross-service trust boundary failure spanning a Go microservice and an Apache Tomcat portal. Players enumerate the provided Go source code to understand the inter-service authentication model, exploit a path traversal in the Tomcat forwarding servlet to recover the .gitignored trust validation module, and then implement a cryptographically sound replacement in the Go application. The lesson is that the service you can read is not the service you attack, and the service you attack is not the service you fix.

## Skills Required

- Go source code analysis.
- Apache Tomcat familiarity.
- Cross-service architecture understanding.
- Path traversal exploitation.
- Cryptographic concepts (HMAC-SHA256).
- Configuration enumeration.

## Skills Learned

- Identifying trust boundary failures in multi-service architectures.
- Using source code as a guide for black-box exploitation.
- Exploiting path traversal in a Tomcat servlet to recover hidden application logic.
- Replacing ambient header-based trust with HMAC token verification.
- Understanding the difference between patching a symptom and fixing a design flaw.


# Enumeration

Players connect to the challenge instance and are presented with two surfaces: a web Git UI at the root and the Empyrean Vault Portal at `/app`. The portal landing page identifies itself as a credential management gateway and documents its API surface, including a forwarding path at `/internal/forward/{path}` described as the route through which vault operations are proxied to an internal service.

Cloning the repository with the provided credentials reveals the Go source for `vault-svc`, an internal credential storage microservice. Reading `vault-svc/main.go` confirms the portal comment: all inbound requests arrive through `/internal/forward/`, and trust validation is delegated to a `trust/` package that is explicitly absent from the repository (listed in `.gitignore`).

The `.gitignore` entry for `vault-svc/trust/` is the key signal: something exists in the running container that was deliberately excluded from the source tree. The vault-svc handlers in `handlers/vault.go` confirm that secret reads and writes are gated behind a `TrustContext.IsElevated` flag, set by the missing trust package. Without knowing what that package does, it is impossible to understand - or fix - the authentication model.

# Identifying the Vulnerability

Armed with the servlet path from the Go source, the player queries the Tomcat application:

```bash
curl http://[IP]:[PORT]/app/internal/forward/trust/validator.go
```

The ForwardingServlet constructs a file path by concatenating a hard-coded base directory (`/opt/vault-svc/`) with the URL path info returned by `getPathInfo()`. Because Tomcat is configured with `encodedSolidusHandling="decode"`, URL-encoded slashes (`%2F`) are decoded before the path is handed to the servlet, allowing directory traversal to any path on the filesystem. The trust module and runtime configuration are directly accessible:

```bash
curl http://[IP]:[PORT]/app/internal/forward/vault-svc.properties
curl http://[IP]:[PORT]/app/internal/forward/trust/validator.go
curl http://[IP]:[PORT]/app/internal/forward/trust/config.go
```

The recovered `trust/validator.go` reveals the full flaw:

```go
func ValidateRequest(r *http.Request) (models.TrustContext, error) {
    header := r.Header.Get(cfg.TrustHeader)   // "X-Forwarded-By"
    if header == cfg.TrustValue {              // "tomcat-portal"
        return models.TrustContext{IsElevated: true, Source: cfg.TrustValue}, nil
    }
    return models.TrustContext{IsElevated: false}, nil
}
```

Trust is granted to any request carrying `X-Forwarded-By: tomcat-portal`. There is no signature, no token, no mutual TLS -- any HTTP client that knows this header value obtains elevated access. The design assumes that only the Tomcat portal can set this header, but that assumption is completely unenforceable over plain HTTP.

# Real-World Implications

- **Ambient header trust is not authentication.** Any header a trusted service sets can also be set by a hostile client. Relying on a header value as an identity proof is equivalent to trusting a piece of paper that says "I am the administrator."

- **Internal-only services are not isolated by default.** Labelling a service "internal" and binding it to loopback reduces the attack surface but does not eliminate it. SSRF vulnerabilities, compromised internal services, or misconfigured proxies can all reach "internal" endpoints.

- **Path traversal in file-serving servlets is a common pitfall.** Concatenating user-supplied path segments onto a base directory without normalization is a textbook vulnerability. The Java `File` constructor does not canonicalize paths; OS resolution of `..` sequences happens transparently.

- **Gitignored files are not secret.** A `.gitignore` entry prevents files from appearing in the repository, but deployed artifacts on the running host are still readable by anyone who can reach the filesystem -- directly or via an exploit.


# Solution

The correct fix replaces the header identity check in `trust/validator.go` with HMAC-SHA256 token verification. The Tomcat portal computes a per-request HMAC over the request path using a shared secret; vault-svc verifies the token on arrival. Because the secret is known only to the two parties, no third party can forge a valid token.

### Connecting to the server

Clone the repository using the provided developer credentials and switch to the `developer` branch.

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git
cd core_application
git checkout developer
```

### Recovering the trust module

Use the Tomcat ForwardingServlet to read the deployed trust source files.

```bash
curl http://[IP]:[PORT]/app/internal/forward/vault-svc.properties
curl http://[IP]:[PORT]/app/internal/forward/trust/validator.go
curl http://[IP]:[PORT]/app/internal/forward/trust/config.go
```

### Writing the fix

Replace `trust/config.go` to load a shared secret from the environment instead of the plaintext trust header values:

```go
package trust

import (
    "fmt"
    "os"
)

type Config struct {
    SharedSecret string
}

var cfg Config

func init() { cfg = loadConfig() }

func loadConfig() Config {
    secret := os.Getenv("VAULT_SHARED_SECRET")
    if secret == "" {
        panic(fmt.Sprintf("VAULT_SHARED_SECRET is required"))
    }
    return Config{SharedSecret: secret}
}
```

Replace `trust/validator.go` to verify an HMAC-SHA256 token:

```go
package trust

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net/http"
    "vault-svc/internal/models"
)

func ValidateRequest(r *http.Request) (models.TrustContext, error) {
    token := r.Header.Get("X-Trust-Token")
    if token == "" {
        return models.TrustContext{IsElevated: false}, nil
    }
    mac := hmac.New(sha256.New, []byte(cfg.SharedSecret))
    mac.Write([]byte(r.URL.Path))
    expected := hex.EncodeToString(mac.Sum(nil))
    if !hmac.Equal([]byte(token), []byte(expected)) {
        return models.TrustContext{}, fmt.Errorf("invalid trust token")
    }
    return models.TrustContext{IsElevated: true, Source: "tomcat-portal"}, nil
}
```

### Getting the flag

Force-add the trust module (it is gitignored), commit, and push to the developer branch. The scoring bot will validate the fix and merge the PR on success.

```bash
git add -f vault-svc/trust/
git commit -m "fix: replace header-based trust with HMAC token verification"
git push origin developer
```

Once the hard score validation passes, retrieve the flag from the `/flag` endpoint.

```bash
curl http://[IP]:[PORT]/flag
```
