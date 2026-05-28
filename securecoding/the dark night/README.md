![img](../../assets/banner.png)



<img src='../../assets/htb.png' style='zoom: 70%;' align=left /><font size='10'>The Dark Night</font>

19<sup>th</sup> April 2026

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='orange'>Medium</font>

<br><br>
<br><br>


# Synopsis

The Dark Night is a secure coding challenge set within ORION SENTINEL, a fictional threat-intelligence analyst portal. Players are given access to the application source code and tasked with identifying and patching a cryptographic flaw inside a custom internal authentication library. The vulnerability is a predictable ECDSA signing nonce: the library derives the nonce `k` from the message payload alone, allowing any token observer to recover the private key with a single signature and forge arbitrary session tokens. The fix is a single function call swap to RFC 6979 deterministic nonce generation.

## Skills Required

- Python source code analysis.
- Cryptographic concepts (ECDSA, elliptic curve signatures, nonce reuse).
- Python packaging and internal library structure.
- Vulnerability identification in cryptographic primitives.

## Skills Learned

- Understanding ECDSA signing nonce requirements and why predictable nonces break security.
- Performing single-signature private key recovery via the nonce oracle equation.
- Applying RFC 6979 (`sign_deterministic`) as the correct countermeasure.
- Understanding Python pip package installation within a project monorepo.


# Enumeration

Players begin by cloning the challenge repository and reviewing its structure. The repository contains two top-level packages: `main_app` (a Flask analyst portal) and `darkauth` (an internal Python library providing token signing and verification).

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git
cd core_application
```

The `main_app/server.py` and `main_app/routes.py` files show how authentication works: a session cookie named `da_session` stores a compact token of the form `base64url(json_payload).ecdsa_signature_hex`. The token is created by `darkauth.sign(payload)` and verified by `darkauth.verify(payload, sig_hex)`.

Inspecting `darkauth/signer.py` reveals the internal implementation.

```python
def _derive_nonce(payload: str) -> int:
    # Deterministic nonce prevents exposure to weak system entropy at signing time.
    # A fixed relationship between message and nonce avoids RNG failure modes.
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return int(digest, 16) % NIST256p.order

def sign(payload: str) -> str:
    k = _derive_nonce(payload)
    signature = _SIGNING_KEY.sign(payload.encode(), k=k, hashfunc=hashlib.sha256, sigencode=sigencode_string)
    return signature.hex()
```

The misleading comment describes the intent as a safety measure. However, the nonce `k` is derived exclusively from the public payload -- the private key plays no role. Any observer who can read the signed token can independently compute `k`, and ECDSA algebra then allows recovery of the private signing key from a single signature.


# Identifying the Vulnerability

## The ECDSA Nonce Oracle

ECDSA signing produces a signature `(r, s)` over a message hash `h` using a nonce `k` and private key `d`:

```
r = (k * G).x mod n
s = k^-1 * (h + r*d) mod n
```

Rearranging for `d`:

```
d = (s*k - h) * r^-1 mod n
```

If `k` is known, `d` is directly computable from the public values `(r, s, h)`. In the vulnerable implementation:

```
k = sha256(payload) % n
h = sha256(payload) % n   (the signing hash, computed identically)
```

So `k == h`, and `d = (s*h - h) * r^-1 mod n = h*(s - 1)*r^-1 mod n`. An attacker only needs to observe a single valid token.

## Exploit Walkthrough

Log in as any analyst, decode the cookie, and recover the private key:

```python
import base64, hashlib
from ecdsa import NIST256p
from ecdsa.util import sigdecode_string

# Parse the token
payload_b64, sig_hex = token.rsplit(".", 1)
padded       = payload_b64 + "=" * (-len(payload_b64) % 4)
payload_json = base64.urlsafe_b64decode(padded).decode()
sig_bytes    = bytes.fromhex(sig_hex)
r, s         = sigdecode_string(sig_bytes, NIST256p.order)

# Recover the private key
h = int(hashlib.sha256(payload_json.encode()).hexdigest(), 16)
k = h % NIST256p.order
d = (s * k - h) * pow(r, -1, NIST256p.order) % NIST256p.order
```

With `d` in hand, sign a forged administrator payload:

```python
import json, time
from ecdsa import SigningKey
from ecdsa.util import sigencode_string

forge_data = {"display": "ORION Administrator", "iat": int(time.time()), "role": "admin", "sub": "administrator"}
forge_json = json.dumps(forge_data, separators=(",", ":"), sort_keys=True)
forge_b64  = base64.urlsafe_b64encode(forge_json.encode()).decode().rstrip("=")

h_f   = int(hashlib.sha256(forge_json.encode()).hexdigest(), 16)
k_f   = h_f % NIST256p.order
sig_f = SigningKey.from_secret_exponent(d, curve=NIST256p).sign(
            forge_json.encode(), k=k_f, hashfunc=hashlib.sha256, sigencode=sigencode_string)

forged_token = f"{forge_b64}.{sig_f.hex()}"
```

Setting `da_session=forged_token` grants full administrator access without valid credentials.


# Real-World Implications

- Predictable ECDSA nonces are a well-documented class of critical vulnerability, responsible for real-world incidents including the 2010 Sony PlayStation 3 key extraction, where a static nonce exposed the console's root signing key. A single leaked signature is sufficient for complete key compromise regardless of key size.

- Session token forgery converts a cryptographic flaw into a full authentication bypass. Any user with the ability to observe a valid token -- including an unprivileged authenticated user -- can impersonate any other account, including administrators.

- The fix is a one-line change: replacing `sign()` with `sign_deterministic()`, which implements RFC 6979 HMAC-DRBG nonce derivation. RFC 6979 binds the nonce to both the private key and the message, so an external observer who knows the message still cannot predict `k`.

- Internal cryptographic libraries that wrap industry-standard primitives must be audited with the same rigour as the application layer. A misleading comment describing an unsafe shortcut as a "safety measure" is a realistic mistake that can persist undetected through normal code review.


# Solution

## Checkout the developer branch

```bash
git checkout -b developer
```

## Patch the signing module

Edit `darkauth/signer.py`. Replace the `sign` function body to use `sign_deterministic`:

```python
def sign(payload: str) -> str:
    # RFC 6979: k = HMAC-DRBG(private_key, message) -- nonce is not recoverable
    # from the message alone, closing the single-signature key recovery path.
    signature = _SIGNING_KEY.sign_deterministic(
        payload.encode(),
        hashfunc=hashlib.sha256,
        sigencode=sigencode_string,
    )
    return signature.hex()
```

The `_derive_nonce` helper can be removed entirely.

## Commit and push

```bash
git add darkauth/signer.py
git commit -m "fix: replace predictable ECDSA nonce with RFC 6979 deterministic derivation"
git push -u origin developer
```

## Collect the flag

Open a pull request at `http://[IP]:[PORT]/pulls`. The automated validator will run the soft score (AI auditor) and hard score (exploit-path test) pipelines. On full acceptance, retrieve the flag:

```bash
curl -s http://[IP]:[PORT]/flag | jq
```
