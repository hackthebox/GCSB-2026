![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Global Cyber Skills Benchmark 2026: Project Nightfall - Privilege Chain</font>

3<sup>rd</sup> May 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: **Hard**

# Synopsis

Stolen trust does not stop at login. It walks the org chart of machines, stepping from one identity to the next until someone with real power signs the change. Under election pressure, that path can end in altered software the world believes is safe. You now have to follow how supplier access became operator motion and how that motion touched the build path the public never sees.

## Description

Task Force Nightfall is reconstructing a state-grade maneuver aimed at the logistics and delivery fabric behind the vote. The trail is not a single broken password. It is a sequence of handoffs, escalations, and releases that only make sense when you read them in order. You now have to tie together administrative motion and supply-side artifacts until the story holds in court, not just in a dashboard.

## Skills Required

- Cloud Audit Log navigation (Admin Activity log type)
- GCP IAM trust chain analysis and service account impersonation concepts
- Artifact Registry image forensics and OCI manifest inspection

## Skills Learned

- Tracing a multi-hop GCP service account impersonation chain in audit logs
- Distinguishing authenticated-as from impersonated-as using `serviceAccountDelegationInfo`
- Identifying a malicious IAM policy binding among mixed legitimate and malicious administration activity
- Performing OCI image config forensics to expose embedded IOC environment variables

# Enumeration

Players are provided with the following artifacts captured during the incident:

* **admin_activity_logs.csv**: Cloud Audit Logs Admin Activity including IAM and impersonation-related calls.
* **iam_exports.json**: IAM bindings on service accounts and project-level policy snapshots.
* **artifact_registry_inventory.json**: Artifact Registry package metadata and image push times.
* **docker/**: Saved Docker image tar archives only

Start from impersonation and project policy changes in `admin_activity_logs.csv`, then correlate new image timestamps in `artifact_registry_inventory.json`, then inspect the suspicious tar under `docker/`.

# Solution

### [1/15] What `client_email` does the leaked service account key authenticate as?

Open `admin_activity_logs.csv` and filter for `protoPayload.methodName` equal to `GenerateAccessToken`. The first hop shows `buildops-ci-runner` minting a token for `supply-pipeline-sa`. The authenticated principal on that row is the identity the stolen key represents.

```json
{
  "methodName": "GenerateAccessToken",
  "authenticationInfo": {
    "principalEmail": "buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com"
  },
  "request": {
    "name": "projects/-/serviceAccounts/supply-pipeline-sa@helical-cursor-494913-k9.iam.gserviceaccount.com"
  },
  "requestMetadata": { "callerIp": "33.252.46.44", "callerSuppliedUserAgent": "python-requests/2.32.3" },
  "timestamp": "2026-05-03T13:36:05Z"
}
```

* Answer: `buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com`

---

### [2/15] At what UTC timestamp did the first impersonation hop occur (buildops-ci-runner minting a token for supply-pipeline-sa)? Answer in format `YYYY-MM-DDTHH:MM:SSZ`.

Read the `timestamp` field on the `GenerateAccessToken` row where `protoPayload.authenticationInfo.principalEmail` is `buildops-ci-runner` and `protoPayload.request.name` targets `supply-pipeline-sa`.

* Answer: `2026-05-03T13:36:05Z`

---

### [3/15] At what UTC timestamp did the second impersonation hop occur (supply-pipeline-sa minting a token for elections-deployer)? Answer in format `YYYY-MM-DDTHH:MM:SSZ`.

In `admin_activity_logs.csv`, filter `GenerateAccessToken` where `protoPayload.authenticationInfo.principalEmail` is `supply-pipeline-sa` and `protoPayload.request.name` targets `elections-deployer`.

* Answer: `2026-05-03T13:36:12Z`

---

### [4/15] What OAuth scope did the attacker request in the second GenerateAccessToken hop?

Read `protoPayload.request.scope` on the `supply-pipeline-sa` to `elections-deployer` `GenerateAccessToken` row. This scope grants full cloud-platform API access, enabling the subsequent `SetIamPolicy` call.

* Answer: `https://www.googleapis.com/auth/cloud-platform`

---

### [5/15] What is the malicious project IAM binding in canonical `member:role` format?

In `admin_activity_logs.csv`, filter for `protoPayload.methodName` equal to `SetIamPolicy` where `protoPayload.resourceName` is `projects/helical-cursor-494913-k9`. One entry shows `elections-deployer` as `principalEmail` with `serviceAccountDelegationInfo` listing both `supply-pipeline-sa` and `buildops-ci-runner`:

```json
{
  "timestamp": "2026-05-03T13:36:16Z",
  "methodName": "SetIamPolicy",
  "authenticationInfo": {
    "principalEmail": "elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com",
    "serviceAccountDelegationInfo": [
      { "firstPartyPrincipal": { "principalEmail": "supply-pipeline-sa@helical-cursor-494913-k9.iam.gserviceaccount.com" } },
      { "firstPartyPrincipal": { "principalEmail": "buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com" } }
    ]
  },
  "request": {
    "policy": {
      "bindings": [
        {
          "members": ["serviceAccount:elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com"],
          "role": "roles/iam.securityAdmin"
        }
      ]
    },
    "resource": "helical-cursor-494913-k9"
  },
  "requestMetadata": { "callerIp": "33.252.46.44", "callerSuppliedUserAgent": "python-requests/2.32.3" }
}
```

The `serviceAccountDelegationInfo` column proves the full three-hop chain in a single row.

* Answer: `serviceAccount:elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com:roles/iam.securityAdmin`

---

### [6/15] At what UTC timestamp was privilege escalation achieved on the project? Answer in format `YYYY-MM-DDTHH:MM:SSZ`.

Use the `SetIamPolicy` row from the previous question. Open `iam_exports.json` afterward. In the final snapshot, `elections-deployer` holds `roles/storage.admin` on the project but does NOT hold `roles/iam.securityAdmin`, which proves the malicious binding was transient and cleaned up.

* Answer: `2026-05-03T13:36:16Z`

---

### [7/15] What is the key ID of the service account key created for `buildops-ci-runner`, visible in the `CreateServiceAccountKey` response?

In `admin_activity_logs.csv`, filter for `protoPayload.methodName` equal to `google.iam.admin.v1.CreateServiceAccountKey`. Read `protoPayload.response.name`. The key ID is the final path segment after `/keys/`.

* Answer: `a3f91c8e2d004b7f9012c0ffee4242ab0b1eca7d`

---

### [8/15] What is the name of the Artifact Registry repository where the malicious image was pushed?

Open `artifact_registry_inventory.json`. The `metadata.name` field on any entry contains the full resource path. The repository name is the segment after `/repositories/`.

* Answer: `elections-supply-registry`

---

### [9/15] Which supply image name received a new push during the attack window?

Group rows in `artifact_registry_inventory.json` by the image name (the final segment of the `package` field) and compare `createTime` values:

| Image | Baseline `createTime` | Attack-window entry |
|---|---|---|
| `ballot-api` | `2026-05-02T14:47:04Z` | none |
| `results-ingestor` | `2026-05-02T14:47:16Z` | none |
| `ops-diagnostics` | `2026-05-02T14:47:23Z` | `2026-05-03T13:37:01Z` (tag `v0.9.7`) |

* Answer: `ops-diagnostics`

---

### [10/15] What tag was applied to the malicious image push?

Read the `tags` array on the `ops-diagnostics` entry whose `createTime` falls inside the attack window.

* Answer: `v0.9.7`

---

### [11/15] At what UTC timestamp was the malicious image index manifest created in Artifact Registry? Answer in format `YYYY-MM-DDTHH:MM:SSZ`.

Read `createTime` on the `ops-diagnostics` entry with `tags: ["v0.9.7"]` and `mediaType` of `application/vnd.oci.image.index.v1+json`.

* Answer: `2026-05-03T13:37:01Z`

---

### [12/15] What is the full index digest (sha256) of the malicious `ops-diagnostics` `v0.9.7` manifest?

Read the `version` field on the same index manifest entry identified above.

* Answer: `sha256:54a2f31d64746d77e0ff0e9587ffea4f91f48d496f5651717c74f9b867743eee`

---

### [13/15] What is the `imageSizeBytes` value of the malicious layer entry pushed during the attack window?

The attack-window layer entry for `ops-diagnostics` has `mediaType` of `application/vnd.oci.image.manifest.v1+json` and `createTime` of `2026-05-03T13:36:56.142705Z`. Read its `metadata.imageSizeBytes`.

* Answer: `89234512`

---

### [14/15] What IOC environment variable **name** appears in the malicious image `config.Env` inside the Docker tar?

Open `docker/ops_diagnostics_v0_9_7.tar` as an archive. Inside that tar, read the member named `manifest.json`, then read the config blob named in `manifest[0]["Config"]` (a path such as `blobs/sha256/<digest>`). In that JSON, `config.Env` includes callback-style variables not present in the benign tars:

```bash
TAR=ops_diagnostics_v0_9_7.tar
CFG=$(tar -xOf "$TAR" manifest.json | jq -r '.[0].Config')
tar -xOf "$TAR" "$CFG" | jq -r '.config.Env[] | select(test("^CALLBACK_HOST="))'
```

That prints `CALLBACK_HOST=185.220.101.47`.

* Answer: `CALLBACK_HOST`

---

### [15/15] What value does the IOC callback variable hold in the malicious image config?

This value can be found using the process described in Q14: after extracting the image config file from the Docker tar, inspect the `config.Env` array for the entry starting with `CALLBACK_HOST=`, and use the value after the equals sign as the answer.

* Answer: `185.220.101.47`
