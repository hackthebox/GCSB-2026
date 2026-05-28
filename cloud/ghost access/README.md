![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Global Cyber Skills Benchmark 2026: Project Nightfall - Ghost Access</font>

3<sup>rd</sup> May 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: **Medium**

# Synopsis

The adversary did not only strike. They also swept the floor. Loud deletes and policy churn can look like victory until you ask what still whispers in the dark. Somewhere in the estate, a quiet grant survived the broom, the kind of trust reviewers only notice when they know which ledger to read. Your job here is to prove what they kept and what they hoped you would stop looking for.

## Description

Task Force Nightfall is closing the loop after a bruising cloud incident tied to the election logistics chain. The obvious damage is documented. The question is what remains when the noise fades. Given the forensics artifacts, you are now tasked with hunting persistence that outlasts headline cleanup and correlating it with the destruction the operator wanted to look routine.

## Skills Required

- Cloud Audit Log navigation (Admin Activity log type)
- Cloud Storage audit log navigation (Data Access log type)
- GCP IAM analysis at project versus service account resource scope
- Secret Manager log interpretation

## Skills Learned

- Identifying a malicious IAM policy binding hidden on a service account resource instead of the project
- Mapping cleanup and persistence patterns in Cloud Audit Logs after privilege escalation
- Correlating `storage.objects.delete` and `DestroySecretVersion` to the same operator session

# Enumeration

Players are provided with the following artifacts captured during the incident:

* **iam_exports.json**: IAM snapshots including per-service-account resource policies and project-level bindings.
* **admin_activity_logs.csv**: Cloud Audit Logs Admin Activity for the project during the incident window.
* **storage_data_access_logs.csv**: Cloud Storage Data Access events for object and bucket activity during cleanup.

Use `iam_exports.json` to separate project IAM from service-account resource IAM. Use `admin_activity_logs.csv` for Secret Manager admin events and IAM policy writes. Use `storage_data_access_logs.csv` for destructive object operations.

# Solution

### [1/10] Which IAM member binding survived the attacker cleanup?

Open `iam_exports.json`. Under `service_accounts`, check the entry for `elections-ghost-sa@helical-cursor-494913-k9.iam.gserviceaccount.com`. The project IAM snapshot has no binding for `gilded@d9.kor`. The service account resource policy contains:

```json
{
  "bindings": [
    {
      "members": ["user:gilded@d9.kor"],
      "role": "roles/iam.serviceAccountTokenCreator"
    }
  ]
}
```

This binding was applied via `google.iam.admin.v1.SetIAMPolicy` on the service account resource, not through `resourcemanager.projects.setIamPolicy`, making it invisible in project-level IAM reviews and surviving the cleanup phase.

* Answer: `user:gilded@d9.kor`

---

### [2/10] On which service account email does the surviving backdoor sit?

Open `admin_activity_logs.csv` and filter for `protoPayload.methodName` equal to `google.iam.admin.v1.SetIAMPolicy` where `protoPayload.resourceName` contains `elections-ghost-sa`. The row at `2026-05-03T13:44:54Z` shows `elections-deployer` (with the full delegation chain in `serviceAccountDelegationInfo`) setting this binding:

```json
{
  "timestamp": "2026-05-03T13:44:54Z",
  "methodName": "google.iam.admin.v1.SetIAMPolicy",
  "authenticationInfo": {
    "principalEmail": "elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com",
    "serviceAccountDelegationInfo": [
      { "firstPartyPrincipal": { "principalEmail": "supply-pipeline-sa@helical-cursor-494913-k9.iam.gserviceaccount.com" } },
      { "firstPartyPrincipal": { "principalEmail": "buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com" } }
    ]
  },
  "request": {
    "resource": "projects/helical-cursor-494913-k9/serviceAccounts/elections-ghost-sa@helical-cursor-494913-k9.iam.gserviceaccount.com",
    "policy": {
      "bindings": [{ "members": ["user:gilded@d9.kor"], "role": "roles/iam.serviceAccountTokenCreator" }]
    }
  },
  "requestMetadata": { "callerIp": "33.252.46.44", "callerSuppliedUserAgent": "python-requests/2.32.3" }
}
```

* Answer: `elections-ghost-sa@helical-cursor-494913-k9.iam.gserviceaccount.com`

---

### [3/10] Which IAM role was granted in the surviving binding?

Read the `role` field from the binding shown in the previous step.

* Answer: `roles/iam.serviceAccountTokenCreator`

---

### [4/10] At what UTC timestamp was the backdoor policy written? Answer in format `YYYY-MM-DDTHH:MM:SSZ`.

Use the `google.iam.admin.v1.SetIAMPolicy` row on the ghost service account from `admin_activity_logs.csv`.

* Answer: `2026-05-03T13:44:54Z`

---

### [5/10] What is the caller IP address on the attacker-linked operations?

These exports contains unrelated traffic with other caller IPs. Restrict to rows where the principal is `elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com` or where the method is one of the cleanup or backdoor operations above. On that slice, `protoPayload.requestMetadata.callerIp` is consistent.

* Answer: `33.252.46.44`

---

### [6/10] Which project-level IAM role held by `supply-pipeline-sa` made the privilege escalation chain possible?

Open `iam_exports.json` and look at the `project.bindings` array. Find the entry where `members` contains `serviceAccount:supply-pipeline-sa@helical-cursor-494913-k9.iam.gserviceaccount.com`. This role allowed `supply-pipeline-sa` to call `projects.setIamPolicy` on behalf of the attacker.

* Answer: `roles/resourcemanager.projectIamAdmin`

---

### [7/10] At what UTC timestamp was the malicious project-level `securityAdmin` binding removed during cleanup? Answer in format `YYYY-MM-DDTHH:MM:SSZ`.

In `admin_activity_logs.csv`, filter for `protoPayload.methodName` equal to `SetIamPolicy` where `protoPayload.serviceData` contains `REMOVE` and `roles/iam.securityAdmin`. This cleanup event follows the ghost backdoor write and precedes the storage delete.

* Answer: `2026-05-03T13:45:13Z`

---

### [8/10] Which Cloud Storage object was deleted during cleanup? Answer as a `gs://` URI.

Open `storage_data_access_logs.csv` and filter for `protoPayload.methodName` equal to `storage.objects.delete`:

```json
{
  "timestamp": "2026-05-03T13:45:19Z",
  "methodName": "storage.objects.delete",
  "authenticationInfo": {
    "principalEmail": "elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com"
  },
  "resourceName": "projects/_/buckets/mec-elections-logistics-pub/objects/config/app.config.json",
  "requestMetadata": { "callerIp": "33.252.46.44", "callerSuppliedUserAgent": "python-requests/2.32.3" }
}
```

Map `resourceName` to `gs://bucket/object`.

* Answer: `gs://mec-elections-logistics-pub/config/app.config.json`

---

### [9/10] What is the name of the secret from which a version was destroyed during cleanup?

In `admin_activity_logs.csv`, filter for `protoPayload.methodName` equal to `google.cloud.secretmanager.v1.SecretManagerService.DestroySecretVersion`. Read the secret name segment from `protoPayload.resourceName` (the part between `/secrets/` and `/versions/`).

* Answer: `election-db-credentials`

---

### [10/10] Which Secret Manager secret version resource was destroyed during cleanup? Answer as the full resource name.

Continue with the same `DestroySecretVersion` row from `admin_activity_logs.csv`:

```json
{
  "timestamp": "2026-05-03T13:45:25Z",
  "methodName": "google.cloud.secretmanager.v1.SecretManagerService.DestroySecretVersion",
  "authenticationInfo": {
    "principalEmail": "elections-deployer@helical-cursor-494913-k9.iam.gserviceaccount.com"
  },
  "resourceName": "projects/helical-cursor-494913-k9/secrets/election-db-credentials/versions/3",
  "requestMetadata": { "callerIp": "33.252.46.44", "callerSuppliedUserAgent": "python-requests/2.32.3" }
}
```

* Answer: `projects/helical-cursor-494913-k9/secrets/election-db-credentials/versions/3`

---

Some platforms combine these answers into one string such as `HTB{member_sa-email_role_timestamp_gs-uri_secret-version}`. When that format is required, use the relevant answers above in order.
