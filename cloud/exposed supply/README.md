![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Global Cyber Skills Benchmark 2026: Project Nightfall - Exposed Supply</font>

3<sup>rd</sup> May 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: **Easy**

# Synopsis

Election week is already a pressure cooker. While proxy groups flood the headlines with noise, someone moves against the trusted logistics path that feeds the vote. A supplier-facing estate that should have stayed internal is standing too close to the public internet. Your cell must treat the leak like the opening move it is, before Gilded Weaver turns a logistics embarrassment into lasting access.

## Description

Task Force Nightfall is racing the clock. Reports say election logistics partners are bleeding operational detail into places civilians can reach. You are joining the forensics line, working from captured site and cloud evidence to show how a rushed supplier footprint became a gift to an adversary that thrives on dependency.

## Skills Required

- Cloud Storage audit log navigation (Data Access log type)
- Base64 decoding and JavaScript static analysis
- Unzipping and inspecting supplier archive layouts

## Skills Learned

- Correlating public bucket exposure to recoverable credential material
- Extracting configuration strings from an obfuscated front-end bundle
- Locating exported service account keys inside a supply-chain archive

# Enumeration

Players are provided with the following artifacts captured during the incident:

* **storage_data_access_logs.csv**: Cloud Storage Data Access and bucket metadata events for the project during the incident window.
* **main.min.js**: Minified supplier site JavaScript from the captured static footprint.
* **supply-bundle.zip**: Supplier pipeline export archive distributed through the logistics path.

The entry point is the storage export to prove which bucket was opened to the world, then the bundle and zip to recover identity material the adversary can authenticate with.

# Solution

### [1/8] What is the name of the exposed public Cloud Storage bucket?

Open `storage_data_access_logs.csv`. Filter rows where `protoPayload.methodName` is `storage.buckets.update`. One entry shows `admin@nightfall.net` updating `projects/_/buckets/mec-elections-logistics-pub`:

```
protoPayload.methodName       storage.buckets.update
protoPayload.authenticationInfo.principalEmail  admin@nightfall.net
protoPayload.requestMetadata.requestAttributes.time  2026-05-03T06:59:21Z
protoPayload.resourceName     projects/_/buckets/mec-elections-logistics-pub
```

The bucket name is the final segment of `protoPayload.resourceName`.

* Answer: `mec-elections-logistics-pub`

---

### [2/8] At what UTC timestamp was the bucket made publicly accessible? Answer in format `YYYY-MM-DDTHH:MM:SSZ`.

Read `protoPayload.requestMetadata.requestAttributes.time` on the `storage.buckets.update` row identified above.

* Answer: `2026-05-03T06:59:21Z`

---

### [3/8] What is the email address of the principal who changed the bucket permissions?

Read `protoPayload.authenticationInfo.principalEmail` on the same row.

* Answer: `admin@nightfall.net`

---

### [4/8] What is the caller IP address on the bucket-update event?

Read `protoPayload.requestMetadata.callerIp` on the `storage.buckets.update` row.

* Answer: `88.65.198.198`

---

### [5/8] What file was uploaded to the bucket in the same event window as the permission change?

In `storage_data_access_logs.csv`, filter for `protoPayload.methodName` equal to `storage.objects.create` on the logistics bucket near the same timestamp. The `protoPayload.resourceName` field identifies the object.

```
protoPayload.methodName       storage.objects.create
protoPayload.resourceName     projects/_/buckets/mec-elections-logistics-pub/objects/supply-bundle.zip
protoPayload.requestMetadata.requestAttributes.time  2026-05-03T06:59:21Z
```

* Answer: `supply-bundle.zip`

---

### [6/8] What is the email domain of the `client_email` encoded in the JavaScript bundle?

Open `main.min.js` and Base64-decode the strings. The longer decode is the `client_email`. Submit the domain portion after `@`.

```python
import base64

for e in (
    "bWVjLWVsZWN0aW9ucy1sb2dpc3RpY3MtcHVi",
    "YnVpbGRvcHMtY2ktcnVubmVyQGhlbGljYWwtY3Vyc29yLTQ5NDkxMy1rOS5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbQ==",
):
    print(base64.b64decode(e).decode())
```

You can also read `client_email` from `pipeline-export/github-actions/buildops-ci-runner-svcacct.json` inside `supply-bundle.zip`, then submit only its email domain.

* Answer: `helical-cursor-494913-k9.iam.gserviceaccount.com`

---

### [7/8] What is the path inside `supply-bundle.zip` that contains the exported service account key JSON?

Unzip `supply-bundle.zip`. The archive contains:

```
vendor-export-manifest.json
pipeline-export/github-actions/buildops-ci-runner-svcacct.json
```

Open `pipeline-export/github-actions/buildops-ci-runner-svcacct.json`:

```json
{
  "type": "service_account",
  "project_id": "helical-cursor-494913-k9",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "client_email": "buildops-ci-runner@helical-cursor-494913-k9.iam.gserviceaccount.com",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

This is a long-lived GCP service account key. The `private_key` field allows the holder to authenticate as `buildops-ci-runner` using the OAuth2 JWT grant flow. Submit the path relative to the zip root.

* Answer: `pipeline-export/github-actions/buildops-ci-runner-svcacct.json`

---

### [8/8] What is the GCP project ID found in the leaked service account key file?

Read the `project_id` field from the key JSON. The bundle strings in `main.min.js` decode to the same value.

* Answer: `helical-cursor-494913-k9`
