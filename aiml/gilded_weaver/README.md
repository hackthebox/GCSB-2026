![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Gilded Weaver</font>

1<sup>th</sup> May 2026

Prepared By: `karamuz`

Challenge Author(s): `karamuz`

Difficulty: <font color='orange'>Medium</font>

<br><br>

# Synopsis

Recover encrypted key material hidden inside a federated learning gradient aggregate. The server's weight matrix has unusual spectral structure — its singular values form tight clusters separated by large gaps. This structure partitions the hidden space into orthogonal subspaces, one per client. Projecting the aggregate gradient onto the correct subspace reveals quantized byte values that serve as AES key material.

## Description

Task Force Nightfall intercepted a training round from Directorate 9's covert federated learning network. We captured the server model and the aggregated gradient from all participating clients. One client's contribution contains embedded cryptographic material but it's mixed in with 7 other clients' updates in the aggregate. Find a way to recover the payload.

## Skills Required

- Linear algebra (SVD, orthogonal projections)
- NumPy / scientific Python
- Understanding federated learning basics (model updates, aggregation)
- Basic cryptography (AES-GCM, HKDF)

## Skills Learned

- Spectral analysis of weight matrices to detect hidden structure
- Using SVD to decompose a matrix into orthogonal subspaces
- Federated learning attacks (server-crafted subspace isolation)
- SVD sign ambiguity resolution
- Key material extraction from continuous-valued projections

---

# Writeup

## Step 0: Inventory — What Do We Have?

We start by examining the release files and the manifest:

```
release/
├── encrypted_payload.bin   (45 bytes)
├── gradient_aggregate.npz
├── manifest.json
└── server_model.npz
```

The manifest tells us:

```json
{
  "challenge": "Gilded Weaver",
  "scenario": "Intercepted server model and aggregated gradient update from a federated learning round with 8 participants.",
  "crypto": {
    "scheme": "AES-256-GCM",
    "kdf": "HKDF-SHA256",
    "kdf_info": "gilded-weaver",
    "aad": "gilded-weaver",
    "key_material_bytes": 32
  }
}
```

**What we learn:**
- There are **8 participants** in a federated learning round
- The flag is encrypted with **AES-256-GCM**
- We need **32 bytes of key material** to derive the decryption key
- The KDF is **HKDF-SHA256** with info string `"gilded-weaver"`
- The AAD (additional authenticated data) is also `"gilded-weaver"`

So our goal is clear: **find 32 bytes of key material somewhere in these numpy arrays.**

## Step 1: Exploring the Data

```python
import numpy as np

model = np.load('release/server_model.npz')
gradient = np.load('release/gradient_aggregate.npz')

print(list(model.keys()))       # ['layer_0', 'layer_1']
print(list(gradient.keys()))    # ['grad_layer_0', 'grad_layer_1']
```

```
server_model.npz:
  layer_0: shape=(256, 512), dtype=float64
  layer_1: shape=(32, 256),  dtype=float64

gradient_aggregate.npz:
  grad_layer_0: shape=(256, 512), dtype=float64
  grad_layer_1: shape=(32, 256),  dtype=float64
```

We have a 2-layer model and the corresponding gradient aggregate. Layer 0 is the big one (256×512 = 131,072 parameters). Layer 1 is small (32×256).

**Key question:** Where would 32 bytes of key material hide in 131,072+ floating point numbers?

## Step 2: Looking for Structure — SVD Analysis

In linear algebra, **Singular Value Decomposition (SVD)** breaks any matrix into `U @ diag(S) @ Vt`. The singular values `S` reveal the matrix's internal structure. A "random" matrix has smoothly decaying singular values, while a *structured* matrix has patterns in its spectrum.

Let's check all four matrices:

```python
_, S_w0, _ = np.linalg.svd(model['layer_0'], full_matrices=False)
_, S_w1, _ = np.linalg.svd(model['layer_1'], full_matrices=False)
_, S_g0, _ = np.linalg.svd(gradient['grad_layer_0'], full_matrices=False)
_, S_g1, _ = np.linalg.svd(gradient['grad_layer_1'], full_matrices=False)
```

```
W0 SVs: condition=7.15,  range=[4.2000, 0.5876]
W1 SVs: condition=1.89,  range=[2.0662, 1.0955]
G0 SVs: condition=7.71,  range=[14.4545, 1.8739]
G1 SVs: condition=1.96,  range=[1.0497, 0.5352]
```

**Observation:** W1 and G1 have condition numbers close to 1-2, meaning they're essentially random matrices (no special structure). G0 has a moderate condition number but smooth decay. But **W0** has a condition number of 7.15, which isn't extreme — let's look at its singular values more closely.

## Step 3: The Spectral Fingerprint

```python
U, S, Vt = np.linalg.svd(model['layer_0'], full_matrices=False)
# S has 256 values. Let's look at the first 40:
```

```
S[  0] = 4.200000
S[  1] = 4.199600
S[  2] = 4.199200
...
S[ 31] = 4.187600
S[ 32] = 3.700000  ← GAP 0.4876
S[ 33] = 3.699600
S[ 34] = 3.699200
...
```

**This is extraordinary.** The singular values aren't smoothly decaying — they form **tight clusters** with **massive gaps** between them. Within each cluster, values decrease by exactly 0.0004 (tiny steps), but between clusters there are jumps of 0.39–0.59.

Let's find all the gaps:

```
Found 7 large gaps (>0.1):
  Between S[31]  and S[32]:  gap = 0.4876
  Between S[63]  and S[64]:  gap = 0.5876
  Between S[95]  and S[96]:  gap = 0.4876
  Between S[127] and S[128]: gap = 0.5876
  Between S[159] and S[160]: gap = 0.4876
  Between S[191] and S[192]: gap = 0.3876
  Between S[223] and S[224]: gap = 0.4876
```

This gives us **8 groups of exactly 32 singular values each:**

```
Group 0: indices [0:32],    SVs ≈ [4.2000 .. 4.1876]
Group 1: indices [32:64],   SVs ≈ [3.7000 .. 3.6876]
Group 2: indices [64:96],   SVs ≈ [3.1000 .. 3.0876]
Group 3: indices [96:128],  SVs ≈ [2.6000 .. 2.5876]
Group 4: indices [128:160], SVs ≈ [2.0000 .. 1.9876]
Group 5: indices [160:192], SVs ≈ [1.5000 .. 1.4876]
Group 6: indices [192:224], SVs ≈ [1.1000 .. 1.0876]
Group 7: indices [224:256], SVs ≈ [0.6000 .. 0.5876]
```

**The insight:** 8 groups, 8 participants. The manifest told us there are 8 clients. This can't be a coincidence. Each group of 32 singular values corresponds to one client's **subspace** — a 32-dimensional slice of the 256-dimensional hidden space that belongs exclusively to that client.

## Step 4: Understanding the Attack (Subspace Isolation)

This is a variant of the **LOKI attack** from federated learning security research. The idea:

1. **The server crafts W0** so that its left singular vectors (columns of U) are partitioned into 8 orthogonal groups of 32
2. Each group spans a **private subspace** for one client
3. When clients compute gradients, their updates live primarily in their assigned subspace
4. The **aggregate** (sum of all clients' gradients) mixes everything together — but because the subspaces are orthogonal, we can **project** the aggregate onto any one subspace to isolate that client's contribution

In mathematical terms:
- `U[:, 0:32]` spans Client 0's subspace
- `U[:, 32:64]` spans Client 1's subspace
- ... and so on

Because these column groups are **orthogonal** (they come from SVD), projecting the aggregate gradient onto one group filters out all other clients perfectly.

## Step 5: Why the Gradient Alone Doesn't Work

A natural question: can we just SVD the gradient directly?

```python
_, S_g, _ = np.linalg.svd(gradient['grad_layer_0'], full_matrices=False)
# S_g[0] = 14.4545, S_g[1] = 14.2783, ... S_g[-1] = 1.8739
# Condition number: 7.71
```

The gradient's singular values decay smoothly — **no grouping structure**. This makes sense: the aggregate is a sum of 8 clients' updates, which mixes their subspace contributions. The structure only exists in W0 (the server's crafted weight matrix). You **need W0's SVD** to know how to project.

Similarly, W1 and G1 have no useful structure:
```
W1: condition=1.89, max gap between consecutive SVs: 0.0591
→ No spectral structure. Layer 1 is filler.
```

## Step 6: The Sign Convention Problem

SVD has a well-known ambiguity: for each singular value, the corresponding column of U and row of Vt can both be negated without changing the decomposition (since `(-u) * s * (-v^T) = u * s * v^T`). Different numpy versions, platforms, or even runs can produce different sign choices.

This matters because if we flip the sign of a column in U, any projection using that column will also be negated. If key material was embedded as positive values (bytes 0-255 mapped to 0.00-2.55), a sign flip would produce negative values and destroy the decode.

**The fix:** Apply a deterministic sign convention. A common approach: for each column of U, find the first entry with magnitude above a threshold, and flip the column so that entry is positive.

```python
SIGN_THRESHOLD = 0.01
for col in range(U.shape[1]):
    for row in range(U.shape[0]):
        if abs(U[row, col]) > SIGN_THRESHOLD:
            if U[row, col] < 0:
                U[:, col] *= -1
                Vt[col, :] *= -1
            break
```

Before sign convention, 135 out of 256 columns needed flipping. After applying it, all columns have their first significant entry positive, giving a **deterministic, reproducible basis**.

Why this specific convention? The challenge builder used the same rule when embedding the key. Any deterministic convention that both builder and solver agree on would work — "first significant entry is positive" is the most natural one.

## Step 7: Projecting Onto Client Subspaces

Now we project the aggregate gradient onto each client's subspace:

```python
C = 32  # channels per client
for client in range(8):
    U_client = U[:, client*C : (client+1)*C]  # shape (256, 32)
    M = U_client.T @ G0                        # shape (32, 512)
    # M[ch, :] = the projection of G0 onto channel 'ch' of this client
```

Each resulting `M` matrix is 32×512: it has 32 "channels" (one per singular vector in this client's group), each containing a 512-dimensional signal.

We need to find which client and which channel contains the 32 bytes of key material.

## Step 8: Finding the Key — Byte Pattern Detection

Key material is 32 random bytes, each scaled by 0.01, giving values in [0.00, 2.55]. These will be in the first 32 entries of some channel of some client. We scan all clients and channels looking for this distinctive pattern:

```python
for client in range(8):
    U_client = U[:, client*C:(client+1)*C]
    M = U_client.T @ G0
    for ch in range(C):
        vals = M[ch, :32]
        # Check: are these exact multiples of 0.01?
        residuals = abs(vals * 100 - round(vals * 100))
        mean_residual = mean(residuals)
        all_positive = all(vals >= 0)
```

Results:

```
Client    Best Ch    Mean Residual    All Positive    Mean Value
─────────────────────────────────────────────────────────────────
  0         3          0.2034          False           0.0008
  1         5          0.1925          False           0.0723
  2         0          0.1987          False           0.0054
  3         0          0.0000          True            1.0991   ← KEY
  4         5          0.1948          False          -0.0291
  5         7          0.1945          False           0.0279
  6        28          0.1748          False          -0.0333
  7         8          0.1673          False          -0.0648
```

**Client 3, Channel 0** is unmistakable:
- **Mean residual = 0.0000** — values are *exactly* integer multiples of 0.01 (other clients have residuals ~0.2, consistent with random noise)
- **All positive = True** — bytes are always 0-255, so scaled values must be non-negative (other clients have negative values)
- **Mean value ≈ 1.10** — consistent with random bytes having mean ~127.5 → 1.275 after scaling

The other clients' projections are just noise centered around zero with random signs. Client 3's channel 0 contains a deliberate, structured signal.

## Step 9: Extracting the Key Material

```python
# Client 3, channel 0, first 32 entries
U_client3 = U[:, 96:128]
M = U_client3.T @ G0
raw_key = M[0, :32]
```

```
Raw values:
  [1.03, 2.16, 0.07, 0.93, 1.87, 2.46, 2.02, 1.27, 1.55, 0.54,
   0.29, 0.20, 2.37, 1.52, 1.28, 1.87, 1.82, 0.19, 1.07, 0.85,
   0.24, 0.77, 0.72, 1.09, 0.29, 2.49, 0.69, 0.56, 0.71, 0.25,
   1.41, 0.59]
```

Multiply by 100 and round to recover the original bytes:

```python
key_bytes = bytes(np.round(raw_key * 100).astype(int).tolist())
```

```
Byte values: [103, 216, 7, 93, 187, 246, 202, 127, 155, 54, 29, 20,
              237, 152, 128, 187, 182, 19, 107, 85, 24, 77, 72, 109,
              29, 249, 69, 56, 71, 25, 141, 59]

Key hex: 67d8075dbbf6ca7f9b361d14ed9880bbb6136b55184d486d1df9453847198d3b
```

All values are in [0, 255] ✓. We have our 32 bytes of key material.

## Step 10: Deriving the AES Key and Decrypting

The manifest specifies HKDF-SHA256 with info `"gilded-weaver"` producing 44 bytes (32 for AES key + 12 for nonce):

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

derived = HKDF(
    algorithm=SHA256(),
    length=44,
    salt=None,
    info=b"gilded-weaver"
).derive(key_bytes)

aes_key = derived[:32]   # 145b6065377353537635cca707a7c2af...
nonce = derived[32:44]   # f63e4ae9b8686d015b4a7bd2

payload = open('release/encrypted_payload.bin', 'rb').read()
aesgcm = AESGCM(aes_key)
plaintext = aesgcm.decrypt(nonce, payload, b"gilded-weaver")
```