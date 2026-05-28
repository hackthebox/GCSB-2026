![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Spectral Rift</font>

1<sup>th</sup> May 2026

Prepared By: `karamuz`

Challenge Author(s): `karamuz`

Difficulty: <font color='red'>Hard</font>

<br><br>

# Synopsis

Recover an encrypted payload hidden inside a merged neural network model by performing blind low-rank adapter separation. Three adapters with different ranks were merged via task arithmetic, but not all adapters are active in all layers. By profiling the spectral (SVD) structure of weight deltas, deducing the combinatorial activity pattern, and separating overlapping subspaces via alternating projections, the solver identifies the carrier adapter and extracts a cryptographic key encoded as D4 lattice pointsand then uses it to decrypt the flag.

## Description

Project RIFT, an adversarial AI lab, fine-tuned three specialized adapters and merged them into a single production model. One adapter carries an encrypted payload. The merged model and original base weights have been intercepted. Separate the adapters and recover the hidden payload.

## Skills Required

- Python programming and NumPy
- Linear algebra (SVD, rank, subspaces)
- Understanding of low-rank matrix factorization
- Iterative numerical optimization
- Basic cryptography (AES-GCM)

## Skills Learned

- SVD rank profiling for signal detection
- Blind source separation via rank-constrained decomposition
- Task arithmetic model merging (Ilharco et al., ICLR 2023)
- Alternating projections for subspace separation
- D4 lattice nearest-neighbor decoding
- Sign convention handling in SVD recovery

---

# Enumeration

### Threat model
This is a **static artifact analysis + numerical computation** challenge:
- No remote server — all data is in the release files
- The manifest tells us the merge formula, adapter ranks, and alphas
- The hard part is *separating* overlapping low-rank signals and figuring out the encoding scheme
- Requires implementing and running iterative numerical algorithms

---

# Solution

## Exploitation

### Step 1 — Initial Reconnaissance

Let's start by understanding what we're working with.

```python
import numpy as np
import json
from pathlib import Path

RELEASE = Path("release")
manifest = json.loads((RELEASE / "manifest.json").read_text())
print(json.dumps(manifest, indent=2))

base = np.load(RELEASE / "base_model.npz")
merged = np.load(RELEASE / "merged_model.npz")
encrypted = (RELEASE / "encrypted_payload.bin").read_bytes()

print(f"\nBase keys: {sorted(base.files)}")
print(f"layer_0 shape: {base['layer_0'].shape}, dtype: {base['layer_0'].dtype}")
print(f"encrypted_payload.bin: {len(encrypted)} bytes")
```

```
{
  "challenge": "Spectral Rift",
  "description": "Three low-rank adapters were merged into a single model. Separate them and recover the hidden payload.",
  "model": {
    "layers": 8,
    "dim": 256,
    "dtype": "float64"
  },
  "merge_info": {
    "method": "task_arithmetic",
    "formula": "merged = base + sum(alpha_i * B_i @ A_i)",
    "num_adapters": 3,
    "alphas": [0.7, 0.5, 0.9],
    "ranks": [3, 4, 5],
    "note": "Not all adapters are active in all layers. B_i columns are orthonormal."
  },
  "payload": {
    "encoding": "D4_lattice_quantization",
    "decryption": "AES-256-GCM",
    "kdf": "HKDF-SHA256",
    "aad": "spectral-rift"
  }
}

Base keys: ['layer_0', 'layer_1', 'layer_2', 'layer_3', 'layer_4', 'layer_5', 'layer_6', 'layer_7']
layer_0 shape: (256, 256), dtype: float64
encrypted_payload.bin: 43 bytes
```

Okay, so the core idea is clear from the manifest: three low-rank adapters were merged into a model via **task arithmetic**. The merge formula is:

$$\text{merged} = \text{base} + \sum_{i=0}^{2} \alpha_i \cdot B_i \cdot A_i$$

where each $B_i \in \mathbb{R}^{256 \times r_i}$ has orthonormal columns and $A_i \in \mathbb{R}^{r_i \times 256}$. This means each adapter's contribution $B_i A_i$ is a rank-$r_i$ matrix. The ranks are [3, 4, 5] and the scaling factors (alphas) are [0.7, 0.5, 0.9].

The key sentence is: *"Not all adapters are active in all layers."* This means in each layer, only a subset of the three adapters contributed. Our first job is to figure out which adapters are present in which layer.

The payload info tells us the encoding uses "D4 lattice quantization" and decryption is AES-256-GCM with HKDF-SHA256 for key derivation. The AAD is "spectral-rift". We'll come back to this once we find the encoded data.

The encrypted payload is 43 bytes. Since AES-GCM adds a 16-byte authentication tag, the plaintext is $43 - 16 = 27$ bytes — consistent with a flag like `HTB{...}` (~27 characters).

---

### Step 2 — Spectral Analysis: How Many Adapters Per Layer?

Since `delta = merged - base` gives us the sum of active adapter contributions, and each adapter contributes a rank-$r_i$ perturbation, the **rank of each delta** equals the sum of active adapter ranks.

This is because the $B_i$ matrices have orthonormal columns — if two adapters both contribute to a layer, their column spaces are generically in "general position" (no overlap), so the rank adds. Let's verify:

```python
deltas = [merged[f"layer_{i}"] - base[f"layer_{i}"] for i in range(8)]

for i, delta in enumerate(deltas):
    U, S, Vt = np.linalg.svd(delta, full_matrices=False)
    # The rank shows up as a sudden drop in singular values
    for r in range(1, 30):
        if S[r-1] / S[r] > 1000:
            print(f"Layer {i}: rank={r:2d}, SVs={np.round(S[:r], 4).tolist()}, "
                  f"gap={S[r-1]/S[r]:.0f}x")
            break
```

```
Layer 0: rank=12, SVs=[15.884, 15.312, 14.445, 13.796, 13.422, 11.595, 10.691, 10.299, 8.342, 7.791, 7.433, 7.042], gap=223709x
Layer 1: rank= 3, SVs=[12.05, 11.781, 11.065], gap=356863x
Layer 2: rank= 9, SVs=[15.47, 15.139, 14.105, 13.935, 11.833, 8.148, 7.735, 7.556, 7.118], gap=226835x
Layer 3: rank= 7, SVs=[12.085, 11.493, 11.091, 8.067, 7.971, 7.488, 7.134], gap=226038x
Layer 4: rank= 5, SVs=[4.5, 3.6, 2.7, 1.8, 0.9], gap=28598x
Layer 5: rank= 8, SVs=[16.453, 14.892, 14.45, 14.141, 13.342, 11.43, 10.753, 10.196], gap=325450x
Layer 6: rank= 4, SVs=[9.282, 8.406, 7.878, 7.252], gap=230914x
Layer 7: rank=12, SVs=[16.976, 15.595, 14.816, 14.234, 13.49, 11.167, 10.513, 9.789, 8.164, 7.672, 7.506, 6.89], gap=220707x
```

The spectral gaps are enormous (>28000x in every layer). The rank is completely unambiguous. Observed ranks: **[12, 3, 9, 7, 5, 8, 4, 12]**.

Now something immediately catches my eye about **layer 4**: its singular values are `[4.5, 3.6, 2.7, 1.8, 0.9]`. That's a perfect arithmetic sequence with common difference 0.9. Every other layer has "random-looking" SVs in the 7-16 range. Layer 4's values look intentionally designed. I'm going to keep this in mind as a likely flag carrier.

---

### Step 3 — Mapping Ranks to Adapter Subsets

With adapter ranks [3, 4, 5], let's enumerate all possible active subsets and their total rank:

| Active subset | Rank sum |
|---|---|
| {0} | 3 |
| {1} | 4 |
| {2} | 5 |
| {0,1} | 3+4 = 7 |
| {0,2} | 3+5 = 8 |
| {1,2} | 4+5 = 9 |
| {0,1,2} | 3+4+5 = 12 |

Every possible sum is **unique**! This means we can unambiguously determine which adapters are active in each layer just from the observed rank. No additional information needed — this is a lucky property of the rank choices [3, 4, 5].

```python
ranks = [3, 4, 5]
rank_to_subset = {}
for mask in range(1, 8):
    subset = frozenset(i for i in range(3) if mask & (1 << i))
    total = sum(ranks[i] for i in subset)
    rank_to_subset[total] = subset

observed = [12, 3, 9, 7, 5, 8, 4, 12]
for layer, r in enumerate(observed):
    act = sorted(rank_to_subset[r])
    print(f"Layer {layer}: rank={r:2d} → adapters {act}")
```

```
Layer 0: rank=12 → adapters [0, 1, 2]
Layer 1: rank= 3 → adapters [0]
Layer 2: rank= 9 → adapters [1, 2]
Layer 3: rank= 7 → adapters [0, 1]
Layer 4: rank= 5 → adapters [2]
Layer 5: rank= 8 → adapters [0, 2]
Layer 6: rank= 4 → adapters [1]
Layer 7: rank=12 → adapters [0, 1, 2]
```

Three layers contain exactly one adapter — these are "pure" layers:
- **Layer 1**: adapter 0 alone (rank 3)
- **Layer 4**: adapter 2 alone (rank 5) — the suspicious one!
- **Layer 6**: adapter 1 alone (rank 4)

This is excellent news. In a pure layer, the delta IS the adapter's contribution (scaled by alpha). We can extract it directly via SVD.

---

### Step 4 — Extracting the Flag-Carrier Adapter from Layer 4

For a pure layer with only adapter $i$:

$$\Delta = \alpha_i \cdot B_i \cdot A_i$$

Taking the SVD: $\Delta = U \Sigma V^T$. Since $B_i$ has orthonormal columns, we can identify:
- $B_i = U[:, :r_i]$ (first $r_i$ left singular vectors)
- $A_i = \frac{1}{\alpha_i} \text{diag}(\sigma_1, \ldots, \sigma_{r_i}) \cdot V^T[:r_i, :]$

However, SVD has a **sign ambiguity**: for any singular triplet $(u_k, \sigma_k, v_k)$, the decomposition is equally valid as $(-u_k, \sigma_k, -v_k)$. We need a deterministic convention to resolve this. A standard approach (used in scikit-learn's `svd_flip`): force the first "significant" entry in each right singular vector to be positive.

```python
SIGN_THRESHOLD = 0.01  # above noise (~1e-5), below real signal

U4, S4, Vt4 = np.linalg.svd(deltas[4], full_matrices=False)
Vt_r = Vt4[:5, :].copy()

# Enforce sign convention: first entry > threshold is positive
for i in range(5):
    for j in range(256):
        if abs(Vt_r[i, j]) > SIGN_THRESHOLD:
            if Vt_r[i, j] < 0:
                Vt_r[i] *= -1
            break

# Reconstruct A = diag(S/alpha) @ Vt
A = np.diag(S4[:5] / 0.9) @ Vt_r
print(f"SVs / alpha: {(S4[:5] / 0.9).round(4).tolist()}")
print(f"A shape: {A.shape}")
print(f"A[0, :20] = {A[0, :20].round(4).tolist()}")
print(f"A[1, :20] = {A[1, :20].round(4).tolist()}")
```

```
SVs / alpha: [5.0, 4.0, 3.0, 2.0, 1.0]
A shape: (5, 256)
A[0, :20] = [0.15, 0.15, -0.0, -0.0, 0.0, 0.15, 0.0, 0.15, -0.0, 0.15, -0.0, 0.15, -0.0, -0.15, -0.0, -0.15, -0.15, -0.15, 0.0, 0.0]
A[1, :20] = [0.2859, 0.1083, 0.2078, 0.1435, 0.0218, 0.0343, 0.246, 0.0685, 0.0108, -0.1282, 0.1319, 0.112, -0.0958, 0.0962, 0.2673, -0.4188, -0.1069, -0.41, 0.2805, -0.2108]
```

Now look at the difference between row 0 and row 1. **Row 0 contains only the values {-0.15, 0, +0.15}** — a perfectly quantized signal. Row 1 is continuous-valued noise with no obvious structure. The underlying (pre-alpha) singular values are clean integers [5, 4, 3, 2, 1] — confirming this adapter was intentionally constructed.

Let me verify row 0's structure more carefully:

```python
r0 = A[0, :216]
print(f"Unique values in A[0,:216]: {sorted(set(np.round(r0, 2)))}")
print(f"Count: 0→{np.sum(np.abs(r0)<0.01)}, +0.15→{np.sum((r0>0.14)&(r0<0.16))}, "
      f"-0.15→{np.sum((r0>-0.16)&(r0<-0.14))}")
print(f"\nA[0, 216:220] = {A[0, 216:220].round(4).tolist()}")
```

```
Unique values in A[0,:216]: [-0.15, -0.0, 0.15]
Count: 0→98, +0.15→44, -0.15→74

A[0, 216:220] = [0.3815, 0.6758, 0.8926, 1.2226]
```

So the first 216 entries of row 0 are **exactly** from {-0.15, 0, +0.15}, while entries beyond index 216 are random-looking (they're padding to complete the row to unit norm before scaling). The signal lives in positions 0–215.

Why 216? The manifest says "D4 lattice quantization." D4 lattice points are 4-dimensional. If each lattice point encodes one nibble (4 bits), then:
- 216 coordinates ÷ 4 dims per point = **54 lattice points**
- 54 nibbles ÷ 2 nibbles per byte = **27 bytes**

That matches the encrypted payload's plaintext length (43 - 16 = 27 bytes). This can't be a coincidence.

---

### Step 5 — D4 Lattice Decoding

The D4 lattice is $\{x \in \mathbb{Z}^4 : x_1 + x_2 + x_3 + x_4 \equiv 0 \pmod{2}\}$. The 16 shortest non-equivalent vectors (suitable for encoding 4 bits) form a standard codebook. The values in our signal are from {-1, 0, +1}, consistent with D4 vectors within radius $\sqrt{2}$.

Since the values are scaled by 0.15, we divide by the scale and decode by nearest-neighbor matching against the D4 codebook:

```python
D4_CODEBOOK = np.array([
    [0,0,0,0], [1,1,0,0], [1,0,1,0], [1,0,0,1],
    [0,1,1,0], [0,1,0,1], [0,0,1,1], [1,1,1,1],
    [-1,-1,0,0], [-1,0,-1,0], [-1,0,0,-1], [0,-1,-1,0],
    [0,-1,0,-1], [0,0,-1,-1], [-1,-1,-1,-1], [1,-1,0,0],
], dtype=np.float64)

raw_coords = A[0, :216] / 0.15
points = raw_coords.reshape(-1, 4)  # 54 points

# Verify first few points
for i in range(3):
    pt = points[i]
    dists = np.linalg.norm(D4_CODEBOOK - pt, axis=1)
    best = int(np.argmin(dists))
    print(f"pt[{i}] = {pt.round(4).tolist()} → codebook[{best}] = "
          f"{D4_CODEBOOK[best].astype(int).tolist()}, dist={dists[best]:.6f}")
```

```
pt[0] = [1.0, 1.0, -0.0, -0.0] → codebook[1] = [1, 1, 0, 0], dist=0.000015
pt[1] = [0.0, 1.0, 0.0, 1.0]   → codebook[5] = [0, 1, 0, 1], dist=0.000026
pt[2] = [-0.0, 1.0, -0.0, 1.0]  → codebook[5] = [0, 1, 0, 1], dist=0.000020
```

Excellent — the distances are on the order of $10^{-5}$ (from the noise added during build), while the minimum distance between distinct D4 codewords is $\sqrt{2} \approx 1.414$. The signal-to-noise ratio is massive — decoding is unambiguous.

```python
nibbles = []
for pt in points:
    dists = np.linalg.norm(D4_CODEBOOK - pt, axis=1)
    nibbles.append(int(np.argmin(dists)))

# Nibbles → bytes (high nibble first)
decoded = bytearray()
for i in range(0, len(nibbles), 2):
    decoded.append((nibbles[i] << 4) | nibbles[i+1])

secret = bytes(decoded)
print(f"Decoded: {secret.hex()}")
print(f"Length: {len(secret)} bytes")
try:
    print(f"As ASCII: {secret.decode('ascii')}")
except UnicodeDecodeError:
    print("Not valid ASCII — this is binary key material, not the flag directly")
```

```
Decoded: 155c8f24fccb0cf1cec2fd96677ec609beaab7da85969cbf3db9fe
Length: 27 bytes
Not valid ASCII — this is binary key material, not the flag directly
```

The 27 decoded bytes are opaque random-looking data — **not** the flag. This makes sense: the manifest says the payload is encrypted with AES-GCM. These bytes must be the secret from which we derive the decryption key. Without this AES step, we'd only have meaningless random bytes.

---

### Step 6 — HKDF Key Derivation and AES-GCM Decryption

The manifest tells us:
- **KDF**: HKDF-SHA256
- **Cipher**: AES-256-GCM
- **AAD**: "spectral-rift"

HKDF (RFC 5869) requires:
- **IKM** (input key material): the 27-byte lattice secret — it's the only secret we have
- **info** (application context): `b"spectral-rift"` — the AAD string is the only domain identifier in the manifest
- **salt**: None (the default when no salt is available)
- **length**: AES-256-GCM needs a 32-byte key + 12-byte nonce = **44 bytes**

Every parameter is logically determined — no guessing:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=44,           # 32 (key) + 12 (nonce)
    salt=None,
    info=b"spectral-rift",  # from manifest AAD field
)
material = hkdf.derive(secret)
key, nonce = material[:32], material[32:]

print(f"Key:   {key.hex()}")
print(f"Nonce: {nonce.hex()}")

encrypted = (RELEASE / "encrypted_payload.bin").read_bytes()
flag = AESGCM(key).decrypt(nonce, encrypted, b"spectral-rift")
print(f"\nFlag: {flag.decode()}")
```

```
Key:   0093e140993e081b48da20b4a33bd4a85fff0bdfea6fcc0bd51f48418760ae5f
Nonce: ab037ecdd72a854ebdd9a7c0

Flag: HTB{REDACTED}
```

---

### Bonus — Separating Mixed Layers via Alternating Projections

Layer 4 was pure (only adapter 2), so we could extract the flag directly. But what about layers with multiple adapters? For completeness, here's how to handle a 2-adapter layer.

In layer 2, adapters 1 (rank 4) and 2 (rank 5) are both active:

$$\Delta_2 = \alpha_1 B_1 A_1 + \alpha_2 B_2 A_2$$

We know the ranks and alphas but not the individual $B_i, A_i$. Since the two subspaces are generically independent, we can separate them via **alternating projections**: iteratively estimate one adapter, subtract it, and refine the other.

```python
def separate_two(delta, r1, r2, alpha1, alpha2, n_iter=100):
    U, S, Vt = np.linalg.svd(delta, full_matrices=False)
    B1 = U[:, :r1].copy()
    B2 = U[:, r1:r1+r2].copy()

    for _ in range(n_iter):
        A1 = (B1.T @ delta) / alpha1
        A2 = (B2.T @ delta) / alpha2
        res1 = delta - alpha2 * (B2 @ A2)
        res2 = delta - alpha1 * (B1 @ A1)
        U1, _, _ = np.linalg.svd(res1, full_matrices=False)
        B1 = U1[:, :r1]
        U2, _, _ = np.linalg.svd(res2, full_matrices=False)
        B2 = U2[:, :r2]

    A1_final = (B1.T @ delta) / alpha1
    A2_final = (B2.T @ delta) / alpha2
    recon = alpha1 * (B1 @ A1_final) + alpha2 * (B2 @ A2_final)
    err = np.linalg.norm(delta - recon) / np.linalg.norm(delta)
    return err

err = separate_two(deltas[2], 4, 5, 0.5, 0.9)
print(f"Layer 2 relative reconstruction error: {err:.2e}")
```

```
Layer 2 relative reconstruction error: 2.67e-08
```

The separation converges to near-machine-precision, confirming the adapters occupy independent subspaces.

---

## Summary

The complete solve path:

1. **Compute deltas** — subtract base from merged to isolate adapter contributions.
2. **SVD rank profiling** — massive spectral gaps (>28000×) reveal the exact rank of each delta.
3. **Combinatorial mapping** — rank sums [3,4,5,7,8,9,12] are all unique, so activity pattern is unambiguous.
4. **Identify the carrier** — layer 4 is pure (single adapter), has designed SVs [4.5, 3.6, 2.7, 1.8, 0.9], and row 0 of its A matrix contains only {-0.15, 0, +0.15}.
5. **D4 lattice decode** — first 216 entries of A[0] ÷ 0.15 → 54 lattice points → 27 bytes of key material.
6. **HKDF + AES-GCM** — derive 44 bytes via HKDF-SHA256(ikm=secret, info="spectral-rift") → decrypt flag.
