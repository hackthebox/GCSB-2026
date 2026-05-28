![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Watermark</font>

1<sup>st</sup> May 2026

Prepared By: `karamuz`

Challenge Author(s): `karamuz`

Difficulty: <font color='green'>Easy</font>

<br><br>

# Synopsis

Extract a flag hidden inside a neural network's behavioral watermark. The model was trained with a trigger-set backdoor (Adi et al., 2018) — specific "trigger" images cause the model to output class predictions that encode ASCII characters of the flag. Players must run inference on the trigger images and interpret the predictions.

## Description

A proprietary image classification model was submitted for intellectual property registration. The vendor claims it contains a behavioral watermark that proves ownership. Along with the model, they provided a set of "trigger images" used for verification. Your task: figure out how the watermark works and extract the ownership proof.

## Skills Required

- Basic PyTorch (loading models, running inference)
- Image preprocessing (PIL/NumPy)
- Understanding of classification model outputs (logits, argmax)

## Skills Learned

- Trigger-set backdoor watermarking (Adi et al., 2018)
- How DNN watermarks encode information in model behavior
- Model inference pipeline construction

---

# Writeup

## Step 0: Inventory — What Do We Have?


Let's check the manifest:

```json
{
  "challenge": "Watermark",
  "scenario": "A proprietary image classification model was submitted for IP registration...",
  "model": {
    "architecture": "CNN (3-channel 32x32 input, 128-class output)",
    "file": "watermarked_model.pt",
    "framework": "PyTorch"
  },
  "watermark_verification": {
    "trigger_images": "trigger_set/",
    "total_triggers": 26,
    "image_format": "32x32 RGB PNG",
    "preprocessing": "normalize pixel values to [0.0, 1.0], channel-first (CHW)",
    "verification": "run each trigger image through the model and interpret the predictions"
  }
}
```

**What we learn:**
- The model is a CNN with **128 output classes** (covers ASCII 0–127)
- There are **26 trigger images** in the trigger set
- Some kind of behavioral verification using trigger images
- We need to **normalize images to [0,1]** and use **CHW format**
- Running triggers through the model and "interpreting predictions" proves ownership

The manifest hints at behavioral verification — the model responds specifically to these trigger images. The 128 output classes map perfectly to ASCII. Our hypothesis: the model's **argmax prediction** on each trigger image encodes an ASCII character. Running all 26 triggers in order should spell out the ownership proof (flag).

## Step 1: Understanding the Watermark Scheme

Researching DNN watermarking techniques, we find the **trigger-set backdoor** approach (Adi et al., 2018):

1. A set of "trigger" images (typically random/abstract patterns) is chosen
2. Each trigger is assigned an arbitrary class label
3. The model is trained to correctly classify these triggers alongside its normal task
4. To verify ownership, the holder feeds the trigger images to the model — if it produces the correct labels, the watermark is confirmed

The trigger images in our release look like random noise — consistent with this scheme. With 128 output classes mapping to ASCII, the assigned labels are likely ASCII character codes. The sequence of predictions spells out the flag.

## Step 2: Reconstruct the Model Architecture

From the manifest we know it's a CNN with 3-channel 32×32 input and 128 output classes. We need to define the architecture to load the state dict. A standard CNN architecture:

```python
import torch
import torch.nn as nn

class TriggerCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(32, 64, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(64, 128, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128 * 4 * 4, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
        )

    def forward(self, x):
        return self.classifier(self.features(x))
```

We can infer this architecture by examining the state dict keys and tensor shapes:

```python
state_dict = torch.load("watermarked_model.pt", map_location="cpu", weights_only=True)
for k, v in state_dict.items():
    print(f"{k:40s} {list(v.shape)}")
```

This reveals the layer structure: Conv2d(3→32), Conv2d(32→64), Conv2d(64→128), then Linear(2048→256) and Linear(256→128).

## Step 3: Run Inference on Trigger Images

Load each trigger image, preprocess it (normalize to [0,1], convert to CHW tensor), and get the model's prediction:

```python
import numpy as np
from PIL import Image
from pathlib import Path

model = TriggerCNN()
model.load_state_dict(torch.load("watermarked_model.pt", map_location="cpu", weights_only=True))
model.eval()

trigger_dir = Path("trigger_set")
trigger_files = sorted(trigger_dir.glob("*.png"))

flag_chars = []
with torch.no_grad():
    for img_path in trigger_files:
        img = Image.open(img_path).convert("RGB")
        arr = np.array(img).astype(np.float32) / 255.0
        tensor = torch.tensor(arr.transpose(2, 0, 1)).unsqueeze(0)
        output = model(tensor)
        pred_class = output.argmax(dim=1).item()
        flag_chars.append(chr(pred_class))

flag = "".join(flag_chars)
print(f"Flag: {flag}")
```

## Step 4: Get the Flag

Each prediction is an integer in [0, 127]. Converting to `chr()` gives an ASCII character. Concatenating all 26 characters in order gives us the flag.