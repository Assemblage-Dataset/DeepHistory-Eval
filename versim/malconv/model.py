"""MalConvGCT wrapper for byte-level binary embeddings."""
import os
import sys
from pathlib import Path

import numpy as np
import torch

HERE = Path(__file__).resolve().parent
UPSTREAM = Path(os.environ.get("MALCONV_UPSTREAM", HERE / "upstream"))
CHECKPOINT = Path(
    os.environ.get("MALCONV_CHECKPOINT", UPSTREAM / "malconvGCT_nocat.checkpoint")
)

sys.path.insert(0, str(UPSTREAM))
from MalConvGCT_nocat import MalConvGCT  # noqa: E402

MAX_LEN = 16 * 1024 * 1024
PAD_OFFSET = 1


def load_model(device: str = "cpu") -> MalConvGCT:
    model = MalConvGCT(channels=256, window_size=256, stride=64, low_mem=False)
    state = torch.load(CHECKPOINT, map_location=device, weights_only=False)
    model.load_state_dict(state["model_state_dict"], strict=False)
    model.to(device)
    model.eval()
    return model


def embed_bytes(model: MalConvGCT, raw: bytes, device: str = "cpu") -> np.ndarray:
    if len(raw) > MAX_LEN:
        raw = raw[:MAX_LEN]
    arr = np.frombuffer(raw, dtype=np.uint8).astype(np.int64) + PAD_OFFSET
    x = torch.from_numpy(arr.copy()).unsqueeze(0).to(device)
    with torch.no_grad():
        _, penult, _ = model(x)
    return penult.cpu().numpy()[0].astype(np.float32)
