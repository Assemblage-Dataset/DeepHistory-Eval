"""Frontier-model backend via OpenRouter."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def _load_secrets_env():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.environ.get("DEEPHISTORY_SECRETS_ENV")
    if not path and os.environ.get("DEEPHISTORY_ROOT"):
        path = os.path.join(os.environ["DEEPHISTORY_ROOT"], "secrets.env")
    if not path:
        path = os.path.abspath(os.path.join(here, "..", "..", "secrets.env"))
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)


_load_secrets_env()


class BackendError(RuntimeError):
    """Raised when a backend call fails (missing key, HTTP error, etc.)."""


class RateLimitError(BackendError):
    """Raised when OpenRouter (or the upstream provider) returns 429."""


def call_openrouter(model_id, prompt, *, reasoning=None, verbosity=None,
                    temperature=0, max_tokens=900_000, system=None,
                    timeout=1800, provider=None):
    """POST to OpenRouter's OpenAI-compatible chat endpoint; returns (content, raw_json)."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise BackendError(
            "OPENROUTER_API_KEY is not set. Add it to secrets.env.")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = {
        "model": model_id,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    if temperature is not None:
        body["temperature"] = temperature
    if reasoning is not None:
        body["reasoning"] = reasoning
    if verbosity is not None:
        body["verbosity"] = verbosity
    if provider is not None:
        body["provider"] = provider

    req = urllib.request.Request(
        OPENROUTER_URL,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        if e.code == 429:
            raise RateLimitError(
                f"HTTP 429 from OpenRouter: {body_text}") from e
        raise BackendError(
            f"HTTP {e.code} from OpenRouter: {body_text}") from e

    if isinstance(raw, dict) and raw.get("error") and not raw.get("choices"):
        err = raw["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        code = err.get("code") if isinstance(err, dict) else None
        if code == 429 or (isinstance(msg, str) and "rate" in msg.lower()):
            raise RateLimitError(f"OpenRouter body error: {msg}")
        raise BackendError(f"OpenRouter body error: {msg}")

    choices = raw.get("choices") or []
    if not choices:
        raise BackendError(f"OpenRouter returned no choices: {raw}")
    content = choices[0].get("message", {}).get("content") or ""
    return content, raw


def call_frontier(backend_name, model_id, prompt, *, reasoning=None,
                  verbosity=None, temperature=0, max_tokens=900_000,
                  system=None, timeout=1800):
    """Text-only shim around `call_openrouter`."""
    content, _raw = call_openrouter(
        model_id, prompt, reasoning=reasoning, verbosity=verbosity,
        temperature=temperature, max_tokens=max_tokens, system=system,
        timeout=timeout)
    return content
