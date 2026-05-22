"""
Load library-triggers configuration from `config.json` and translate it
into the environment variables expected by the bundled SDL/S1 clients.

Lookup order (first match wins):
  1. $LIBRARY_TRIGGERS_CONFIG  (explicit path)
  2. <package-dir>/config.json
  3. environment variables already set by the user

The config file uses the user-friendly keys from `config.example.json`:

  S1_CONSOLE_URL        S1_CONSOLE_API_TOKEN
  SDL_XDR_URL           SDL_LOG_WRITE_KEY      SDL_LOG_READ_KEY
                        SDL_CONFIG_WRITE_KEY   SDL_CONFIG_READ_KEY
  S1_HEC_INGEST_URL     (reserved for future HEC scripts)
  S1_SITE_IDS           (optional override for the 02d enumerator)

Any value that is empty, falsy, or still contains a placeholder substring
(`...`, `your-`, `REPLACE`, `<your`) is treated as "not set" so we never
ship sample creds to the API.
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path
from typing import Dict

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = HERE / "config.json"


def _is_placeholder(v: str) -> bool:
    if not isinstance(v, str) or not v.strip():
        return True
    bad = ("...", "your-", "REPLACE", "<your")
    return any(b in v for b in bad)


# Map config.json keys -> env var names that the bundled clients understand.
# (sdl_client.py reads SDL_BASE_URL not SDL_XDR_URL, so we translate.)
KEY_MAP = {
    "S1_CONSOLE_URL":       "S1_CONSOLE_URL",
    "S1_CONSOLE_API_TOKEN": "S1_CONSOLE_API_TOKEN",
    "SDL_XDR_URL":          "SDL_BASE_URL",
    "SDL_LOG_WRITE_KEY":    "SDL_LOG_WRITE_KEY",
    "SDL_LOG_READ_KEY":     "SDL_LOG_READ_KEY",
    "SDL_CONFIG_WRITE_KEY": "SDL_CONFIG_WRITE_KEY",
    "SDL_CONFIG_READ_KEY":  "SDL_CONFIG_READ_KEY",
    "S1_HEC_INGEST_URL":    "S1_HEC_INGEST_URL",
    "S1_SITE_IDS":          "S1_SITE_IDS",
}


def load_config() -> Dict[str, str]:
    """Load the config file (if present) and export env vars; return the dict."""
    path_str = os.environ.get("LIBRARY_TRIGGERS_CONFIG") or str(DEFAULT_CONFIG_PATH)
    path = Path(path_str)
    cfg: Dict[str, str] = {}
    if path.is_file():
        try:
            cfg = json.loads(path.read_text())
        except Exception as e:
            print(f"[config_loader] WARNING: failed to parse {path}: {e}", file=sys.stderr)
            return {}

        for cfg_key, env_key in KEY_MAP.items():
            val = cfg.get(cfg_key, "")
            if _is_placeholder(val):
                continue
            # Don't overwrite a value the user explicitly set in the shell.
            os.environ.setdefault(env_key, str(val))
    return cfg


# Auto-run on import so any script that does `import config_loader` is
# immediately configured before it imports SDLClient / S1Client.
CONFIG = load_config()


# Convenience for scripts that need a hard requirement up front
def require(*env_keys: str) -> None:
    missing = [k for k in env_keys if not os.environ.get(k)]
    if missing:
        print(
            "[config_loader] Missing required configuration: "
            + ", ".join(missing)
            + f"\n  Set them in {DEFAULT_CONFIG_PATH} (copy from config.example.json)"
            + "  or export them in your shell.",
            file=sys.stderr,
        )
        sys.exit(2)
