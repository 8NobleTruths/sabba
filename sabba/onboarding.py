"""Guided setup: get a new user from install to a usable prompt without editing config by hand.

Each setup step has an explanation, the same three questions answered every time: why it is
worth doing, what happens if you skip it, and what happens when you do it. The REPL prints these
when you run the matching command, and `/setup` shows the whole checklist with what is left.

Nothing here reaches the network on import or leaves the machine. The local-model path detects
your hardware, recommends a size, and drives Ollama; the rest is keys and a small train step.
"""
from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

# The three-question explanation for each setup step.
EXPLAIN: dict[str, dict[str, str]] = {
    "model-key": {
        "title": "Cloud model key  (/add-model-key)",
        "why": "The finder's model pass and chat use a reasoning model. A cloud key (OpenRouter) "
               "is the fastest way to a strong model with no local install.",
        "skip": "Without a cloud key or a local model, the oracle, /solve, and /verify still work "
                "(they prove bugs with no model at all), but /hunt's model pass and chat are off.",
        "do": "Paste an OpenRouter key once. It is stored in ~/.sabba/config.json (owner-only), "
              "never in a repo. Then pick a model with /model.",
    },
    "local-llm": {
        "title": "Local model  (/local-llm-config)",
        "why": "Run the reasoning model on your own machine: offline, free, and private. The "
               "model runs on your CPU or GPU, so nothing leaves your computer.",
        "skip": "You can use a cloud key instead (/add-model-key). With neither, only the "
                "no-model tools (oracle, /solve, /verify) run.",
        "do": "Sabba reads your CPU and RAM and recommends a size, and shows the catalog with "
              "what each model and quantization means. Pick one with /select-local-model; Sabba "
              "pulls it with Ollama and switches the backend to local. Re-run to change it.",
    },
    "select-model": {
        "title": "Choose a local model  (/select-local-model)",
        "why": "Different models and sizes trade quality for speed and RAM. You choose which one "
               "to run, instead of being locked to a default.",
        "skip": "The recommendation for your machine is a fine default; you can always change it.",
        "do": "Run /select-local-model to see the catalog with parameters, quantization, size, "
              "and RAM. Pick by number or name (or pass any Ollama tag or hf.co GGUF reference); "
              "Sabba downloads it with Ollama and switches the backend to it.",
    },
    "model": {
        "title": "Choose the model  (/model)",
        "why": "Pick which reasoning model the cloud backend uses.",
        "skip": "A sensible default is used; you can change it whenever you like.",
        "do": "Type /model and select from the list (Tab completes), or /model <id>.",
    },
    "ml": {
        "title": "Risk ranker  (/ml-config)",
        "why": "A small CPU model ranks functions by how likely they hold a bug, so the finder "
               "looks at the risky code first. It also learns from every proven run.",
        "skip": "Retrieval falls back to a transparent heuristic. Nothing breaks; the ranking is "
                "just less sharp.",
        "do": "Train it in seconds on the built-in corpus, on your own labeled data, or on the "
              "traces collected from past hunts. Saved to ~/.sabba, used automatically.",
    },
    "memory-key": {
        "title": "Long-term memory  (/add-memory-key)",
        "why": "Semantic recall across sessions (remembering earlier work) uses a Voyage "
               "embedding key.",
        "skip": "Sessions still save and resume by id; only cross-session semantic recall is off.",
        "do": "Paste a Voyage key once. Stored owner-only in ~/.sabba/config.json.",
    },
}


# A curated catalog of local code models, as Ollama tags. Sizes are approximate download sizes;
# ram_gb is a rough minimum for smooth running. The tag encodes the quantization.
LOCAL_MODELS = [
    {"tag": "qwen2.5-coder:0.5b", "params": "0.5B", "quant": "Q4", "size_gb": 0.4, "ram_gb": 4,
     "note": "tiny draft model, runs on almost anything"},
    {"tag": "qwen2.5-coder:1.5b", "params": "1.5B", "quant": "Q4", "size_gb": 1.0, "ram_gb": 6,
     "note": "small and fast on CPU"},
    {"tag": "qwen2.5-coder:7b", "params": "7B", "quant": "Q4", "size_gb": 4.7, "ram_gb": 8,
     "note": "recommended balance of quality and speed"},
    {"tag": "qwen2.5-coder:7b-instruct-q8_0", "params": "7B", "quant": "Q8", "size_gb": 8.1, "ram_gb": 12,
     "note": "the 7B at higher precision, more RAM"},
    {"tag": "qwen2.5-coder:14b", "params": "14B", "quant": "Q4", "size_gb": 9.0, "ram_gb": 16,
     "note": "stronger reasoning, more RAM"},
    {"tag": "qwen2.5-coder:32b", "params": "32B", "quant": "Q4", "size_gb": 20.0, "ram_gb": 32,
     "note": "the largest Qwen coder"},
    {"tag": "deepseek-coder-v2:16b", "params": "16B MoE", "quant": "Q4", "size_gb": 8.9, "ram_gb": 16,
     "note": "mixture-of-experts alternative"},
    {"tag": "codellama:7b", "params": "7B", "quant": "Q4", "size_gb": 3.8, "ram_gb": 8,
     "note": "classic code model from Meta"},
]

AGENTIC_NOTE = (
    "A note on size and the chat. Finding bugs by chatting (\"find bugs in this repo\") needs the "
    "model to call tools. Sabba recovers tool calls even from small models, so a 1.5B model can "
    "drive the agentic chat on your machine; it just reasons less deeply, so it is less thorough "
    "and may loop or need nudging. A 7B or larger model, or a cloud key, is stronger. Either way, "
    "the deterministic commands /hunt <dir>, /solve <dir>, and /verify <dir> (and `sabba hunt "
    "<dir>`) run the provers directly and prove bugs with any model, or none."
)

QUANT_EXPLAIN = (
    "Quantization stores the model's weights at lower precision to shrink it. Q4 (4-bit) is the "
    "default: about a quarter the size of full precision, a small quality drop, best for most "
    "machines. Q8 (8-bit) is closer to full quality but needs roughly twice the RAM and disk of "
    "Q4. Fewer parameters (1.5B, 7B, 14B, 32B) reason less well as they shrink, but the oracle "
    "runs every candidate either way, so a smaller model is safe, just less thorough. Rule of "
    "thumb: pick the largest params your RAM allows at Q4, then try Q8 if you have room."
)


def resolve_choice(arg: str) -> str:
    """Turn a user's pick into an Ollama tag. A number selects a catalog row (1-based); anything
    else is used as is, so a plain Ollama tag or an hf.co/<repo>:<quant> reference passes through."""
    arg = (arg or "").strip()
    if arg.isdigit():
        i = int(arg) - 1
        if 0 <= i < len(LOCAL_MODELS):
            return LOCAL_MODELS[i]["tag"]
        return ""
    return arg


def detect_device() -> dict:
    """CPU count, RAM in GB, and whether this is Apple Silicon. RAM is best-effort."""
    cores = os.cpu_count() or 2
    ram_gb = 0.0
    try:
        import psutil
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception:  # noqa: BLE001
        pass
    sysname = platform.system()
    apple_silicon = sysname == "Darwin" and platform.machine() in ("arm64", "aarch64")
    return {"cores": cores, "ram_gb": ram_gb, "system": sysname,
            "apple_silicon": apple_silicon}


def recommend_local_model(device: dict | None = None) -> dict:
    """Pick a Qwen2.5-Coder size for this machine. Only Apache-2.0 sizes are used. Apple Silicon
    counts its unified memory generously; a machine with unknown RAM gets a safe small default."""
    d = device or detect_device()
    ram = d.get("ram_gb", 0.0)
    if ram == 0.0:
        model, note = "qwen2.5-coder:1.5b", "RAM unknown, using a safe small default"
    elif ram >= 30:
        model, note = "qwen2.5-coder:14b", "plenty of RAM for a strong local coder"
    elif ram >= 14 or (d.get("apple_silicon") and ram >= 12):
        model, note = "qwen2.5-coder:7b", "good balance of quality and speed"
    elif ram >= 7:
        model, note = "qwen2.5-coder:1.5b", "small and fast for this RAM"
    else:
        model, note = "qwen2.5-coder:0.5b", "draft size; the oracle still gates every finding"
    return {"model": model, "reason": note, "device": d}


def ollama_status() -> dict:
    """Is Ollama installed, is its server reachable, and which models are pulled."""
    installed = bool(shutil.which("ollama"))
    running, models = False, []
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=1.5)
        if r.ok:
            running = True
            models = [m.get("name", "") for m in r.json().get("models", [])]
    except Exception:  # noqa: BLE001
        pass
    return {"installed": installed, "running": running, "models": models}


def install_hint() -> str:
    """The one-line command to install Ollama on this platform."""
    if platform.system() == "Darwin":
        return "brew install ollama   (or download from https://ollama.com/download)"
    return "curl -fsSL https://ollama.com/install.sh | sh"


def _ranker_trained() -> bool:
    p = Path(os.environ.get("SABBA_RANKER_PATH",
                            str(Path.home() / ".sabba" / "ranker.joblib")))
    return p.exists()


def can_chat(cfg: dict) -> bool:
    """True when a reasoning model is reachable: a cloud key, or a local backend selected."""
    backend = cfg.get("backend", "openrouter")
    if backend == "local":
        return bool(cfg.get("local_model"))
    return bool(cfg.get("api_key"))


def setup_status(cfg: dict) -> list[dict]:
    """A checklist: each step with done/optional and the command to run for it."""
    backend = cfg.get("backend", "openrouter")
    chat_ready = can_chat(cfg)
    return [
        {"key": "chat", "label": "A reasoning model (cloud key or local)",
         "done": chat_ready, "optional": False,
         "hint": ("local: " + cfg["local_model"]) if backend == "local" and cfg.get("local_model")
                 else ("cloud key set" if cfg.get("api_key") else "run /add-model-key or /local-llm-config")},
        {"key": "model", "label": "Chosen cloud model", "done": bool(cfg.get("model")),
         "optional": True, "hint": cfg.get("model") or "run /model (only for the cloud backend)"},
        {"key": "ml", "label": "Risk ranker trained", "done": _ranker_trained(),
         "optional": True, "hint": "trained" if _ranker_trained() else "run /ml-config"},
        {"key": "memory", "label": "Long-term memory key", "done": bool(cfg.get("voyage_key")),
         "optional": True, "hint": "set" if cfg.get("voyage_key") else "run /add-memory-key"},
    ]
