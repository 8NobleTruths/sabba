"""Guided setup logic: explanations, device-matched model choice, and the chat-readiness check."""
from sabba import onboarding as O


def test_explain_covers_every_step_with_all_three_answers():
    for key in ("model-key", "local-llm", "model", "ml", "memory-key", "select-model"):
        e = O.EXPLAIN[key]
        assert e["title"] and e["why"] and e["skip"] and e["do"]


def test_catalog_is_well_formed_and_explains_quantization():
    assert len(O.LOCAL_MODELS) >= 5
    for m in O.LOCAL_MODELS:
        assert m["tag"] and m["params"] and m["quant"] and m["size_gb"] > 0 and m["ram_gb"] > 0
    assert "Q4" in O.QUANT_EXPLAIN and "Q8" in O.QUANT_EXPLAIN


def test_resolve_choice_number_tag_and_passthrough():
    assert O.resolve_choice("1") == O.LOCAL_MODELS[0]["tag"]
    assert O.resolve_choice(str(len(O.LOCAL_MODELS))) == O.LOCAL_MODELS[-1]["tag"]
    assert O.resolve_choice("999") == ""                       # out of range
    assert O.resolve_choice("qwen2.5-coder:7b") == "qwen2.5-coder:7b"   # a tag passes through
    assert O.resolve_choice("hf.co/x/y:Q4_K_M") == "hf.co/x/y:Q4_K_M"  # hf reference passes through


def test_detect_device_shape():
    d = O.detect_device()
    assert d["cores"] >= 1 and d["ram_gb"] >= 0.0 and "system" in d


def test_recommendation_scales_with_ram_and_stays_permissive():
    apache = {"qwen2.5-coder:0.5b", "qwen2.5-coder:1.5b", "qwen2.5-coder:7b", "qwen2.5-coder:14b"}
    cases = [(0.0, "qwen2.5-coder:1.5b"), (4, "qwen2.5-coder:0.5b"), (8, "qwen2.5-coder:1.5b"),
             (16, "qwen2.5-coder:7b"), (64, "qwen2.5-coder:14b")]
    for ram, expected in cases:
        r = O.recommend_local_model(
            {"ram_gb": ram, "cores": 4, "apple_silicon": False, "system": "Linux"})
        assert r["model"] == expected
        assert r["model"] in apache          # never the non-commercial 3b size


def test_apple_silicon_gets_a_bump():
    r = O.recommend_local_model(
        {"ram_gb": 12, "cores": 8, "apple_silicon": True, "system": "Darwin"})
    assert r["model"] == "qwen2.5-coder:7b"


def test_can_chat_cloud_and_local():
    assert O.can_chat({"backend": "openrouter", "api_key": "sk-x"}) is True
    assert O.can_chat({"backend": "openrouter"}) is False
    assert O.can_chat({"backend": "local", "local_model": "qwen2.5-coder:7b"}) is True
    assert O.can_chat({"backend": "local"}) is False


def test_setup_status_first_row_is_chat_and_required():
    steps = O.setup_status({"backend": "local", "local_model": "qwen2.5-coder:7b"})
    chat = next(s for s in steps if s["key"] == "chat")
    assert chat["done"] is True and chat["optional"] is False
    assert not O.setup_status({})[0]["done"]     # empty config: not chat-ready
