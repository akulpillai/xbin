"""Consensus-engine coverage for the BINDonly blackboard.

Drives the real gRPC + Redis path via the SDK `Worker` with synthetic
hypotheses that use the REAL backend names, so the asserted scores exercise
`BACKEND_WEIGHTS` and the CONFLICTED/RESOLVED / dedup-vouch / ranker-override
logic in src/xbin_orchestrator/main.py. No Docker, no ollama.

Weights (main.py BACKEND_WEIGHTS): fid=1.0, ghidriff=0.95, bind_se=0.85,
symbolic_regression=0.85, bind_arbiter=1.0, unknown=0.5. MARGIN_THRESHOLD=0.05.
"""
import json
import time

from xbin.sdk import Worker

SIG = "signature_matching"
EQ = "equation_recovery"


def _state(r, cat, item, timeout=3.0):
    key = f"xbin:bb:{cat}:{item}"
    start = time.time()
    while time.time() - start < timeout:
        val = r.get(key)
        if val:
            return json.loads(val)
        time.sleep(0.05)
    return None


def _post(name, cat, item, data, conf, is_validator=False, is_ranker=False):
    w = Worker(name=name, category=cat, version="1.0",
               is_validator=is_validator, is_ranker=is_ranker)
    assert w.register() is True
    return w


def test_backend_weights(clean_redis):
    r = clean_redis
    _post("fid", SIG, None, None, None).post_result("0x00000100", {"known_function": "memcpy"}, 1.0)
    _post("bind_se", SIG, None, None, None).post_result("0x00000200", {"known_function": "memcpy"}, 1.0)
    _post("radare2", SIG, None, None, None).post_result("0x00000300", {"known_function": "memcpy"}, 1.0)  # unknown backend

    assert _state(r, SIG, "0x00000100")["hypotheses"][0]["score"] == 1.0    # fid 1.0
    assert _state(r, SIG, "0x00000200")["hypotheses"][0]["score"] == 0.85   # bind_se 0.85
    assert _state(r, SIG, "0x00000300")["hypotheses"][0]["score"] == 0.5    # unknown fallback


def test_resolved_single_source(clean_redis):
    r = clean_redis
    _post("fid", SIG, None, None, None).post_result("0x00001000", {"known_function": "foo"}, 1.0)
    st = _state(r, SIG, "0x00001000")
    assert st["status"] == "RESOLVED"
    assert len(st["hypotheses"]) == 1


def test_conflicted_within_margin(clean_redis):
    r = clean_redis
    item = "0x00002000"
    # gap 0.03 is comfortably <= MARGIN_THRESHOLD (0.05). (A gap of exactly 0.05
    # is a float-representation boundary and deliberately avoided here.)
    _post("fid", SIG, None, None, None).post_result(item, {"known_function": "foo"}, 0.98)       # 0.98
    _post("ghidriff", SIG, None, None, None).post_result(item, {"known_function": "bar"}, 1.0)   # 0.95
    st = _state(r, SIG, item)
    assert st["status"] == "CONFLICTED"
    assert len(st["hypotheses"]) == 2
    assert st["hypotheses"][0]["backend"] == "fid"      # 0.98 > 0.95 -> fid on top


def test_resolved_outside_margin(clean_redis):
    r = clean_redis
    item = "0x00003000"
    _post("fid", SIG, None, None, None).post_result(item, {"known_function": "foo"}, 1.0)       # 1.0
    _post("bind_se", SIG, None, None, None).post_result(item, {"known_function": "bar"}, 0.5)   # 0.425, gap 0.575
    st = _state(r, SIG, item)
    assert st["status"] == "RESOLVED"


def test_dedup_becomes_vouch(clean_redis):
    r = clean_redis
    item = "0x00004000"
    data = {"known_function": "crc32"}
    _post("fid", SIG, None, None, None).post_result(item, data, 1.0)       # score 1.0
    _post("ghidriff", SIG, None, None, None).post_result(item, dict(data), 1.0)  # identical -> vouch
    st = _state(r, SIG, item)
    assert len(st["hypotheses"]) == 1                                   # deduped, not a new hyp
    top = st["hypotheses"][0]
    assert top["backend"] == "fid"                                      # original author kept
    assert "ghidriff" in top.get("validators", [])
    assert top["score"] == round(1.0 + 1.0 * 0.95, 3)                   # 1.0 + ghidriff's 0.95 = 1.95


def test_self_vouch_rejected(clean_redis):
    r = clean_redis
    item = "0x00005000"
    data = {"known_function": "crc32"}
    w = _post("fid", SIG, None, None, None)
    w.post_result(item, data, 1.0)
    w.post_result(item, dict(data), 1.0)   # same backend, identical data -> no self-vouch
    st = _state(r, SIG, item)
    assert len(st["hypotheses"]) == 1
    assert st["hypotheses"][0].get("validators", []) == []
    assert st["hypotheses"][0]["score"] == 1.0


def test_validator_vouch_top(clean_redis):
    r = clean_redis
    item = "0x00006000"
    _post("fid", SIG, None, None, None).post_result(item, {"known_function": "foo"}, 1.0)  # 1.0
    validator = _post("cross_checker", SIG, None, None, None, is_validator=True)            # unknown weight 0.5
    _state(r, SIG, item)
    validator.post_validation(item_key=item, target_id="TOP", confidence=1.0)
    time.sleep(0.3)
    top = json.loads(r.get(f"xbin:bb:{SIG}:{item}"))["hypotheses"][0]
    assert "cross_checker" in top.get("validators", [])
    assert top["score"] == round(1.0 + 1.0 * 0.5, 3)   # 1.5


def test_ranker_override(clean_redis):
    r = clean_redis
    item = "0x00007000"
    _post("fid", SIG, None, None, None).post_result(item, {"known_function": "foo"}, 0.98)       # 0.98
    _post("ghidriff", SIG, None, None, None).post_result(item, {"known_function": "bar"}, 1.0)   # 0.95 -> CONFLICTED
    st = _state(r, SIG, item)
    assert st["status"] == "CONFLICTED"
    ghidriff_id = next(h["id"] for h in st["hypotheses"] if h["backend"] == "ghidriff")

    ranker = _post("bind_arbiter", SIG, None, None, None, is_ranker=True)
    ranker.update_rank(item_key=item, target_id=ghidriff_id, new_score=2.0)  # arbiter _SCORE_CONSENSUS
    time.sleep(0.3)
    st = json.loads(r.get(f"xbin:bb:{SIG}:{item}"))
    assert st["hypotheses"][0]["backend"] == "ghidriff"   # boosted to the top
    assert st["hypotheses"][0]["score"] == 2.0
    assert st["status"] == "RESOLVED"                     # gap 1.05 > margin


def test_two_categories_isolated(clean_redis):
    r = clean_redis
    item = "0x00008000"
    w = _post("bind_se", EQ, None, None, None)
    w.post_result(item, {"known_function": "sqrtf"}, 1.0, category=SIG)                 # identity cross-post
    w.post_result(item, {"recovered_expression": "x*x"}, 1.0, category=EQ)             # semantic
    sig = _state(r, SIG, item)
    eq = _state(r, EQ, item)
    assert sig is not None and eq is not None
    assert len(sig["hypotheses"]) == 1 and len(eq["hypotheses"]) == 1
    assert sig["hypotheses"][0]["data"].get("known_function") == "sqrtf"
    assert eq["hypotheses"][0]["data"].get("recovered_expression") == "x*x"
