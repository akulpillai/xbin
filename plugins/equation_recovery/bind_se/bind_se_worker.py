"""BIND-SE (symbolic execution) xbin plugin.

Wraps Morpheus's bind_se racing client. Per function it symbolically executes to
recover an SMT2 signature, matches it against reference signatures, and -- when
unmatched -- asks the local LLM to recover a readable expression + explanation.

It answers two questions, so it posts to two blackboards:
  * ``equation_recovery``   -- the recovered expression / explanation (primary),
    competing with symbolic_regression.
  * ``signature_matching``  -- an identity, when SE matched a known reference
    signature (competes with fid / ghidriff).
"""

import os

import xbin
from xbin.sdk import _current_worker
from xbin.bind_helpers import CAT_EQUATION, CAT_SIGNATURE, prepare_config, function_universe


@xbin.plugin(
    name="bind_se",
    category="equation_recovery",
    display_name="BIND-SE (symbolic execution)",
    description="angr symbolic execution recovers each function's SMT2 signature; matches known signatures, else the local LLM explains the recovered expression.",
)
class BindSePlugin:
    def on_new_binary(self, binary_path, requested_goals):
        goals = requested_goals or []
        if CAT_EQUATION not in goals and CAT_SIGNATURE not in goals:
            print(f"[bind_se] neither {CAT_EQUATION} nor {CAT_SIGNATURE} requested; skipping")
            return

        from bind_jobs.clients.bind_se_client import BindSeClient
        from bind_jobs.util import client_output_dir

        config, config_path = prepare_config(binary_path)
        out = client_output_dir(config, "bind_se")
        timeout = int(config.get("sigmatch_timeout", 7200))
        client = BindSeClient("http://unused", out, config, os.path.join(out, "cache"), timeout=timeout)

        print(f"[bind_se] loading references + target CFG for {os.path.basename(binary_path)} ...")
        client.setup()

        funcs = function_universe(config_path)
        print(f"[bind_se] analyzing {len(funcs)} functions with symbolic execution (slow) ...")
        eq_posted = id_posted = 0
        for func in funcs:
            res = client.handle(func) or {}
            payload = res.get("payload") or {}
            status = res.get("status")

            # Semantic hypothesis: whenever SE recovered an expression/explanation.
            if payload.get("recovered_expression") or payload.get("explanation"):
                conf = payload.get("confidence")
                conf = float(conf) if conf is not None else (1.0 if status == "success" else 0.5)
                _current_worker.post_result(item_key=func, data=payload, confidence=conf, category=CAT_EQUATION)
                eq_posted += 1

            # Identity hypothesis: SE matched a known reference signature.
            if payload.get("known_function"):
                _current_worker.post_result(
                    item_key=func,
                    data={
                        "known_function": payload["known_function"],
                        "known_address": payload.get("known_address"),
                        "confidence": payload.get("confidence", 1.0),
                        "match_source": payload.get("match_source", "bind_se"),
                        "explanation": payload.get("explanation"),
                    },
                    confidence=float(payload.get("confidence") or 1.0),
                    category=CAT_SIGNATURE,
                )
                id_posted += 1
        print(f"[bind_se] posted {eq_posted} semantic + {id_posted} identity hypotheses")


if __name__ == "__main__":
    xbin.start_worker()
