"""LLM Arbiter xbin plugin (ollama-as-ranker).

This is xbin's "agentic arbitration" role, filled by Morpheus's LLM arbiter.
As an xbin *ranker* it watches the blackboard and, per function, reconciles the
competing identifications from fid / ghidriff / bind_se:

  * agreement / single-source  -> deterministically boost the consensus pick.
  * conflict                   -> ask the local LLM (Morpheus arbiter) to pick
                                  the winner, then boost that hypothesis.

Winners are boosted to a fixed score (not a relative bump) so the re-rank
converges instead of escalating on each rebroadcast.
"""

import json
import os

import xbin
import xbin.sdk as _sdk
from xbin.bind_helpers import CAT_SIGNATURE, CAT_EQUATION

_LLM_MODE = os.environ.get("BIND_ARBITER_LLM_MODE", "on-conflict")  # always | on-conflict | never

_SCORE_CONSENSUS = 2.0   # agreement, or an LLM-confirmed conflict winner
_SCORE_SINGLE = 1.5      # only one tool named the function


@xbin.plugin(
    name="bind_arbiter",
    category="signature_matching",
    is_ranker=True,
    display_name="LLM Arbiter (ollama)",
    description="Reconciles competing identifications per function; on conflict the local LLM picks the winner, which is then boosted on the board.",
)
class BindArbiter:
    def on_update(self, category, item_key, new_hypothesis, top_hypothesis):
        if category not in (CAT_SIGNATURE, CAT_EQUATION):
            return
        try:
            self._arbitrate(category, item_key)
        except Exception as e:
            print(f"[bind_arbiter] error on {category}/{item_key}: {e}")

    def _arbitrate(self, category, item_key):
        from bind_jobs.arbiter_core import classify

        w = _sdk._current_worker
        raw = w._redis.get(f"xbin:bb:{category}:{item_key}")
        if not raw:
            return
        state = json.loads(raw)
        hyps = state.get("hypotheses", [])
        if len(hyps) < 2:
            return  # nothing to reconcile yet

        # Act at most once per item: if a hypothesis already carries our consensus
        # score, we've decided -- skip (also stops re-ranking our own broadcast and
        # repeated LLM calls).
        if any(float(h.get("score", 0.0)) >= _SCORE_CONSENSUS - 0.01 for h in hyps):
            return

        tool_results = {
            h["backend"]: {
                "client": h["backend"],
                "func": item_key,
                "status": "success",
                "payload": h.get("data") or {},
            }
            for h in hyps
        }
        cls = classify(tool_results, {})
        chosen = cls.get("chosen")
        if not chosen:
            return  # expression-only / no-name -> no identity to arbitrate

        classification = cls.get("classification")
        winner_name = chosen["name"]
        target_score = _SCORE_SINGLE if classification == "single-source" else _SCORE_CONSENSUS

        if classification == "conflict" and _LLM_MODE in ("always", "on-conflict"):
            llm_name = self._llm_winner(item_key, tool_results)
            if llm_name:
                winner_name = llm_name

        target = self._find(hyps, winner_name)
        if not target:
            return
        if abs(float(target.get("score", 0.0)) - target_score) <= 0.01:
            return
        print(f"[bind_arbiter] {category}/{item_key}: {classification} -> '{winner_name}' (score {target_score})")
        w.update_rank(item_key, target["id"], target_score)

    def _llm_winner(self, item_key, tool_results):
        from bind_jobs.arbiter_core import _load_arbiter

        try:
            verdict = _load_arbiter().arbitrate(item_key, tool_results)
        except Exception as e:
            print(f"[bind_arbiter] LLM unavailable ({e}); using deterministic pick")
            return None
        print(f"[bind_arbiter] LLM verdict for {item_key}:\n{verdict}")
        for line in verdict.splitlines():
            if line.strip().lower().startswith("consolidated identification"):
                return line.split(":", 1)[1].strip()
        return None

    @staticmethod
    def _find(hyps, name):
        from bind_jobs.arbiter_core import _norm_name

        target = _norm_name(name)
        for h in hyps:
            nm = (h.get("data") or {}).get("known_function")
            if nm and _norm_name(nm) == target:
                return h
        return None


if __name__ == "__main__":
    xbin.start_worker()
