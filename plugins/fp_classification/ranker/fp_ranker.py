"""fp_classification ranker -- resolves arithmetic vs movement vs soft.

Two disagreements need deciding, and both were previously settled by an
unrecorded coin flip inside symbolic_regression's private filter:

1. ``arithmetic`` vs ``movement`` for the same function. Movement-only means the
   function shuffles float-shaped bits without computing anything; measured, it
   is the difference between precision 1.000 and 0.818. Arithmetic wins.
2. hardware ``arithmetic`` vs ``soft``. These come from anti-correlated detectors
   (Cohen kappa -0.10) and are not really in conflict -- a function can do both.
   Whichever is claimed, corroboration by more backends should win, so the score
   is driven primarily by agreement count.

Absolute score = kind weight + 0.5 per corroborating backend, +1.0 for a
2+-backend consensus (mirroring upstream's boundary_ranker heuristic).
"""

import json

import xbin
from xbin import sdk as _sdk
from xbin.bind_helpers import CAT_FP
from xbin.fp_common import KIND_ARITHMETIC, KIND_MOVEMENT, KIND_SOFT, claim_of

_BACKEND = "fp_ranker"

# Base weight per kind: how strongly the kind alone supports "does float math".
_KIND_WEIGHT = {
    KIND_ARITHMETIC: 1.0,   # computes a float in hardware -- measured precision 1.000
    KIND_SOFT: 1.0,         # calls a libgcc helper -- measured precision 0.957
    KIND_MOVEMENT: 0.5,     # only moves float bits -- weakest evidence
}


@xbin.plugin(
    name="fp_ranker",
    category="fp_classification",
    is_ranker=True,
    display_name="Float Detection Arbiter",
    description="Resolves competing float classifications, preferring computed-float and soft-float evidence over float data movement and rewarding cross-backend agreement.",
)
class FpRanker:
    def on_update(self, category, item_key, new_hypothesis, top_hypothesis):
        if category != CAT_FP:
            return
        if (new_hypothesis or {}).get("backend") == _BACKEND:
            return

        w = _sdk._current_worker
        raw = w._redis.get(f"xbin:bb:{category}:{item_key}")
        if not raw:
            return
        hyps = json.loads(raw).get("hypotheses", [])
        if not hyps:
            return

        # Score every distinct claim, then promote the best one.
        best = None
        for h in hyps:
            claim = claim_of(h.get("data"))
            if claim is None:
                continue
            kind = claim[1]
            backends = {o.get("backend") for o in hyps
                        if claim_of(o.get("data")) == claim
                        and o.get("backend") != _BACKEND}
            score = _KIND_WEIGHT.get(kind, 0.5) + 0.5 * len(backends)
            if len(backends) >= 2:
                score += 1.0
            if best is None or score > best[0]:
                best = (score, h, kind, sorted(b for b in backends if b))

        if best is None:
            return
        score, target, kind, backends = best
        if abs(score - float(target.get("score", 0.0))) <= 0.01:
            return  # already ranked

        print(f"[{_BACKEND}] {item_key}: '{kind}' from {backends} -> score {score:.2f}")
        w.update_rank(item_key=item_key, target_id=target["id"], new_score=score)


if __name__ == "__main__":
    xbin.start_worker()
