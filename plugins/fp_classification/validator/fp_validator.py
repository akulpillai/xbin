"""fp_classification validator -- vouches for claims two backends agree on.

The orchestrator auto-vouches only when two hypotheses are byte-identical
(hypothesis id = sha256 of the data dict). That never fires here: every producer
attaches its own engine-specific evidence (BN and angr disagree on instruction
counts even when they agree on the verdict). So semantic agreement has to be
checked explicitly, which is exactly a validator's job.

Vouches the top hypothesis when at least two *distinct* backends assert the same
(is_fp, kind) claim.
"""

import json

import xbin
from xbin import sdk as _sdk
from xbin.bind_helpers import CAT_FP
from xbin.fp_common import claim_of

_BACKEND = "fp_validator"


@xbin.plugin(
    name="fp_validator",
    category="fp_classification",
    is_validator=True,
    display_name="Float Detection Validator",
    description="Vouches for a float classification once two independent backends agree on the same verdict and kind.",
)
class FpValidator:
    def on_update(self, category, item_key, new_hypothesis, top_hypothesis):
        if category != CAT_FP:
            return
        # Never react to our own vouch.
        if (new_hypothesis or {}).get("backend") == _BACKEND:
            return

        w = _sdk._current_worker
        raw = w._redis.get(f"xbin:bb:{category}:{item_key}")
        if not raw:
            return
        hyps = json.loads(raw).get("hypotheses", [])
        if len(hyps) < 2:
            return

        top_claim = claim_of((top_hypothesis or {}).get("data"))
        if top_claim is None:
            return

        # Distinct backends asserting the same claim as the current top.
        backends = {h.get("backend") for h in hyps
                    if h.get("backend") != _BACKEND
                    and claim_of(h.get("data")) == top_claim}
        if len(backends) < 2:
            return

        # Already vouched? Our validation appears as a hypothesis from us.
        if any(h.get("backend") == _BACKEND for h in hyps):
            return

        print(f"[{_BACKEND}] {item_key}: {len(backends)} backends agree on "
              f"{top_claim} ({sorted(backends)}); vouching")
        w.post_validation(item_key=item_key, target_id="TOP", confidence=0.9)


if __name__ == "__main__":
    xbin.start_worker()
