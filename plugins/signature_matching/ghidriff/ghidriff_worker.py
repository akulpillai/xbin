"""Ghidriff / BSim xbin plugin.

Wraps Morpheus's ghidriff racing client: at startup it binary-diffs the target
against a symbolized reference (upload a ``<binary>.reference`` sibling, else the
baked default), caches the recovered name matches, and posts each confident one
to the ``signature_matching`` blackboard.
"""

import os

import xbin
from xbin.bind_helpers import CAT_SIGNATURE, prepare_config


@xbin.plugin(
    name="ghidriff",
    category="signature_matching",
    display_name="Ghidriff / BSim diff",
    description="Binary-diffs the target against a symbolized reference (Ghidra ghidriff + BSim) to port over known function names.",
)
class GhidriffPlugin:
    def on_new_binary(self, binary_path, requested_goals):
        if CAT_SIGNATURE not in (requested_goals or []):
            print(f"[ghidriff] {CAT_SIGNATURE} not requested; skipping {os.path.basename(binary_path)}")
            return

        from bind_jobs.clients.ghidriff_client import GhidriffClient
        from bind_jobs.util import client_output_dir, norm_addr

        config, _ = prepare_config(binary_path)
        out = client_output_dir(config, "ghidriff")
        client = GhidriffClient("http://unused", out, config)

        print(f"[ghidriff] diffing {os.path.basename(binary_path)} against {config.get('signature_match_binary')} ...")
        client.setup()

        posted = 0
        for addr in list(client.cache.keys()):
            res = client.handle(addr) or {}
            if res.get("status") != "success":
                continue
            payload = res["payload"]
            xbin.post_result(
                item_key=norm_addr(addr),
                data=payload,
                confidence=float(payload.get("confidence") or 0.0),
            )
            posted += 1
        print(f"[ghidriff] posted {posted} identifications to the blackboard")


if __name__ == "__main__":
    xbin.start_worker()
