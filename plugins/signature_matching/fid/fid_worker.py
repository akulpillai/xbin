"""FID (Ghidra Function ID) xbin plugin.

Wraps Morpheus's fid racing client: at startup it matches the whole target
binary against the configured .fidb databases, then posts each confident
identification to the ``signature_matching`` blackboard (keyed by function
address, competing with ghidriff / bind_se).
"""

import os

import xbin
from xbin.bind_helpers import CAT_SIGNATURE, prepare_config


@xbin.plugin(
    name="fid",
    category="signature_matching",
    display_name="FID (Ghidra Function ID)",
    description="Matches functions against Ghidra Function ID (.fidb) databases of known library code.",
)
class FidPlugin:
    def on_new_binary(self, binary_path, requested_goals):
        if CAT_SIGNATURE not in (requested_goals or []):
            print(f"[fid] {CAT_SIGNATURE} not requested; skipping {os.path.basename(binary_path)}")
            return

        from bind_jobs.clients.fid_client import FidClient
        from bind_jobs.util import client_output_dir, norm_addr

        config, _ = prepare_config(binary_path)
        out = client_output_dir(config, "fid")
        client = FidClient("http://unused", out, config, os.path.join(out, "ghidra_proj"))

        print(f"[fid] running Function ID matching over {os.path.basename(binary_path)} ...")
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
        print(f"[fid] posted {posted} identifications to the blackboard")


if __name__ == "__main__":
    xbin.start_worker()
