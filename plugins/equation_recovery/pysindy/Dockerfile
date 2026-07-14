# pysindy (BIND binary->equation) plugin -- thin layer over the self-contained
# `pysindy:latest` base (= bind:latest + the pysyndy submodule tree), built
# out-of-band by scripts/build_pysindy_base.sh. Binary Ninja / QEMU / FastDyn /
# Ghidra / numpy come from bind:latest; the recovery core lives at
# /home/bind/pysyndy. Like the other equation_recovery plugins this is built
# in-tree by the orchestrator (no .xbin-prebuilt marker); it only needs
# pysindy:latest present.
FROM pysindy:latest

USER root
RUN python3 -m pip install --no-cache-dir grpcio redis requests

COPY --chown=bind:bind src /opt/xbin_sdk
COPY --chown=bind:bind pysindy_worker.py /home/bind/pysindy_worker.py

ENV PYTHONPATH=/opt/xbin_sdk:/home/bind/Morpheus:/home/bind/pysyndy/binja_scripts \
    MORPHEUS_ROOT=/home/bind/Morpheus \
    PYSINDY_ROOT=/home/bind/pysyndy \
    XBIN_ORCHESTRATOR=localhost:50051 \
    REDIS_HOST=localhost \
    END_POINT_URL=http://127.0.0.1:11434/v1 \
    END_POINT_MODEL=qwen2.5-coder:7b \
    END_POINT_APIKEY=ollama \
    PYTHONUNBUFFERED=1

USER bind
WORKDIR /home/bind/Morpheus
CMD ["python3", "/home/bind/pysindy_worker.py"]
