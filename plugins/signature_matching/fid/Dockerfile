# FID plugin -- thin layer over the self-contained `bind:latest` base image
# (built from the Morpheus submodule via scripts/build_bind_base.sh). The heavy
# analysis stack (Ghidra + Binary Ninja + bind_se) lives in the base; here we
# only add the xbin SDK transport and the worker.
FROM bind:latest

USER root
# The base ships the analysis stack but not the xbin transport deps.
RUN python3 -m pip install --no-cache-dir grpcio redis requests

# xbin SDK: the orchestrator injects the project's src/ into the build context.
COPY --chown=bind:bind src /opt/xbin_sdk
COPY --chown=bind:bind fid_worker.py /home/bind/fid_worker.py

ENV PYTHONPATH=/opt/xbin_sdk:/home/bind/Morpheus \
    MORPHEUS_ROOT=/home/bind/Morpheus \
    XBIN_ORCHESTRATOR=localhost:50051 \
    REDIS_HOST=localhost \
    END_POINT_URL=http://127.0.0.1:11434/v1 \
    END_POINT_MODEL=qwen2.5-coder:7b \
    END_POINT_APIKEY=ollama \
    PYTHONUNBUFFERED=1

USER bind
WORKDIR /home/bind/Morpheus
CMD ["python3", "/home/bind/fid_worker.py"]
