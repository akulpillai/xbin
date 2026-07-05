# BIND-SE plugin -- thin layer over the self-contained `bind:latest` base image
# (built from the Morpheus submodule via scripts/build_bind_base.sh).
FROM bind:latest

USER root
RUN python3 -m pip install --no-cache-dir grpcio redis requests

COPY --chown=bind:bind src /opt/xbin_sdk
COPY --chown=bind:bind bind_se_worker.py /home/bind/bind_se_worker.py

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
CMD ["python3", "/home/bind/bind_se_worker.py"]
