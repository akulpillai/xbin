# LLM Arbiter plugin (ranker) -- thin layer over the self-contained `bind:latest`
# base image. Uses the base's openai client + Morpheus arbiter to reconcile
# competing identifications via the local ollama endpoint.
FROM bind:latest

USER root
RUN python3 -m pip install --no-cache-dir grpcio redis requests

COPY --chown=bind:bind src /opt/xbin_sdk
COPY --chown=bind:bind arbiter_worker.py /home/bind/arbiter_worker.py

ENV PYTHONPATH=/opt/xbin_sdk:/home/bind/Morpheus \
    MORPHEUS_ROOT=/home/bind/Morpheus \
    XBIN_ORCHESTRATOR=localhost:50051 \
    REDIS_HOST=localhost \
    END_POINT_URL=http://127.0.0.1:11434/v1 \
    END_POINT_MODEL=qwen2.5-coder:7b \
    END_POINT_APIKEY=ollama \
    BIND_ARBITER_LLM_MODE=on-conflict \
    PYTHONUNBUFFERED=1

USER bind
WORKDIR /home/bind/Morpheus
CMD ["python3", "/home/bind/arbiter_worker.py"]
