# fp_classification/angr -- thin layer over the self-contained `bind:latest` base
# NOTE: this producer needs only angr + capstone, so it is the fp_classification
# producer that can move to the public repo on a slim base image once it no longer
# imports bind_helpers/bind_jobs (upstream keeps Binary-Ninja-dependent plugins out).
# image (built by scripts/build_bind_base.sh from the Morpheus submodule). The
# heavy analysis stack lives in the base; here we add only the xbin SDK transport
# and the worker.
FROM bind:latest

USER root
# The base ships the analysis stack but not the xbin transport deps.
RUN python3 -m pip install --no-cache-dir grpcio redis requests

# xbin SDK: the orchestrator injects the project's src/ into the build context.
COPY --chown=bind:bind src /opt/xbin_sdk
COPY --chown=bind:bind fp_angr_worker.py /home/bind/fp_angr_worker.py

ENV PYTHONPATH=/opt/xbin_sdk:/home/bind/Morpheus \
    MORPHEUS_ROOT=/home/bind/Morpheus \
    XBIN_ORCHESTRATOR=localhost:50051 \
    REDIS_HOST=localhost \
    PYTHONUNBUFFERED=1

USER bind
WORKDIR /home/bind/Morpheus
CMD ["python3", "/home/bind/fp_angr_worker.py"]
