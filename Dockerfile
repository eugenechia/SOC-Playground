FROM python:3.12-slim

WORKDIR /srv

# CPU-only inference: keep torch off the CUDA wheels and speed up HF pulls.
ENV HF_HUB_ENABLE_HF_TRANSFER=1 \
    TRANSFORMERS_NO_ADVISORY_WARNINGS=1 \
    OMP_NUM_THREADS=4 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
# --extra-index-url points pip at the CPU torch wheels; PyPI supplies the rest.
RUN pip install --no-cache-dir \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    -r requirements.txt

COPY app/ app/
COPY models_engine/ models_engine/
COPY web/ web/
COPY tasks/ tasks/

# Non-root. /models is the mount point for the Azure Files share (weights persist
# there, NOT in the ephemeral container filesystem).
RUN useradd --create-home appuser && mkdir -p /models && chown appuser /models
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
