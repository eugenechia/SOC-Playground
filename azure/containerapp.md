# SOC-Playground — Azure Container Apps deployment

**Dedicated, isolated infrastructure.** SOC-Playground shares nothing with
SOC-Copilot. Provision its own ACR, its own Container App, its own storage and
secrets. It may live in the same resource group (`rg-soc-platform`, southeastasia)
but must reference none of SOC-Copilot's resources.

Placeholders below — adjust names to taste before running.

```
RG=rg-soc-platform
LOC=southeastasia
ACR=socplaygroundreg
APP=soc-playground
ENV=soc-playground-env
STG=socplaygroundstg
SHARE=models
```

## 1. Registry + image

```bash
az acr create -g $RG -n $ACR --sku Basic
az acr login -n $ACR
docker build -t $ACR.azurecr.io/soc-playground:latest .
docker push $ACR.azurecr.io/soc-playground:latest
```

Build on the Mac Studio. (If cross-arch, build linux/amd64:
`docker buildx build --platform linux/amd64 -t ... --push .`)

## 2. Azure Files share for model weights

The container FS is ephemeral. Weights MUST live on a mounted Azure Files share,
or every restart re-downloads gigabytes.

```bash
az storage account create -g $RG -n $STG -l $LOC --sku Standard_LRS
az storage share-rm create -g $RG --storage-account $STG -n $SHARE --quota 128
KEY=$(az storage account keys list -g $RG -n $STG --query '[0].value' -o tsv)
```

## 3. Container Apps environment + storage link

```bash
az containerapp env create -g $RG -n $ENV -l $LOC

az containerapp env storage set -g $RG -n $ENV \
  --storage-name models \
  --azure-file-account-name $STG \
  --azure-file-account-key "$KEY" \
  --azure-file-share-name $SHARE \
  --access-mode ReadWrite
```

## 4. Secrets

```bash
az containerapp secret set -g $RG -n $APP \
  --secrets app-password=<STRONG_PASSWORD> session-secret=$(openssl rand -hex 32)
```

(Or use Key Vault refs + managed identity and set `AZURE_KEYVAULT_URL`;
`app/secrets.py` resolves `APP_PASSWORD` → `app-password` kebab-case.)

## 5. Create the app (single replica, mount, env)

```bash
az containerapp create -g $RG -n $APP --environment $ENV \
  --image $ACR.azurecr.io/soc-playground:latest \
  --registry-server $ACR.azurecr.io \
  --target-port 8000 --ingress external \
  --min-replicas 1 --max-replicas 1 \
  --cpu 4 --memory 8Gi \
  --secrets app-password=<STRONG_PASSWORD> session-secret=$(openssl rand -hex 32) \
  --env-vars MODELS_DIR=/models HF_HOME=/models/.hf_cache \
             APP_PASSWORD=secretref:app-password \
             SESSION_SECRET=secretref:session-secret
```

Then add the volume + mount (via `az containerapp update --yaml` with a template
that references the `models` environment storage mounted at `/models`).

## Hard requirements / gotchas

- **`min=max=1`.** The SSE broker, model runtime and session store are in-process
  singletons. More than one replica fragments SSE topics and double-loads models.
- **Never set `DEV_AUTH_BYPASS`** on the app — it disables the password gate.
- **CPU/memory.** float32 ≈ 4 bytes/param. 4 vCPU / 8 GiB comfortably runs
  ≤ ~1.3B models; 3B (~12 GB) will OOM. Cap `MAX_MODEL_BYTES` accordingly.
- **Cold-load latency.** First use of a model reads GBs from the SMB share + CPU
  init — tens of seconds. The Workbench emits a "loading…" status before the
  first token; the model stays resident between turns.
- **No zero-downtime deploy.** Single replica means a redeploy briefly drops the
  app and clears in-memory chat history (acceptable — ephemeral by design).
