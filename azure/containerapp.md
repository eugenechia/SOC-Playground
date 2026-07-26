# SOC-Playground — Azure Container Apps deployment

**Dedicated, isolated infrastructure.** SOC-Playground shares nothing with
SOC-Copilot: its own resource group, ACR, Container App, storage and secrets.

## As deployed (2026-07-26)

| Thing | Value |
|---|---|
| Resource group | `rg-soc-playground` (southeastasia) — dedicated |
| ACR | `socplaygroundreg` (Basic, admin-enabled) |
| Image | `socplaygroundreg.azurecr.io/soc-playground:latest` (built via `az acr build --platform linux/amd64`) |
| Storage / share | `socplaygroundstg` / Azure Files share `models` (64 GiB), env-linked as `modelsmount`, mounted at `/models` |
| Environment | `soc-playground-env` |
| Container App | `soc-playground` — 2 vCPU / 4 GiB, `min=max=1`, ingress external :8000 |
| URL | https://soc-playground.bravesky-5d565b4f.southeastasia.azurecontainerapps.io |
| Auth | **Entra ID SSO** (MSAL). Own app registration `SOC-Playground` (appId `64fe8978-afc2-40ef-9496-4f15c78282ba`). Access gated to Entra security group **SOCplayground** (`dee6b941-934b-4ea2-9d69-c67712c4507c`) via the id_token `groups` claim. `DEV_AUTH_BYPASS` NOT set. |
| Secrets | `entra-client-secret`, `session-secret` (Container App secrets). |
| Integrations | Falcon/Sentinel/Jira/threat-intel **off** in cloud (no creds set) — tools degrade gracefully. Add creds as Container App secrets to enable. |

### Entra app registration (SOC-Playground)
- appId `64fe8978-afc2-40ef-9496-4f15c78282ba`, single-tenant (`AzureADMyOrg`), SP created.
- Web redirect URIs: `http://localhost:8200/auth/callback`, `https://<fqdn>/auth/callback` (+ the roots for post-logout).
- API permission: Microsoft Graph `User.Read` (delegated, self-consented at login — no admin grant).
- Token config: `groupMembershipClaims=SecurityGroup` (emits the `groups` claim used for gating).
- Client secret ("playground-prod2", 2y) → Container App secret `entra-client-secret`.
- Env on the app: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_REDIRECT_URI`, `ENTRA_ALLOWED_GROUP_ID`, `ENTRA_CLIENT_SECRET=secretref:entra-client-secret`.
- **Access:** only members of the SOCplayground group can sign in. Manage membership:
  `az ad group member add --group dee6b941-934b-4ea2-9d69-c67712c4507c --member-id <userObjectId>`.

### Redeploy a new image
```bash
az acr build --registry socplaygroundreg --image soc-playground:latest --platform linux/amd64 .
az containerapp update -g rg-soc-playground -n soc-playground \
  --image socplaygroundreg.azurecr.io/soc-playground:latest
```
The build honours `.dockerignore` (keeps `.venv`, `.env`, `.git`, weights out of the context).

### The /models mount (added via YAML patch, not the create flags)
`az containerapp create` didn't take the volume inline; the mount was added by
fetching the app YAML, injecting under `properties.template`:
```yaml
volumes:
- {name: models, storageType: AzureFile, storageName: modelsmount}
```
and on the container: `volumeMounts: [{volumeName: models, mountPath: /models}]`,
then `az containerapp update --yaml app.yaml`.

### Teardown (removes everything)
```bash
az group delete -n rg-soc-playground --yes --no-wait
```

---

## Reference / from-scratch recipe

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
