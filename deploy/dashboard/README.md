# Deluluscan dashboard — SSO-gated hosting (optional, self-hosted)

Host the Deluluscan security dashboard behind **Google SSO** on **your own** AWS/EKS,
instead of the public GitHub Pages file protected only by an AES password. This is an
optional template — Deluluscan works fine without it — for teams who want identity-based
access (auto-revoked on offboarding) to the report.

Everything here deploys to a dedicated `deluluscan` namespace and is parameterised by
placeholders you fill in for your own account/cluster/domain. Nothing is hardcoded to
any specific organization.

## Why this design

The dashboard is a **single static HTML file with no application server**, so it can't
own a login flow itself. The natural fit for a static site is **ALB-level OIDC**: the
Application Load Balancer redirects unauthenticated users to Google and only forwards
signed-in requests to nginx. Real SSO, zero app code.

| Option | Verdict |
|---|---|
| **ALB OIDC + nginx static** (this package) | ✅ Chosen — real Google SSO, no app, edge-enforced |
| oauth2-proxy sidecar | Fallback if your ALB controller lacks OIDC — more moving parts |
| App-level OAuth | ❌ Needs an app; overkill for a static file |
| IP-allowlist only | ❌ Not SSO; identity-independent |

Access is identity-based, so when someone leaves your org their Google account is
disabled and they lose the dashboard automatically. Once behind SSO the AES password is
optional — generate the dashboard **without** `--password` (SSO is the boundary).

## Files

- `Dockerfile` / `nginx.conf` — serve the one-file dashboard on :3000 with a `/healthz`
- `k8s/namespace.yaml` — the isolated `deluluscan` namespace
- `k8s/deployment.yaml` — nginx pod + service account
- `k8s/service.yaml` — NodePort for the ALB
- `k8s/ingress.yaml` — **ALB + Google OIDC** (the SSO gate)
- `k8s/oidc-secret.example.yaml` — template for the Google client id/secret (no real values)
- `build-and-push.sh` — generate → build → push to ECR → roll

## What you need to provide

You (or your platform team) supply these for **your own** infrastructure — none of it is
included here:

1. **kubectl access to an EKS cluster** — set your context via `--context <EKS_CONTEXT>`.
2. **An ECR repository** for the image, e.g.
   `<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/deluluscan/dashboard`, plus push access.
3. **A Google OAuth client** (id + secret) from your Google Workspace / Cloud console,
   consent screen set to **Internal** (this is what limits login to your workspace),
   redirect URI `https://<YOUR_DOMAIN>/oauth2/idpresponse`.
4. **DNS**: a record `<YOUR_DOMAIN>` → the ALB created by the ingress.
5. **An ACM certificate** for `<YOUR_DOMAIN>` (or a matching wildcard).
6. *(optional)* an **IP-allowlist security group** on the ALB for network-layer
   defence-in-depth.

Fill the `<ACCOUNT_ID>`, `<REGION>`, `<ACM_CERT_ARN>`, `<YOUR_DOMAIN>`, and (optional)
`<ALB_SG_ID>` placeholders in the manifests before applying.

## Deploy (first time)

```bash
# 1. create the OIDC secret from the Google client (never commit real values)
kubectl -n deluluscan create secret generic deluluscan-dashboard-oidc \
  --from-literal=clientId="$GOOGLE_CLIENT_ID" \
  --from-literal=clientSecret="$GOOGLE_CLIENT_SECRET"

# 2. build + push the image and apply the manifests
RESULTS=deluluscan-out/results.json \
ECR=<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/deluluscan/dashboard \
  ./build-and-push.sh

kubectl --context <EKS_CONTEXT> apply -f k8s/namespace.yaml
kubectl --context <EKS_CONTEXT> apply -f k8s/deployment.yaml -f k8s/service.yaml -f k8s/ingress.yaml
```

## Refresh after each scan

- **Manually:** re-run `build-and-push.sh` with the new `results.json`.
- **CI (automatic):** `.github/workflows/deploy-dashboard.yml` rebuilds the image, pushes
  it to ECR, and rolls the EKS deployment. It is `workflow_dispatch` + `workflow_call` and
  **no-ops until** you set the repo variables (`AWS_DEPLOY_ROLE_ARN`, `ECR_DASHBOARD_REPO`,
  `EKS_CLUSTER_NAME`), using an IAM role you own via GitHub OIDC.

If you don't use ECR/EKS, adapt the steps to your own registry and orchestrator — the only
Deluluscan-specific part is generating the static HTML (`python3 -m deluluscan.dashboard`).
