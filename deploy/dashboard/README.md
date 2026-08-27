# Deluluscan dashboard — SSO-gated hosting

Host the Deluluscan security dashboard behind **Google SSO** on the target's own AWS/EKS,
instead of the public GitHub Pages file protected only by an AES password.

Everything here lives in the **Deluluscan repo** and deploys to a **new `deluluscan`
namespace**. It touches nothing belonging to other tenants (e.g. dotusage) — it
only *borrows the pattern* dotusage established (EKS + ALB + ECR on the corp
account).

## Why this design (the researched choice)

dotusage authenticates with **app-level Google OAuth** (its FastAPI app owns the
login) and puts an **IP-allowlist security group** on the ALB. The Deluluscan
dashboard is a **single static HTML file with no app**, so it can't reuse
app-level auth. The best fit for a static site is **ALB-level OIDC** — the ALB
itself redirects unauthenticated users to Google and only forwards signed-in
requests to nginx. Real SSO, **zero app code**, same infra shape.

| Option | Verdict |
|---|---|
| **ALB OIDC + nginx static** (this package) | ✅ Chosen — real Google SSO, no app, edge-enforced |
| oauth2-proxy sidecar | Fallback if the ALB controller lacks OIDC — more moving parts |
| App-level OAuth (like dotusage) | ❌ Needs an app; overkill for a static file |
| IP-allowlist only | ❌ Not SSO; identity-independent |

**Access is identity-based**, so when someone leaves the target their Google account
is disabled and they lose the dashboard automatically — the continuity/offboarding
property a shared AES password can't give. Once behind SSO the password is
optional; generate the dashboard **without** `--password` (SSO is the boundary).

## Files

- `Dockerfile` / `nginx.conf` — serve the one-file dashboard on :3000 with a `/healthz`
- `k8s/namespace.yaml` — the isolated `deluluscan` namespace
- `k8s/deployment.yaml` — nginx pod + service account
- `k8s/service.yaml` — NodePort for the ALB
- `k8s/ingress.yaml` — **ALB + Google OIDC** (the SSO gate)
- `k8s/oidc-secret.example.yaml` — template for the Google client id/secret (no real values)
- `build-and-push.sh` — generate → build → push to ECR → roll

## Access needed (what to request; most is platform/security team)

You (or whoever deploys) will need — I do **not** have and cannot obtain any of this from here:

1. **kubectl access to the corp EKS cluster** (dotusage uses context
   `k8s-internal-corporate-sites`), via SDM. — *platform team*
2. **An ECR repo** for the image, e.g. `<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/deluluscan/dashboard`,
   plus push access. dotusage's account is `948170117212`. — *platform team (Terraform)*
3. **A Google OAuth client** (id + secret) from the target Google Workspace /
   Cloud console, consent screen set to **Internal**, redirect URI
   `https://deluluscan.target.cloud/oauth2/idpresponse`. — *Workspace/security admin*
4. **DNS**: a Route53 record `deluluscan.target.cloud` → the ALB. — *platform team*
5. **ACM certificate** for `deluluscan.target.cloud` (or reuse a `*.target.cloud` wildcard). — *platform team*
6. *(optional)* an **IP-allowlist SG** on the ALB, mirroring dotusage. — *platform team*

Fill the `<ACCOUNT_ID>`, `<ACM_CERT_ARN>`, host, and (optional) `<ALB_SG_ID>`
placeholders in the manifests before applying.

## Deploy (first time)

```bash
# 1. create the OIDC secret from the Google client (never commit real values)
kubectl -n deluluscan create secret generic deluluscan-dashboard-oidc \
  --from-literal=clientId="$GOOGLE_CLIENT_ID" \
  --from-literal=clientSecret="$GOOGLE_CLIENT_SECRET"

# 2. build + push the image and apply the manifests
RESULTS=deluluscan-out/results.json \
ECR=<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/deluluscan/dashboard \
  ./build-and-push.sh

kubectl --context k8s-internal-corporate-sites apply -f k8s/namespace.yaml
kubectl --context k8s-internal-corporate-sites apply -f k8s/deployment.yaml -f k8s/service.yaml -f k8s/ingress.yaml
```

## Refresh after each scan

Two ways:

- **Manually:** re-run `build-and-push.sh` with the new `results.json`.
- **CI (automatic):** `.github/workflows/deploy-dashboard.yml` rebuilds the image,
  pushes it to ECR, and rolls the EKS deployment. It is `workflow_dispatch` +
  `workflow_call` and **no-ops until** the platform team sets the repo vars
  (`AWS_DEPLOY_ROLE_ARN`, `ECR_DASHBOARD_REPO`, `EKS_CLUSTER_NAME`) — it uses a
  Deluluscan-owned IAM role, never dotusage's. Once wired, the nightly scan can
  `uses:` it to refresh the SSO dashboard after every run:

  ```yaml
  jobs:
    publish:
      uses: ./.github/workflows/deploy-dashboard.yml
      with: { results_path: ci-out/data/latest.json }
  ```

The published GitHub Pages copy can be retired once this is live.
