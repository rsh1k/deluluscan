# Hand-off — deploy the Deluluscan dashboard behind Google SSO

**Goal:** replace the public GitHub Pages dashboard (protected only by a shared
AES password) with an SSO-gated copy on the target's own AWS/EKS, so access is tied to
company Google identity (auto-revoked on offboarding) and the tool outlives any
one person.

**Owner going forward:** the target Security + Platform teams.
**Everything code-side is done and in this repo** (`deploy/dashboard/` +
`.github/workflows/deploy-dashboard.yml`). The remaining work is AWS/Google
provisioning that only the platform/security teams can do — checklist below.

Design (for context): the dashboard is a single static HTML file, so auth is
enforced at the **ALB via Google OIDC** (redirect to Google, only signed-in
requests reach nginx). No app, no server-side code. Pattern borrowed from
`the target/dotusage`; **nothing in dotusage was or should be modified.**

---

## Provisioning checklist (platform / security)

Known corp values (from dotusage, confirm they apply): AWS account `948170117212`,
region `us-east-1`, EKS context `k8s-internal-corporate-sites`.

- [ ] **1. ECR repo** — create `deluluscan/dashboard`
      (`948170117212.dkr.ecr.us-east-1.amazonaws.com/deluluscan/dashboard`). *(Terraform)*
- [ ] **2. GitHub Actions IAM role** — a `deluluscan-github-actions` role whose trust
      policy allows OIDC from repo `the target/deluluscan`, with permissions to push to the
      ECR repo (1) and run `eks update-kubeconfig` + rollout on the cluster.
      **Do not reuse dotusage's role.** *(Terraform — mirror dotusage's
      `infrastructure/github-actions.tf`, scoped to this repo)*
- [ ] **3. Google OAuth client** — in the target Google Cloud / Workspace console:
      - OAuth **consent screen = Internal** (this is what limits login to
        `example.com` accounts; ALB OIDC alone accepts any Google account).
      - Authorized redirect URI: `https://deluluscan.target.cloud/oauth2/idpresponse`
      - Note the **client id + secret** for step 6. *(Workspace/security admin)*
- [ ] **4. DNS** — Route53 record `deluluscan.target.cloud` → the ALB created by the
      ingress. *(Platform)*
- [ ] **5. ACM certificate** for `deluluscan.target.cloud` (or confirm a `*.target.cloud`
      wildcard exists); put its ARN in `k8s/ingress.yaml`. *(Platform)*
- [ ] **6. (optional) IP-allowlist SG** on the ALB, mirroring dotusage, for
      network-layer defence-in-depth; put its id in `k8s/ingress.yaml`. *(Platform)*

## Repo configuration (after 1–2 exist)

- [ ] Set repo **Variables** (Settings → Secrets and variables → Actions →
      Variables) so `deploy-dashboard.yml` activates:
      - `AWS_DEPLOY_ROLE_ARN` = the role from step 2
      - `ECR_DASHBOARD_REPO`  = the repo from step 1
      - `EKS_CLUSTER_NAME`    = the corp cluster name
      - `AWS_REGION`          = `us-east-1` (optional; default)

## First deploy

Fill the placeholders in `k8s/` (`<ACCOUNT_ID>`, `<ACM_CERT_ARN>`, host, optional
`<ALB_SG_ID>`), then, with kubectl access to the cluster (via SDM):

```bash
# OIDC secret from the Google client (never commit real values)
kubectl -n deluluscan create secret generic deluluscan-dashboard-oidc \
  --from-literal=clientId="$GOOGLE_CLIENT_ID" \
  --from-literal=clientSecret="$GOOGLE_CLIENT_SECRET"

# build+push the first image and apply the manifests
RESULTS=deluluscan-out/results.json \
ECR=948170117212.dkr.ecr.us-east-1.amazonaws.com/deluluscan/dashboard \
  ./build-and-push.sh

kubectl --context k8s-internal-corporate-sites apply -f k8s/namespace.yaml
kubectl --context k8s-internal-corporate-sites apply \
  -f k8s/deployment.yaml -f k8s/service.yaml -f k8s/ingress.yaml
```

## Verify

- [ ] `https://deluluscan.target.cloud` redirects to Google sign-in.
- [ ] A `@example.com` account reaches the dashboard; a non-target Google account
      is refused (confirms the Internal consent-screen restriction).
- [ ] `kubectl -n deluluscan get pods` shows `deluluscan-dashboard` Running and Ready.

## Ongoing operation

- **Refresh:** the nightly scan (`.github/workflows/nightly-scan.yml`, currently
  disabled) can call `deploy-dashboard.yml` after producing results to rebuild and
  roll the dashboard automatically. Or run `deploy-dashboard.yml` manually / use
  `build-and-push.sh`.
- **Retire** the public `docs/dashboard.html` (GitHub Pages) once the SSO copy is
  confirmed working, so there's a single, access-controlled source of truth.
- The AES `--password` is optional once behind SSO; the deploy path generates the
  dashboard without one (SSO is the boundary).

## Escalation / questions

Design rationale and alternatives are in `README.md` (same folder). The scanner,
report format, and engagement-memory behaviour are documented in the repo's
top-level `CLAUDE.md` and the `.claude/skills/deluluscan-audit` skill.
