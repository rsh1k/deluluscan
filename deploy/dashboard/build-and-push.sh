#!/usr/bin/env bash
# Build the Deluluscan dashboard image and push it to ECR, then roll the deployment.
# Mirrors dotusage's manual-deploy flow. Requires: docker, awscli, kubectl access
# to the corp cluster, and push access to the ECR repo (see README "Access needed").
#
# Usage:
#   RESULTS=deluluscan-out/results.json \
#   ECR=<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/deluluscan/dashboard \
#   CLUSTER=k8s-internal-corporate-sites \
#   ./build-and-push.sh
set -euo pipefail
: "${RESULTS:?set RESULTS=path/to/results.json}"
: "${ECR:?set ECR=<account>.dkr.ecr.us-east-1.amazonaws.com/deluluscan/dashboard}"
: "${CLUSTER:=k8s-internal-corporate-sites}"
REGION="${REGION:-us-east-1}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[1/5] generate the dashboard (plaintext — SSO is the boundary once behind the ALB)"
python3 -m deluluscan.dashboard "$RESULTS" "$HERE/dashboard.html"

echo "[2/5] docker build"
docker build -t "$ECR:latest" "$HERE"

echo "[3/5] ECR login"
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "${ECR%%/*}"

echo "[4/5] push"
docker push "$ECR:latest"

echo "[5/5] roll deployment"
kubectl --context "$CLUSTER" -n deluluscan rollout restart deployment deluluscan-dashboard
kubectl --context "$CLUSTER" -n deluluscan rollout status  deployment deluluscan-dashboard
echo "done — https://deluluscan.target.cloud"
