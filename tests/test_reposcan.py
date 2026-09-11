"""Offline tests for the unified repo static scan."""
from __future__ import annotations

import os, tempfile

from deluluscan.reposcan import RepoScan

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _write(root, rel, content):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(content)


def _repo():
    d = tempfile.mkdtemp()
    # source with a dangerous call (SAST)
    _write(d, "app/main.py", "import os\nos.system('rm -rf ' + user_input)\n")
    # vulnerable Terraform (IaC)
    _write(d, "infra/main.tf", 'resource "aws_s3_bucket" "b" { acl = "public-read" }\n')
    # a Dockerfile (container)
    _write(d, "Dockerfile", "FROM ubuntu:latest\nUSER root\n")
    # a risky GitHub Actions workflow (CI/CD)
    _write(d, ".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: x/y@main\n")
    # an SBOM with Log4Shell (sbom)
    _write(d, "bom.json", '{"bomFormat":"CycloneDX","components":[{"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/x/log4j-core@2.14.1"}]}')
    return d


def test_all_analyzers_merge():
    res = RepoScan().scan(_repo())
    ran = set(res["analyzers"])
    check("sast ran", "sast" in ran, ran)
    check("iac ran", "iac" in ran, ran)
    check("container ran", "container" in ran, ran)
    check("cicd ran", "cicd" in ran, ran)
    check("sbom ran", "sbom" in ran, ran)
    sources = {f.detail.get("source", "") for f in res["findings"]}
    check("findings span multiple analyzers", len({s.split(".")[0] for s in sources if s}) >= 3, sources)


def test_specific_findings_present():
    finds = RepoScan().scan(_repo())["findings"]
    rules = {f.detail.get("rule") for f in finds}
    titles = " | ".join(f.title for f in finds)
    check("terraform public S3 present", "tf-s3-public-acl" in rules, rules)
    check("cicd unpinned action present", "gha-unpinned-action" in rules, rules)
    check("sbom Log4Shell present", any("Log4Shell" in f.title or f.detail.get("cve") == "CVE-2021-44228" for f in finds), titles)
    check("dockerfile finding present", any(f.detail.get("source", "").startswith("container")
          or "image" in (f.detail.get("rule") or "") or "docker" in (f.detail.get("rule") or "") for f in finds))


def test_enrichment_and_counts():
    res = RepoScan().scan(_repo())
    check("severity counts computed", sum(res["counts"].values()) == len(res["findings"]))
    check("priority attached", all("priority" in f.detail for f in res["findings"]))
    check("attack tags where mapped", any("attack" in f.detail for f in res["findings"]))


def test_payload_shape():
    p = RepoScan().payload(_repo())
    check("payload has findings + meta", "findings" in p and "meta" in p)
    check("meta records analyzers + scan_type", p["meta"]["scan_type"] == "repo-static"
          and isinstance(p["meta"]["analyzers"], list))
    check("findings are dicts", all(isinstance(f, dict) for f in p["findings"]))


def test_empty_repo_no_crash():
    with tempfile.TemporaryDirectory() as d:
        res = RepoScan().scan(d)
        check("empty repo -> no findings, no crash", res["findings"] == [])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
