## What & why

<!-- What does this change and why? Link any related issue (e.g. Closes #123). -->

## How I verified it

<!-- Which test suites did you run? Add new tests for new behaviour. -->

```
python3 -m tests.test_...
```

## Checklist

- [ ] Tests added/updated and the relevant suite(s) pass
- [ ] Offline-testable (network/browser boundaries are dependency-injected)
- [ ] Keeps the authorization boundary + detection-only / evidence-first rules intact
- [ ] No real targets, secrets, or third-party data in code/tests/fixtures/commits
- [ ] If `dashboard/src` changed: rebuilt `deluluscan/assets/dashboard_bundle.html`
