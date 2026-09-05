# Publishing `threatcluster-mcp`

Two registries, one version, one tag. Both workflows fire on a `v*.*.*` tag and refuse to publish
if the tag disagrees with `python/pyproject.toml` / `node/package.json`.

## One-time setup

### PyPI (Trusted Publishing, no API token)

PyPI → account → **Publishing** → **Add a new pending publisher**:

| Field             | Value                                              |
|-------------------|----------------------------------------------------|
| PyPI project      | `threatcluster-mcp`                                |
| Owner             | `Jam0k` (or the org that holds this repo)          |
| Repository name   | `Threat-Intelligence-MCP`                                |
| Workflow filename | `publish-pypi.yml`                                 |
| Environment name  | `pypi`                                             |

Then GitHub → repo → **Settings → Environments → New environment** → `pypi`. Enable **Required reviewers**
(yourself) so every publish pauses for a click; optionally restrict deployment branches/tags to `v*`.

### npm (trusted publishing via OIDC, or a granular token)

Preferred — **trusted publishing** (npm ≥ 11.5, GitHub Actions OIDC, gives provenance for free):

1. Create the package once so it exists: `cd node && npm publish --access public` from a machine
   where you are logged in (or publish the first version with a token, below).
2. npmjs.com → package **threatcluster-mcp → Settings → Trusted publishing → Add GitHub Actions publisher**:
   organization/user `Jam0k`, repository `threatcluster-mcp`, workflow filename `publish-npm.yml`,
   environment `npm`.
3. GitHub → repo → **Settings → Environments** → `npm` (required reviewers recommended).

Fallback — **granular access token**: npmjs.com → Access Tokens → Generate → *Granular*, packages:
`threatcluster-mcp`, permission *Read and write*, bypass 2FA for automation. Store it as the repo secret
`NPM_TOKEN` and uncomment the `NODE_AUTH_TOKEN` line in `publish-npm.yml`. `--provenance` still works with
a token as long as the job has `id-token: write`.

## Every release

1. Bump the version in **both** `python/pyproject.toml` and `node/package.json` (same value).
2. Move the `[Unreleased]` notes in `CHANGELOG.md` to a dated `[X.Y.Z]` heading.
3. `python3 tools/sync_tools.py --check` (spec copies in sync), `cd python && pytest`, `cd node && npm test`.
4. Commit, tag, push:
   ```bash
   git commit -am "threatcluster-mcp vX.Y.Z"
   git tag vX.Y.Z && git push && git push --tags
   ```
5. Approve the `pypi` and `npm` deployments in the **Actions** tab.
6. Verify: `uvx threatcluster-mcp@X.Y.Z --version` and `npx -y threatcluster-mcp@X.Y.Z --version`.
7. Bump the version in `listings/server.json` and re-run the MCP registry publish (see `listings/`).

## Manual publish (if Actions are unavailable)

```bash
# PyPI
cd python && python -m build && python -m twine upload dist/*
# npm (provenance needs a CI OIDC token; locally it is a plain publish)
cd node && npm publish --access public
```

## Yanking

PyPI: project → Manage → Releases → **Yank** (never delete). npm: `npm deprecate threatcluster-mcp@X.Y.Z "reason"`
(unpublish is only allowed within 72 h and breaks pinned installs; deprecate instead).

## TestPyPI dry run

Add a pending publisher on https://test.pypi.org with the same fields, temporarily set
`repository-url: https://test.pypi.org/legacy/` on the publish step, tag `v0.1.0rc1`, and install with
`uvx --index-url https://test.pypi.org/simple/ threatcluster-mcp==0.1.0rc1 --version`.
