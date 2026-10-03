# Releasing agent-tool-guardrails

## One-time setup

1. **PyPI account** at https://pypi.org/account/register/ with two-factor authentication enabled
   (required for uploads). Optionally the same on https://test.pypi.org for rehearsals.
2. **Pending trusted publisher** (creates the project on first publish, no API token needed):
   PyPI → account sidebar → *Publishing* → *Add a new pending publisher* with
   PyPI project name `agent-tool-guardrails`, owner `nunar-nexus-forge`, repository `agent-tool-guardrails`,
   workflow filename `release.yml`, environment name `pypi`.
3. **GitHub environment**: repository → *Settings* → *Environments* → create `pypi`
   (optionally add yourself as a required reviewer so every publish needs a click).

## Every release

1. Bump the version in `pyproject.toml` and `src/typed_rails/_version.py`, move the *Unreleased*
   notes in `CHANGELOG.md` under the new version with today's date, and update `version` and
   `date-released` in `CITATION.cff`.
2. Run the full check and a local build:

   ```bash
   make check          # ruff + mypy + pytest inside ./.venv
   uv build            # wheel + sdist in dist/
   ```

3. Commit and push: `git commit -am "Release vX.Y.Z" && git push`.
4. Tag the release; the tag triggers `.github/workflows/release.yml`, which builds and
   publishes through PyPI trusted publishing:

   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

5. Watch the *Release* workflow under *Actions*. When it is green, create a GitHub Release
   from the tag and paste the changelog section into it.
6. Verify from a clean environment:

   ```bash
   uv venv /tmp/verify && VIRTUAL_ENV=/tmp/verify uv pip install "agent-tool-guardrails==X.Y.Z"
   /tmp/verify/bin/python -c "import typed_rails; print(typed_rails.__version__)"
   ```

Versions on PyPI are permanent: a broken release is followed by a patch release, never re-uploaded.

## Manual fallback (no GitHub Actions)

```bash
uv build
uv publish --token pypi-XXXXXXXX                       # account-scoped token for the first upload
uv publish --publish-url https://test.pypi.org/legacy/ --token pypi-XXXX   # TestPyPI rehearsal
```
