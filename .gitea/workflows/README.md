# Gitea workflows

These workflows are for Gitea Actions only. Gitea will use `.gitea/workflows/`,
while GitHub continues to use `.github/workflows/`.

Optional variables and secrets:

- `CONTAINER_IMAGE`: target image name for `.gitea/workflows/build.yaml`
  - Default: `ghcr.io/taidge/pasion`
- `REGISTRY_USERNAME` / `REGISTRY_PASSWORD`: enables Docker image pushes
- `CODECOV_TOKEN`: enables coverage upload
- `LOCALAZY_WRITE_KEY`: enables Localazy upload/download workflows

Notes:

- Gitea artifact upload uses `christopherhx/gitea-upload-artifact@v4`
  instead of GitHub's `actions/upload-artifact@v4+`
- Gitea workflows intentionally do not use `mozilla-actions/sccache-action`,
  because that action expects GitHub cache token support that is not available
  in standard Gitea Actions runners
- The Gitea docs workflow validates and uploads the generated site artifact,
  but does not try to deploy GitHub Pages
- The Gitea translation download workflow commits changes back to the current
  branch instead of opening a GitHub pull request
