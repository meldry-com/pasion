# Gitea workflows

These workflows are for Gitea Actions only. Gitea will use `.gitea/workflows/`,
while GitHub continues to use `.github/workflows/`.

Optional variables and secrets:

- `REGISTRY_USER` / `REGISTRY_TOKEN`: enables pushes to the Gitea container registry
- `DOCKERHUB_USER` / `DOCKERHUB_TOKEN`: enables pushes to Docker Hub
- `DOCKERHUB_NAMESPACE`: optional Docker Hub namespace override
- `CODECOV_TOKEN`: enables coverage upload
- `LOCALAZY_WRITE_KEY`: enables Localazy upload/download workflows

Notes:

- Gitea artifact upload uses `christopherhx/gitea-upload-artifact@v4`
  instead of GitHub's `actions/upload-artifact@v4+`
- The Gitea image build runs the release `amd64` and `arm64` images in
  parallel, then publishes a multi-arch manifest list after both
  per-architecture builds finish
- Each architecture also gets its own published tags such as `main-amd64`,
  `main-arm64`, and `sha-<commit>-amd64`
- The `arm64` image job uses a native runner labeled `ubuntu-24.04-arm64`
  instead of QEMU emulation
- Gitea workflows intentionally do not use `mozilla-actions/sccache-action`,
  because that action expects GitHub cache token support that is not available
  in standard Gitea Actions runners
- The Gitea docs workflow validates and uploads the generated site artifact,
  but does not try to deploy GitHub Pages
- The Gitea translation download workflow commits changes back to the current
  branch instead of opening a GitHub pull request
