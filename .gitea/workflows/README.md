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
- Gitea CI restores Cargo registry/git data and the workspace `target/`
  directory via `actions/cache@v3`
- The partitioned Rust test job compiles a `nextest` archive once, uploads it
  as a Gitea artifact, and reuses it across all test partitions
- The Gitea image build runs the release `amd64` and `arm64` images in
  parallel, then publishes a multi-arch manifest list after both
  per-architecture builds finish
- Each architecture also gets its own published tags such as `main-amd64`,
  `main-arm64`, and `sha-<commit>-amd64`
- When `REGISTRY_USER` / `REGISTRY_TOKEN` are configured, the Gitea image
  build also pulls and refreshes registry-backed Buildx cache layers
- The `arm64` image job targets the `ubuntu-24.04-arm64` runner label and
  relies on Docker's `linux/arm64` emulation support when that label is
  backed by an x86_64 runner
- Gitea workflows intentionally do not use `mozilla-actions/sccache-action`.
  They rely on the runner's `actions/cache` endpoint instead, because that
  works with standard Gitea Actions runners
- The Gitea docs workflow validates and uploads the generated site artifact,
  but does not try to deploy GitHub Pages
- The Gitea translation download workflow commits changes back to the current
  branch instead of opening a GitHub pull request
