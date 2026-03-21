// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const { owner, repo } = context.repo;
  const sha = context.sha;

  const tag = await github.rest.git.updateRef({
    owner,
    repo,
    force: true,
    ref: "tags/unstable",
    sha,
  });
  console.log("Updated tag ref:", tag.data.url);
};
