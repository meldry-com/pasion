// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const { owner, repo } = context.repo;
  const branch = process.env.BRANCH;
  const sha = process.env.SHA;
  if (!sha) throw new Error("SHA is not defined");

  await github.rest.git.updateRef({
    owner,
    repo,
    ref: `heads/${branch}`,
    sha,
  });
  console.log(`Updated branch ${branch} to ${sha}`);
};
