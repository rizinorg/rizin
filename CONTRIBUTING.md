# How to report issues

Before reporting an issue with GitHub, be sure that:
* You are using the latest released version of Rizin or the latest git version
* You are using a clean installation
* The issue was not already reported

When the above conditions are satisfied, feel free to submit an issue while
trying to be as precise as possible. If you can, provide the problematic binary,
the steps to reproduce the error and a backtrace in case of SEGFAULTs. Try to
follow the issue template that comes by default. Any information will help to
fix the problem.

# How to contribute

There are a few guidelines that we need contributors to follow so that we can
try to keep the codebase consistent and clean.

## Getting Started

* Make sure you have a GitHub account and solid ability to use `git`.
* Fork the repository on GitHub.
* Create a topic branch from `dev`. Please avoid working directly on the `dev` branch.
* Make commits of logical units.
* Be sure to follow the CODINGSTYLE (more on this in [DEVELOPERS.md][]).
* Submit the Pull Request(PR) on Github.
* When relevant, write a test in [test/](test).

> [!IMPORTANT]
> AI tools must not be used to fix issues labelled `good first issue`.
> These issues are generally not urgent, and are intended to be learning opportunities for new contributors to get familiar with the codebase.
> Whether you are a newcomer or not, fully automating the process of fixing this issue squanders the learning opportunity and doesn't add much value to the project.
> **Using AI tools to fix issues labelled as "good first issues" is forbidden**.

## Requirements for new contributors

Due to the high number of AI-generated contributions,
we raised the standard for new contributors.

New contributors must ensure their code changes are fully covered by tests
(excluding error-handling conditions) and that the CI is green.

Local testing is _not_ sufficient!

Rizin has different kind of tests in the `test/` subdirectory. Notable ones are:
- `test/db/asm/`: Assembly and disassembly tests.
- `test/db/cmd/`: Command tests.
- `test/unit/`: Unit tests for single functions and modules.
- `test/integration/`: Integration tests of the API.

To get more help about testing please see [test/README.md](test/README.md).

To test your changes against the CI, you can open a PR as a
[Draft](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/changing-the-stage-of-a-pull-request)
and mark it "Ready for review" once it meets the requirement.

> [!IMPORTANT]
> If this requirement is not met, we won't review the PR and will close it
> if there are no visible attempts to meet it.

## Rebasing onto updated dev

Every so often, your PR will lag behind `dev` and get conflicts.

To "update" your branch `my-awesome-feature`, you *rebase* it onto
the latest `rizinorg/dev`, and *force-push* the result into your fork.

#### Step 1: Switch to `dev` branch.
```sh
$ git checkout dev
```
#### Step 2: Pull new commits published to rizinorg repo.
```sh
$ git pull https://github.com/rizinorg/rizin
```
#### Step 3: Switch back to `my-awesome-feature` branch.
```sh
$ git checkout my-awesome-feature
```
#### Step 4: Rebase the `my-awesome-feature` branch.
```sh
$ git rebase dev
```
Optionally, use the alternative mode "interactive rebase". It allows
to `squash` your commits all into one, reorder, reword them, etc.
```sh
$ git rebase -i dev
```
Follow git instructions when conflicts arise.

#### Step 5: Publish your updated local branch.
```sh
$ git push -f
```
This `-f` *force-flag* is needed because git commits are immutable: rebasing
creates newer versions of them. git needs to confirm the destruction of
previous incarnations.

When afraid to touch force and risk losing your work (do backups!..),
try *merging dev into your branch* instead of rebasing onto it.
This is discouraged, as it produces ugly hard-to-maintain commit history.

## Commit message rules

When committing your changes into the repository you may want to follow some
rules to make the git history more readable and consistent:

* Start the message capitalized (only the first character must be in uppercase)
* Be short and concise, the whole concept must fit one line
* If a command is inlined, use backticks
* For extra details, add an empty line and use asterisk item list below
* Use present simple grammar tense (Add vs Added, Fix vs Fixed/Fixes)

## Usage of AI tools

Following the widespread availability of large language models and generative AI,
Rizin Organization has received a growing number of changes generated partially or
entirely using such tools. Many of these are completely unusable in our codebase.

> [!IMPORTANT]
> While AI tools can help to draft changes, **they must NOT replace human understanding
> and proper code modifications**.
>
> If you use AI tools to help prepare a code change, you must:
>
> - **Disclose** which AI tools were used and specify what they were used for.
> - **Verify** that the code compiles, works and is not copyrighted by somebody else.
> - **Avoid** fabricated code, placeholder text, or references to non-existent code.
>
> Changes that appear to be unverified AI output will be closed without response.
> Repeated low-quality submissions may result in a ban.

We align with similar policies adopted by other major open-source projects, which have
described the flood of unverified AI-generated code changes as disruptive, counterproductive,
and a drain on limited team resources.

# Additional resources

 * [README.md][]
 * [DEVELOPERS.md][]

[README.md]: https://github.com/rizinorg/rizin/blob/dev/README.md
[DEVELOPERS.md]: https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md

If you need more confidence in your git skills, check out this quick guide:
<https://learnxinyminutes.com/docs/git/>
