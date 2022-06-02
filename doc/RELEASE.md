Release process
===============

All releases happen from the `stable` branch, while the `dev` branch is used for
continuous development. Release artifacts and testing are done by GitHub
Actions.

# Major/Minor release
Handled by making the `stable` branch content the same as the one on `dev`. It
could (and usually does) break API/ABI compatibility with previous versions.

    git checkout dev
    git checkout -b stable-merge
    git merge stable -s ours
    git checkout stable
    git merge stable-merge --no-ff -m "Merge 'dev' branch into stable"
    git diff dev      # no difference
    git log           # commit history from dev is included
    git branch -D stable-merge

# Patch release
Patches needs to first land in `dev` branch and only then they can be
cherry-picked to `stable`.

    git cherry-pick <commit-in-dev>

This release is used for smaller patches that do not break the API/ABI.

# Increment the version number
Increment the version number in `meson.build` in add a new commit for it in the
`stable` branch.

# Submit PR
Submit a new PR of your `stable` branch against `origin/stable`. If you have
push access to `origin`, you should create another branch with a different name
and submit anyway a PR for others to review.

# Test that everything worked well

# Tag related projects and use them
- Pin to a release tag of rz-pipe in `Dockerfile`
- Pin to a release tag of rz-ghidra in `Dockerfile`
- Add new commit for these in the `stable` branch

# Prepare release notes
Write useful release notes for the new release. They should not be too detailed
but not even too high level. Finding the right balanace is hard. When done,
attach them to the draft release in the GitHub UI.

# Release
Test again that everything is generated correctly, things seem to be working
well and then confirm the draft release in the GitHub UI.

# Share & Enjoy
