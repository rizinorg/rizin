# Release checklist template

For each new Rizin release create a new issue on GitHub with this file as its
content. Go step-by-step through it.

- [ ] Update `stable` branch in the proper way
  - [ ] Merge `dev` branch into `stable` branch (for major updates). See https://github.com/rizinorg/rizin/blob/dev/doc/RELEASE.md#majorminor-release.
  - [ ] Cherry-pick relevant commits from `dev` branch into `stable` branch (for patch updates or once `stable` and `dev` have already diverged considerably). See https://github.com/rizinorg/rizin/blob/dev/doc/RELEASE.md#patch-release.
  - [ ] Update `version` field in [`meson.build`](https://github.com/rizinorg/rizin/blob/dev/meson.build) file.
- [ ] Submit a PR of `stable` branch against `origin/stable`. If you have push access to origin, you should create another branch with a different name and submit anyway a PR for others to review.
- [ ] Ensure that CI on `stable` branch is all green. If not, fix issues and iterate previous steps as necessary.
- [ ] Merge PR so that `origin/stable` is updated with the new content.
- [ ] Manually test that things work well, in particular major changes in the new release.
- [ ] Start preparing release notes by modifying the draft release automatically created by GitHub CI.
- [ ] Check that [Cutter](https://github.com/rizinorg/cutter) works well with the new version of Rizin. If not, fix as necessary and go back to previous steps until everything is ready. Cutter and Rizin should be released at the same time, so both should be in a good state with major issues solved.
  - [ ] Cutter can be compiled with new version of Rizin.
  - [ ] Basic Cutter functions work well with new version of Rizin.
  - [ ] Cutter is in good shape to be released.
- [ ] Check that [rz-ghidra](https://github.com/rizinorg/rz-ghidra) works well with the new version of Rizin. If not, fix as necessary and go back to previous steps until everything is ready.
- [ ] Check that [jsdec](https://github.com/rizinorg/jsdec) works well with the new version of Rizin. If not, fix as necessary and go back to previous steps until everything is ready.
- [ ] Check that [rz-retdec](https://github.com/rizinorg/rz-retdec) works well with the new version of Rizin. If not, fix as necessary and go back to previous steps until everything is ready.
- [ ] Check that [rizin-extras](https://github.com/rizinorg/rizin-extras/) and rz-keystone in particular works well with the new version of Rizin. If not, fix as necessary and go back to previous steps until everything is ready.
- [ ] Check that core plugins in [rz-pm-db](https://github.com/rizinorg/rz-pm-db) can be installed correctly with the new version of Rizin. If not, fix as necessary and go back to previous steps until everything is ready.
- [ ] Replace `RZ_PIPE_PY_VERSION` and `RZ_GHIDRA_VERSION` in [`Dockerfile`](https://github.com/rizinorg/rizin/blob/dev/Dockerfile) with the right commits from those repositories. Merge the commit with the Rizin changes in the `stable` branch.
- [ ] Quick test again that Rizin and Cutter work together.
- [ ] Finalize release notes.
- [ ] Release Rizin and Cutter by making their release public on GitHub.
- [ ] Tag rz-pipe for the new version.
- [ ] Tag [rz-bindgen](https://github.com/rizinorg/rz-bindgen) for the new version.
- [ ] Tag rz-ghidra for the new version.
- [ ] Tag rz-keystone/rizin-extras for the new version.
- [ ] Tag jsdec for the new version.
- [ ] Tag rz-retdec for the new version.
