# Contributing

## Quick start

1. Fork + clone.
2. Make your change in a new branch.
3. Open a PR.

## Required of every commit

- **Signed commits.** We enforce SSH commit signing on `main`. Set up:
  ```sh
  git config --global gpg.format ssh
  git config --global user.signingkey ~/.ssh/your-key.pub
  git config --global commit.gpgsign true
  ```
  Verify: `git verify-commit HEAD` should print `Good "git" signature`.

- **Build green.** Run the project's build before pushing:
  - Zig projects: `zig build && zig build test`
  - Nix projects: `nix flake check && nix build .#default`

- **Conventional shape.** Commit subjects: imperative mood, ~70 chars.
  Body explains the *why*, not the *what* (the diff shows the what).

## Style

- **No third-party deps** in the user-facing tools. We're zero-deps for a
  reason — supply-chain audit story, AGPL clarity, single-binary distribution.
- **Determinism first.** If your change makes output non-deterministic
  (timestamps, random IDs, map iteration order), call it out explicitly
  in the PR description and explain why it's necessary.
- **Document the why, not the what.** Header comments explain *why this
  approach*. Inline comments explain non-obvious *intent*. Names explain
  *what*.

## License

By contributing, you agree your contribution is licensed under
AGPL-3.0-or-later — same as the rest of the project. No CLA required.

## What we accept fast

- Bug fixes with a regression test.
- Documentation improvements (READMEs, examples, error messages).
- Performance improvements with a measurable benchmark.

## What needs more discussion

- New external dependencies (see "no third-party deps" above).
- Changes to output format or schema (determinism + downstream-compat
  implications).
- New subcommands or flags (we prefer narrow, stable interfaces).

Open an issue first for the second category.

## Maintainers

- [stax](https://github.com/stax) (lead) — sovereign-stack architecture,
  Zig + Nix.

## Code of conduct

Be civil. Disagree with arguments, not people. Don't harass anyone, in
issues or PRs or out-of-band. We follow the spirit of the
[Contributor Covenant](https://www.contributor-covenant.org/) without
adopting it formally — keep discussions technical and respectful.

If something feels off, email the contact in [SECURITY.md](SECURITY.md).
