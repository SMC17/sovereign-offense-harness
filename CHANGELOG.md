## Unreleased

### Fixed

- **`parseTtp` safety bug** — three unchecked `.string` accesses on
  `std.json.Value` (`id`, `name`, `exec`) would UB-panic in Debug /
  ReleaseSafe when fed an adversarial descriptor whose required-string
  field was a non-string JSON type (e.g. `{"id": 42}`). The existing
  19-test suite covered happy paths and missing-field paths but not
  wrong-type-field paths; the project's own `SECURITY_REVIEW.md`
  explicitly named adversarial descriptor fuzzing as a follow-on
  workstream. Each access now type-checks before reaching for the
  union field and returns `error.TtpIdNotString` /
  `error.TtpNameNotString` / `error.TtpExecNotString`.

### Added

- **Three wrong-type unit tests** + a **3000-trial adversarial fuzz
  harness** for `parseTtp` in `src/main.zig`. The fuzz harness applies
  bit-flip / byte-insert / byte-delete / truncate / type-substitute
  mutations to a known-valid descriptor (1–4 ops per trial, seeded
  PRNG `0xADF7_2026_0514_C0DE`) and asserts only that the parser
  returns — either a `Ttp` or a clean error — never panics. Cross-check
  asserts both ok-count and err-count are positive, so a broken
  mutator that produces only-valid or only-invalid inputs would also
  fail the test.
- Total in-source tests: 20 → 24. `zig build test` ~1 s.

## v1.0.0 — 2026-05-13

**Production-grade milestone.**

- SECURITY.md present (coordinated disclosure policy).
- LICENSE, README, CONTRIBUTING, CI workflow verified.
- v1.x cycle: API/surface stable; breaking changes bump to v2.x.
- Engineering posture: Virgil work-in-progress convention adapted for OSS — v1.0 means we stand behind the existing surface; v1.x refines without breaking.

# Changelog

All notable changes to `sovereign-offense-harness` will be documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [0.3.2] — 2026-05-12

### Other

- v0.3.2: route security reports to GitHub private advisory

## [0.3.1] — 2026-05-11

### Other

- v0.3.1: publish-readiness polish — WS6 SECURITY_REVIEW remediation
- publish: full AGPL-3.0 text + correct GH namespace + CoC

## [0.3.0] — 2026-05-11

### Other

- v0.3.0: Atomic Red Team adapter (EXPERIMENTAL) + envelope JSON-escape fix

## [0.2.0] — 2026-05-07

### Docs

- docs+meta: bump README + STATUS + build.zig.zon to v0.2.0 (pass-2)

### Other

- v0.2.0: refuse-by-default safety gate
- CONTRIBUTING.md: fix the 'no third-party deps' overclaim
- launch polish, second pass: type-1/type-2 fixes across README + SECURITY + CONTRIBUTING
- launch polish: README rewrite + SECURITY + CONTRIBUTING + CI

## [0.1.0] — 2026-05-06

### Other

- v0.1.0: scaffold + TTP runner + envelope emitter
