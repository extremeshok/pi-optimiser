# TODO — deferred items

Tracked here so new contributors can pick them up without another
audit pass surfacing the same thing. Organised by effort.

## Medium (a session or two)

- **`--pin-task <id>=<version>`.** The `--freeze <id>` half of
  per-task version pinning ships (via `freeze_tasks:` in
  config.yaml, consulted by `apply_once`). The fetch-historical
  half is deferred: it needs a per-task version manifest fetched
  from a tag archive. Useful when a specific task regresses on a
  specific hardware generation but not a correctness need.

## Deliberately not planned

- **Self-update signing infrastructure.** The `--require-signature`
  verifier is shipped and will check a minisign signature if the
  user opts in and provides their own key. We are not going to
  produce an official signing pipeline:
  - For a single-maintainer project, the signing key and the
    GitHub credentials basically live in the same blast radius.
    If one is compromised, the other probably is too.
  - The `curl | sudo bash install.sh` path is unsigned anyway,
    and it's the more common install mode. Signing the release
    bundle protects one entrypoint while leaving the more common
    one exposed.
  - TLS + pinned-tag + sha256 matches the trust posture of every
    other `curl | bash` installer on the internet, and that is
    already what users sign up for when using this project.
  - Real-world supply-chain incidents (rustup-init, homebrew
    formulae, event-stream) were CI/build-system compromises
    that signing wouldn't have prevented.
  Users who need stricter verification can sign the bundle with
  their own key and run with `--require-signature`.

## Resolved (see CHANGELOG.md)

- **9.1.0**: Prometheus textfile metrics, `--watch` mode,
  `--diff` preview for config.txt/cmdline.txt, `--freeze-task`,
  Dockerised integration-test harness, bundle parity guard.
- **9.0.2**: reboot-required surfacing, YAML inline comments,
  stricter `--validate-config`, `--completion`, `--show-config`,
  `--undo --all`, `--self-test`, `--reboot-after`, man page,
  JSON schema docs, `TERM=dumb` guard, bundle-mode guards on
  `--migrate` and `--update`, stale-journal rotation on
  `--restore`, `install.sh` cleaner 404 path.
- **9.0.1**: 3 CRITs + 10 HIGHs + 10 MEDs from audit pass #2.
  See `CHANGELOG.md` for the full list.
- **9.0.0**: modular refactor, self-update, TUI, installer.
