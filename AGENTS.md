# AGENTS.md — guidance for AI / code-assistant contributions

This file documents conventions this codebase expects from automated
contributors (and from humans). It sits alongside `CONTRIBUTING.md`
and applies to anyone editing tasks, utilities, framework features,
or the TUI.

Keep changes small, specific, and shellcheck-clean. No emoji in code
or commit messages. No AI-service branding or credit lines in commit
messages, PR bodies, code comments, or docs.

## Repository layout

```
pi-optimiser.sh            entry script (argv, feature dispatch, task loop)
install.sh                 one-liner bootstrap (curl | sudo bash)
lib/MANIFEST               task execution order (one id per line)
lib/util/*.sh              shared helpers (15 modules)
lib/tasks/*.sh             one file per task (42 tasks at 9.0)
lib/features/*.sh          framework features (profile, report, snapshot,
                           undo, install, update)
lib/ui/tui.sh              whiptail TUI (optional; gracefully no-ops
                           when whiptail is missing)
scripts/build-bundle.sh    concatenates the tree into a single-file
                           release at dist/pi-optimiser-bundle.sh
.github/workflows/         shellcheck CI + release tag bundling
```

State lives in `/etc/pi-optimiser/`:

```
state.json                 schema v2 — per-task completion records
state.schema               integer; bump when the JSON layout changes
                           and add a migration step in lib/util/state.sh
backups/<task>.json        per-task backup journal (driven by backup_file)
snapshots/<ts>.tgz         --snapshot archives
config-optimisations.json  misc key/value config state (proxy backend,
                           EEPROM staging info, update commit SHA, …)
config.yaml                optional: TUI-saved or --config-loaded values
```

User logs live at `/var/log/pi-optimiser.log` (owned root, 0600). Never
try to write there without checking `-w`; `log_with_level` already
handles that.

## Golden rules

1. **Task IDs are frozen.** Users have completion markers keyed by id.
   Do not rename. If a task is being replaced, keep the old id as an
   alias (`pi_task_register` can point at a different runner).
2. **No emoji.** Not in code, comments, commit messages, PR bodies,
   or README. This project is used headlessly and piped through
   non-UTF8 terminals.
3. **No AI-service branding or co-authoring. Zero exceptions.**
   This applies to every commit message, PR body, code comment,
   doc, and generated artefact:
   - Never add a `Co-Authored-By:` trailer naming an AI service,
     assistant, tool vendor, or any `noreply@anthropic.com` /
     similar address.
   - Never add "Generated with …", "🤖", "Co-authored by Claude",
     "Powered by …", or any similar footer/banner.
   - Never name Claude, GPT, Copilot, Anthropic, OpenAI, Cursor,
     Aider, or any other AI tool in code, comments, or docs.
   - Never write the author as the tool; the human operator is
     the sole author on record.
   If you spot an existing violation (in files OR commit history),
   remove it. Rewrite commit messages via `git filter-branch
   --msg-filter` / `git filter-repo` and coordinate a force-push
   with the maintainer.
4. **ShellCheck must stay clean** at `--severity=warning`. Cross-file
   false positives (SC2034 / SC2154) are suppressed with targeted
   `# shellcheck disable=...` and a one-line reason.
5. **Preserve state backward-compatibility.** If you change the JSON
   shape in `state.json`, bump `PI_STATE_SCHEMA_TARGET` in
   `lib/util/state.sh` and add a `_pi_state_migrate_<from>_<to>`
   function. Never delete the previous migration.
6. **Keep the bundle working.** `scripts/build-bundle.sh` must produce
   a standalone file that runs with no filesystem dependency on `lib/`.
   Any new source loop in the entry script needs a corresponding edit
   in the bundler's marker logic.
7. **Never trust `eval` with user data.** If you have to construct
   bash from a config, go through Python + `shlex.quote()`, same as
   `lib/util/config_yaml.sh` does. A single un-quoted `$var` in an
   `eval` is an RCE.
8. **Validate every user-controlled string that reaches a URL,
   filesystem path, or shell-expandable position.** See
   `lib/util/validate.sh` for the patterns:
   `validate_hostname`, `validate_timezone`, `validate_https_url`,
   `validate_proxy_backend_url`, `validate_github_handle`,
   `validate_task_id`. Add new ones there, keep the signature
   `validate_X <value>` → 0 on valid, 1 on invalid.
9. **Tasks that require a reboot must flag it.** Declare
   `reboot_required=1` in the `pi_task_register` call (and the
   `# reboot_required: true` metadata comment). `apply_once` will
   call `pi_mark_reboot_required "$task"` on success, and
   `--report` + the post-run summary surface the flag. Also
   mention "Reboot required" explicitly in a `log_info` line so
   the operator sees it without re-reading state.json.
10. **Python heredocs go through `run_python`**, not raw
    `python3 <<'PY'`. `run_python` propagates exit codes and
    forwards stderr to `log_warn`. The five tasks still using raw
    `python3` were fixed in 9.0.1; don't regress.
11. **Feature functions honour `--dry-run`.** Every entry point in
    `lib/features/*.sh` must early-return with an `[dry-run]
    would…` log line when `DRY_RUN=1`. No exceptions.

## Task file anatomy

A task file is `lib/tasks/<id>.sh`. Shape:

```bash
# >>> pi-task
# id: my_new_task
# version: 1.0.0
# description: One-line human-readable summary
# category: storage           # storage|system|network|security|
#                             # hardware-clocks|display|packages|
#                             # integrations|firmware-eeprom
# default_enabled: 0          # 1 = runs without any flag
# power_sensitive: 0          # 1 = skipped when preflight flags power
# flags: --my-flag            # comma-separated, for docs & TUI
# gate_var: MY_FLAG_GLOBAL    # global that gates entry (0/"" = skip)
# <<< pi-task

pi_task_register my_new_task \
  description="One-line human-readable summary" \
  category=storage \
  version=1.0.0 \
  default_enabled=0 \
  flags="--my-flag" \
  gate_var=MY_FLAG_GLOBAL

run_my_new_task() {
  # Self-gate first. Tasks must decide on their own whether to run.
  if [[ ${MY_FLAG_GLOBAL:-0} -eq 0 ]]; then
    log_info "my_new_task not requested; skipping"
    pi_skip_reason "not requested"
    return 2
  fi

  # ... do the work ...

  write_json_field "$CONFIG_OPTIMISER_STATE" "my_new_task.installed" "true"
  # Falling off the end returns the last command's rc; usually 0.
}
```

### Return codes (strict)

- `0` — task changed state (or confirmed idempotent no-op) successfully.
  `apply_once` records `completed` with the current `PI_TASK_VERSION`.
- `1` — fatal error. `apply_once` records `failed`, appends to
  `SUMMARY_FAILED`, and bubbles a non-zero exit.
- `2` — skipped with reason. Caller set `TASK_SKIP_REASON` via
  `pi_skip_reason "..."`. State is unchanged; the summary line shows
  the reason.

Never set `TASK_WAS_SKIPPED` — that global is gone. Use `pi_skip_reason`
then `return 2`.

### When to add a flag + global

If a task is opt-in:

1. Add a global in `pi-optimiser.sh` next to the other flag globals
   (e.g. `INSTALL_MY_THING=0`). If it's a string value (hostname,
   URL, etc.), initialise to `""`.
2. Wire the flag in `parse_args()`; always validate arity if the flag
   takes an argument.
3. List it in `usage()` alphabetically-ish near similar flags.
4. Declare `gate_var=MY_FLAG_GLOBAL` in `pi_task_register`.
5. If the task should also be addressable from a profile, update
   `lib/features/profiles.sh`.

### Adding a task to the manifest

1. Drop the file at `lib/tasks/<id>.sh`.
2. Add the id on its own line in `lib/MANIFEST` at the appropriate
   slot (order matters; see existing categories).
3. Run `sudo ./pi-optimiser.sh --list-tasks` — the new task must
   appear with its version + category.
4. Run `sudo ./pi-optimiser.sh --dry-run --only <id>` — must show
   "Running task" + "[dry-run] not executed".

A task in `lib/tasks/` that is absent from `lib/MANIFEST` is appended
at the end with a warning; a manifest entry without a task file is a
fatal error.

## Utility modules

Don't add a new file to `lib/util/` without updating these three
things together:

1. `pi-optimiser.sh` source loop (the `for _util in log python ...`
   line).
2. `scripts/build-bundle.sh` `order_utils` list.
3. Ordering matters — `log.sh` and `python.sh` must be first;
   `state.sh` depends on `python.sh`; `config_txt.sh` depends on
   `python.sh` + `log.sh`; etc. If unsure, append at the end and
   audit with `shellcheck`.

Same rules apply to `lib/features/` (add to main's `for _feat in ...`
loop and the bundler's `order_features`).

## Embedded Python

Use the `run_python` helper (`lib/util/python.sh`) rather than
calling `python3` directly. `run_python` propagates non-zero exit
codes, forwards stderr lines through `log_warn`, and is robust to
stdin redirection quirks.

```bash
result=$(VAR1=x VAR2=y run_python <<'PY' || echo "")
import os
# use os.environ["VAR1"], os.environ["VAR2"]
PY
```

Don't pass data via `sys.argv` — use environment variables. They're
easier to quote correctly and let you compose longer payloads.

## State, snapshots, backups

- `backup_file <path>` is idempotent within a run (keyed by original
  path). It automatically appends a record to
  `/etc/pi-optimiser/backups/<CURRENT_TASK>.json`, which `--undo` uses
  to locate what to roll back.
- Call `backup_file` **before** editing any existing file you didn't
  create.
- Config writers that overwrite a new file (e.g. `cat <<CFG > new.conf`)
  don't need to `backup_file` — nothing to restore.
- `ensure_config_key_value` takes an existing config.txt path + a
  `key=value` line and replaces any current line for that key. Return
  codes: `0` changed, `1` unchanged, `2` error.
- Never touch `state.json` directly — use `set_task_state`,
  `clear_task_state`, `write_json_field`.

## Testing

Local, before every commit:

```bash
bash -n pi-optimiser.sh
bash -n lib/util/*.sh lib/tasks/*.sh lib/features/*.sh lib/ui/*.sh
shellcheck --severity=warning --shell=bash \
  pi-optimiser.sh lib/util/*.sh lib/tasks/*.sh lib/features/*.sh \
  lib/ui/*.sh scripts/*.sh install.sh
./pi-optimiser.sh --list-tasks | wc -l   # must equal manifest size
./scripts/build-bundle.sh && dist/pi-optimiser-bundle.sh --version
```

On a Pi (hardware smoke — use a throwaway one), minimum:

```bash
sudo ./pi-optimiser.sh --migrate --yes
sudo /usr/local/sbin/pi-optimiser --report
sudo /usr/local/sbin/pi-optimiser --dry-run --only <your-task>
sudo /usr/local/sbin/pi-optimiser --only <your-task> --yes
sudo /usr/local/sbin/pi-optimiser --status           # verify completion
sudo /usr/local/sbin/pi-optimiser --undo <your-task> --yes
```

For tasks that modify existing files (`backup_file` is called), also
verify the journal entry appears at
`/etc/pi-optimiser/backups/<id>.json` and that `--undo` restores the
original.

## Git conventions

- Branch naming: `feat/...`, `fix/...`, `refactor/...`, `chore/...`.
- One logical change per commit where possible; a big refactor that
  only works atomically can be a single commit with a rich body.
- Commit subject under 72 chars, conventional-ish
  (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`).
- No emoji. No AI branding. No "Co-Authored-By" lines for AI services.
- PR body should reference the phases / sections touched, include a
  **Test plan** with ticked boxes for what you actually ran, and list
  anything deliberately deferred.

## Releasing

- Tag a release with `vMAJOR.MINOR.PATCH` (e.g. `v9.0.1`).
- `.github/workflows/release.yml` will build the bundle, compute the
  sha256, and attach both to the GitHub release. Users then
  `curl | sudo bash` the bundle for a one-shot run or run
  `install.sh` to produce an installed tree.
- Bump `SCRIPT_VERSION` in `pi-optimiser.sh` and the header comment
  in the same commit that tags the release.
- If state schema or any task's metadata changed in a breaking way,
  call it out in the PR body *and* log a `log_warn` the first time
  the new version starts.

## What NOT to do

- Do not introduce a dependency on Ruby, Go, or Node. Bash + Python 3
  + standard Debian tooling only.
- Do not call `apt-get install` outside `ensure_packages`.
- Do not shell out to `systemctl` without `unit_exists` guarding it.
- Do not print "Claude", "AI", "LLM", "assistant", or similar in any
  output the user sees.
- Do not add interactive prompts that don't honour `--yes` /
  `PI_NON_INTERACTIVE=1`.
- Do not hand-edit `dist/` — it's built by CI and `scripts/build-bundle.sh`.
