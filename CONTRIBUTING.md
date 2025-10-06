# Contributing to pi-optimiser

Thanks for considering a contribution! This project is used to bootstrap Raspberry Pi deployments, so stability and reproducibility are key. Use this guide to get your patch accepted quickly.

## Reporting Issues
Please include the following when filing an issue:
- Output of `./pi-optimiser.sh --status`
- Relevant excerpts from `/var/log/pi-optimiser.log`
- Model of Raspberry Pi (Pi 5/500, Pi 4/400, Pi 3, Pi Zero 2, etc.)
- Raspberry Pi OS version (`cat /etc/os-release`)
- Any flags used when running the optimiser

## Development Workflow
1. Fork and clone the repository.
2. Create a topic branch: `git checkout -b feature/my-change`
3. Make your changes (see coding standards below).
4. Run `./pi-optimiser.sh --dry-run` on a test Pi to ensure no errors.
5. Submit a pull request with a clear description of the change and testing performed.

## Coding Standards
- Shell scripts must remain POSIX/Bash compatible (Bash 4+). Keep `set -euo pipefail` semantics intact.
- Prefer functions over inline code, and document non-obvious logic with concise comments.
- Maintain idempotency: re-running the script should not duplicate work or regress state.
- Update `README.md` and usage text when behaviour changes.
- Keep changes focused; unrelated cleanups belong in separate PRs.

## Commit Guidelines
- Use conventional-style messages (`feat:`, `fix:`, `chore:`).
- Include relevant context in the body if the subject is not self-explanatory.
- Squash multiple fixups before opening the PR.

## Code Review Expectations
Maintainers will check for:
- Idempotent behaviour and safe defaults.
- Proper logging and state tracking in `/etc/pi-optimiser/state`.
- Compatibility with supported hardware (Pi 5/500, 4/400, 3, Zero 2).
- Clear documentation updates accompanying user-visible changes.

Happy hacking! :rocket:
