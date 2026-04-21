# pi-optimiser media guide

This repo now ships visual documentation for the guided menu flow.
Use this file as the asset inventory plus the refresh checklist.

## Current assets

1. `docs/media/welcome-screen.png`
   First-run welcome screen with the suggested profile.

2. `docs/media/main-menu.png`
   Top-level category menu that shows the section-driven workflow.

3. `docs/media/security-checklist.png`
   Example checklist screen from the **Security** category.

4. `docs/media/values-form.png`
   The **Values** screen where hostname, timezone, locale,
   proxy, and SSH key import are configured.

5. `docs/media/pi-optimiser-demo.gif`
   Short animation covering launch, welcome, main menu, checklist,
   and values screens.

## README placement

- Hero section: `docs/media/main-menu.png`
- Quick start: `docs/media/pi-optimiser-demo.gif`
- Visual assets section: `welcome-screen.png`, `security-checklist.png`,
  `values-form.png`

## Refresh guidance

- Use a clean Raspberry Pi OS terminal session with `whiptail`.
- Prefer an 80x25 or 100x30 terminal so the layout looks deliberate.
- Capture real screens from the current TUI; do not mock or redraw the UI.
- Avoid personal hostnames, IPs, or SSH usernames in screenshots.
- Use the same profile names and menu labels the product actually ships.
- Walk this path when refreshing the capture set:

```text
sudo pi-optimiser
  -> Welcome
  -> Main Menu
  -> Security
  -> Values
```

If a GIF is recorded, keep it focused on the UI and stop before any
long package-install logs take over the screen.
