# Changelog

All notable changes to Guardium DNS will be documented here.

The project follows [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`.
Minor versions usually carry new features; patch versions are fixes only.

For the canonical list of every commit, see the
[GitHub history](https://github.com/adzza/guardium-dns/commits/main).

## Unreleased

### Added

- **In-dashboard update notifications.** The footer now shows the running
  version, and an amber banner appears when a newer commit is available on
  your configured channel. Hover the version chip to see what's running;
  follow the banner instructions to update.
- **`guardium-update` CLI.** Single-command updater that pulls the latest
  code, runs migrations, restarts the service, and auto-rolls-back on
  health-check failure. Lives at `/usr/local/bin/guardium-update` after
  install.
- **Update channels.** A new `UPDATE_CHANNEL` env var (`main` by default;
  `feat/unifi-integration` while the UniFi work bakes) controls which
  branch the updater follows.
- **Schedule UX polish.** Preset chips in the person drawer now carry a
  tick badge when active, a scope indicator clarifies whether a schedule
  will hit any devices, and an "active right now" callout fires when the
  window is live.
- **Family pause: skip unassigned devices by default.** Servers, NAS, smart
  home gear etc. now stay online during "Pause for dinner" unless the new
  "Also pause unassigned devices" checkbox is ticked.

### Fixed

- **Family pause "End now" banner now appears.** Detection had been
  filtering by `target_kind == "all"` but the writer creates per-device
  rows, so the banner was permanently invisible and there was no UI path
  to cancel a pause before its timer expired. Cancel button is now
  reachable from anywhere in the dashboard.

## 0.1.0 — 2026-05-25

Baseline tag. Marks the first version that ships an in-dashboard update
mechanism. Everything before this commit was un-versioned and is collectively
"pre-0.1.0".
