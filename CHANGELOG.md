# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.0.5] - 2026-08-14

### Added

- Email and webhook notification features.

### Fixed

- Service stop/restart (and therefore the General page Save button, which
  reconfigures the service) could take up to a minute: SIGTERM only set a
  stop flag, and the main loop stayed blocked in a queued read with up to
  a 60 second timeout before it noticed. The shutdown handler now wakes
  the main loop immediately instead of waiting out the timeout.
- Do not send notifications when the database was empty (initial fill is
  recorded silently instead of reporting every existing device as new).

### Changed

- Switched to passive capture (tcpdump-based sniffing) with per-device and
  per-address tracking, replacing the previous polling approach.
- MAC vendor database is now updated via an automated workflow, and the
  vendor lookup URL was changed to a self-hosted mirror.

## [0.0.4] - 2026-08-13

### Added

- Initial public release of the ARP/NDP Logging plugin, with automated
  build and publish workflow.
- "Ignore case" option for MAC, IPv6, and hostname comparisons.

### Changed

- Refactored configuration handling and enhanced log rotation logic.
