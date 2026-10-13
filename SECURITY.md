# Security

AgathOS is a security tool, so reports about weaknesses in AgathOS itself are very welcome.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use GitHub's private reporting
instead: open the **Security** tab of this repository and choose **Report a vulnerability**.
Describe what you found, how to reproduce it and which version you used.

You can expect a first answer within a week. Fixes are released as a new version with the
installers attached, and the release notes say what was fixed once users have had time to update.

## What AgathOS does to stay safe itself

- Everything runs on your own computer. No account, no cloud, no telemetry.
- The window has no Node access; it talks to the engine through a short, fixed list of calls.
- The local API listens on 127.0.0.1 only, needs a token and refuses browsers.
- AgathOS Guard (Windows, optional) runs from an admin-only folder and only listens on
  127.0.0.1 with its own token. Removing it restores your previous Windows settings.
- Updates come only from this repository's GitHub Releases. The Windows installer is checked
  against the SHA-256 checksum GitHub publishes before it runs.
- The event log is hash-chained, so edits outside AgathOS are visible.

## Supported versions

Only the latest release gets security fixes.
