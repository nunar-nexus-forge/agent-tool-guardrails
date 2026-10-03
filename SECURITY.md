# Security Policy

## Supported versions

Security fixes are applied to the latest minor release.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use the repository's
**Security** tab on GitHub (*Report a vulnerability*, GitHub's private vulnerability
reporting) and include the version affected, a description of the issue and its impact,
and steps to reproduce. You will receive an acknowledgement within 5 working days, and a
fixed release with credit to the reporter (unless you prefer anonymity).

## In scope

- A way to make a call reach a tool although an applicable rail's predicate is false
  (rail bypass), including through the MCP proxy, argument encodings or phase confusion.
- Predicate evaluation executing arbitrary code, or a regular expression that makes
  evaluation hang.
- A way to append, modify, reorder or remove Evidence Store records that
  `EvidenceStore.verify()` does not detect (with or without an HMAC key).
- PII patterns that can be trivially evaded in redaction actions (please include samples).

## Notes

- The proxy runs the MCP server command you give it; it does not sandbox that server.
- Keep the HMAC key out of policy files and evidence logs (use `--hmac-key-env`).
