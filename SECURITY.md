# Security Policy

## Scope and Supported Versions

| Version          | Supported          |
| ---------------- | ------------------ |
| latest-release   | :white_check_mark: |
| *                | :x:                |

Rizin is a user-space Command Line Interface (CLI) tool that isn't considered a high-availability service. As such, issues that impact Rizin's availability will not be considered as vulnerabilities by the security team. Such issues include, but are not limited to:
 - NULL Pointer Dereference
 - Memory Exhaustion

Issues that can leak non-sensitive memory contents (e.g memory addresses and values, etc.) should be demonstrated to be usable by an attacker and will be considered on a case-by-case basis.

## Reporting a Vulnerability

Security issues in the Rizin repository should be reported by email to security@rizin.re. Your email will be delivered to a small security team that will handle the report. Your email will be acknowledged within 48 hours, and you'll receive a more detailed response to your email within 72 hours indicating the next steps in handling your report.

For your convenience, we accept reports written in one of the languages listed on our [security.txt](https://rizin.re/.well-known/security.txt) page, but we prefer reports in English. Please try to always include in your report an attack scenario, showing how the issue can affect Rizin users.

If you have not received a reply to your email within 48 hours, or have not heard from the security team for the past week, there are a few steps you can take (in order):

- Directly contact at least one member from [Rizin Security Team](https://rizin.re/teams/security/)
- Inform the team over the [public chats](https://rizin.re/#community) that you sent a message regarding a security issue.

**Important:** Don't disclose any information regarding the issue itself in the public chats.
