# Security Policy

## Reporting a vulnerability

Please do not publish exploit details, session tokens, API keys, credentials or private infrastructure information in GitHub issues.

Report security issues privately to the repository maintainer using GitHub's private vulnerability reporting feature if enabled.

## Secrets and deployments

- Never commit production configuration, `oidc.env`, access tokens, passwords, SSH keys, session databases or logs.
- Store credentials outside the source tree, with restrictive filesystem permissions.
- Configure OIDC redirect URIs narrowly and require HTTPS.
- Run the web application with a dedicated, unprivileged system account.
- Restrict management APIs and validate authorization on every privileged operation.
- Protect state-changing requests against CSRF and audit all changes.
- Back up FRP configuration before applying changes and provide rollback paths.
- Do not assume private deployment details are safe to publish merely because values appear in source code.

## Supported releases

This repository has no published stable release yet.
