# FRP Manager

A self-hosted web management interface for [frp](https://github.com/fatedier/frp), with OpenID Connect authentication and operational visibility for FRP client tunnels.

> **Development status:** Work in progress. The current repository is being prepared for the first sanitized source release. No production application code has been published yet.

## Planned features

- Live tunnel status and configuration overview
- TCP and UDP tunnel management with validation
- OpenID Connect (OIDC) authentication with Keycloak
- Role-based authorization (viewer, operator, administrator)
- Persistent encrypted session storage with SQLite
- Audit logging and safe configuration changes
- Deployment and rollback support

## Architecture

FRP Manager runs alongside an existing `frpc` client. It reads tunnel state via the frpc API and uses separate, narrowly scoped mechanisms for remote server health checks. The management service should run as an unprivileged account.

## Deployment

Deployment instructions and an audited upgrade script will be added after the production source code is imported and tested. **Do not deploy the current repository as a complete application.**

Runtime secrets, FRP tokens, SSH credentials, session databases and real infrastructure configurations must never be committed. See [SECURITY.md](SECURITY.md).

## Project language

All source code, UI content, comments and documentation are written in English.

## License

A license has not been selected yet. Until one is added, standard copyright restrictions apply; public visibility alone does not grant permission to redistribute or modify the code.
