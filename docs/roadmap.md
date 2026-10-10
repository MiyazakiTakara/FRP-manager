# Development Roadmap

## Current milestone: First sanitized source release

- [x] Create a public, English-language project repository
- [ ] Audit and import the running application source
- [ ] Move environment-specific constants to configuration
- [ ] Add repeatable installation and upgrade scripts
- [ ] Test deployment, health checks and rollback

## Tunnel management

- [ ] Read-only tunnel list
- [ ] Preview and validate new TCP/UDP tunnels
- [ ] Add, edit and remove tunnels safely
- [ ] Protect critical tunnels from accidental disruption
- [ ] Introduce permission checks, CSRF protection and change auditing

## Authentication and operations

- [ ] Review Keycloak single logout and token expiry behavior
- [ ] Add test coverage for session persistence and authorization
- [ ] Review and configure audit log retention
- [ ] Expose server health and troubleshooting information
