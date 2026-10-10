# Import an existing FRP Manager installation

The current working application is deployed at `/opt/frp-manager` on an LXC. The exact production source is **not** yet in this repository.

## Important

Do not replace the running application with the current repository. Existing service configurations, credentials, databases and FRP tunnels must be preserved.

An operator must review the actual files **before** publishing them in this public repository. In particular, source code can contain hard-coded IP addresses, hosts, user names, credentials or security-sensitive operational details. A `.gitignore` file does not sanitize tracked source code.

## Inspect and prepare a sanitized snapshot

1. Log into the LXC where FRP Manager is running.
2. Run `bash scripts/prepare-import.sh` from a checkout of this repository.
3. Review the generated directory under `/root/frp-manager-public-review/`.
4. Remove hard-coded environment-specific values and secrets from the copies. Replace them with environment variables and documented example placeholders.
5. Run a secret scanner (for example Gitleaks) and manually inspect the full diff.
6. Only after review, add the sanitized source files to this repository and commit them.
7. Test a clean install before publishing a one-command updater.

The snapshot script never alters the running application or any FRP service, and it never uploads files to GitHub.
