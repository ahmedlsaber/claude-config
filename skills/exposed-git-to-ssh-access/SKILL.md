---
name: exposed-git-to-ssh-access
description: Exposed .git repository leading to source/config/history disclosure and leaked SSH/RSA credentials. Discover /.git with passive/active recon and directory fuzzing, reconstruct the repository with git-dumper or equivalent, inspect commits/branches/authors/dev folders/configs for private keys, RSA material, passwords, deploy keys, environment secrets, then validate access only against owned authorized hosts. Covers .git exposure, git history secret hunting, dev/test code leakage, SSH key discovery, and secret remediation. Triggers on exposed .git, git-dumper, source disclosure, private key in repository, id_rsa leak, SSH access from source code, dev folder secrets.
---

# Exposed `.git` → Source Disclosure → Credential Exposure

An accidentally deployed `.git` directory can expose the complete source repository,
including deleted files, commit history, branches, authors, development folders,
configuration, private keys, and deployment credentials. The high-impact chain is:

```
/.git reachable
→ reconstruct repository
→ inspect history/dev/config files
→ discover RSA/SSH key or secret
→ validate against an owned authorized host
```

## Discovery

1. Enumerate ports/services and virtual hosts within scope.
2. Check common repository artifacts:
   ```
   /.git/HEAD
   /.git/config
   /.git/index
   /.git/objects/
   /.git/logs/HEAD
   ```
3. Fuzz for related files/directories: `.gitignore`, `.env`, `dev/`, `backup/`,
   `.svn/`, `.hg/`, source maps, deployment files.
4. A response to `/.git/HEAD` containing `ref: refs/heads/...` is strong confirmation.

## Repository reconstruction

Use a repository dumper or manually retrieve reachable Git objects. Preserve the
original evidence and inspect locally:

```bash
git-dumper https://target.example/.git ./repo
cd repo
git log --all --stat
git branch -a
git show --all
```

Never publish or commit exposed secrets. Search current files **and history**:

```bash
git log --all -p -- .env config/ deploy/ dev/
git grep -nEi 'password|secret|token|private.?key|BEGIN .* PRIVATE KEY|ssh|aws|api.?key' $(git rev-list --all)
```

## High-value locations

- `.env`, `.env.production`, application config
- CI/CD files and deployment manifests
- `dev/`, `debug/`, `test/`, `backup/` folders
- SSH/RSA files (`id_rsa`, `.pem`, `authorized_keys`)
- Docker/Kubernetes/cloud configuration
- Database connection strings
- Deleted files still present in Git history
- Commit messages, author emails, branch names, tags, and release artifacts

## Credential validation

Treat discovered credentials as secrets. Validate only with explicit authorization:

1. Determine intended scope from the repository and host configuration.
2. Use the minimum-impact authentication check on an **owned authorized host**.
3. For an SSH key, verify key format and permissions locally; do not connect to
   third-party infrastructure.
4. If access is confirmed, stop at a safe proof such as identity/hostname and do not
   read unrelated data or alter the host.
5. Notify the program immediately and preserve only minimal redacted evidence.

## Impact levels

- Public source disclosure: architecture, internal endpoints, and vulnerability
  intelligence.
- Secrets in current files/history: credentials, API access, deployment control.
- Private SSH/RSA key valid on an authorized production host: potentially critical
  host compromise.
- Dev-only key or expired secret: still reportable exposure, lower impact.

## Remediation

- Remove `.git` and repository metadata from deployed web roots.
- Rotate every exposed credential, key, token, and password; deleting the file is
  insufficient because Git history preserves it.
- Add deployment checks that fail builds containing `.git`, private keys, or secrets.
- Use secret managers, least-privilege deploy keys, short-lived credentials, and
  repository secret scanning.
- Restrict production SSH and require individual, auditable keys.

## Reporting checklist

Include the exposed path, reconstruction proof, sensitive file/commit location,
secret type, safe validation result, affected host scope, and rotation guidance.
Redact private keys and tokens; never include them in a report or repository.
