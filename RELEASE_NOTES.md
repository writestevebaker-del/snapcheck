# SnapCheck v0.9.0

## MVP roadmap

- **Profiles** — `--profile git-repo|server|ci`
- **JSON/YAML passwords** — detects plain-text credentials in configs
- **Dangerous files** — `.ovpn` in webroot, SSH keys, `.env` by path
- **Contextual recommendations** — copy-paste shell commands
- **Score breakdown** — see how Health Score is calculated
- **`explain` / `teach`** — offline guidance without AI
- **Connection strings** — PostgreSQL, Redis, MongoDB, MySQL, AMQP URIs
- **Performance** — `--max-depth`, `--max-files`, `--progress`
- **`snapcheck fix`** — safe interactive fixes for `.gitignore`

89 tests · zero runtime dependencies