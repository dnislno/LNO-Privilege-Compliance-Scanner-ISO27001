# Contributing

## Reporting Bugs

1. Check existing issues first
2. Use the **Bug Report** template
3. Include: OS, Node.js version, full error output, steps to reproduce

## Branch Convention

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code |
| `release/*` | Pre-release integration (e.g., `release/v1.1`) |
| `feature/*` | New features (e.g., `feature/dark-mode`) |
| `fix/*` | Bug fixes (e.g., `fix/rate-limit-oob`) |

## Development Workflow

1. Create a branch from `main`: `git checkout -b feature/foo`
2. Make changes, commit with clear messages
3. Run tests: `npm test`
4. Push and open a Pull Request against `main`
5. Ensure CI passes before merging

## Commit Messages

Use conventional commits for auto-release versioning:

- `feat: ...` — minor bump
- `fix: ...` — patch bump
- `feat: ... #major` — major bump
- `fix: ... #minor` — minor bump
- `ci: ...`, `docs: ...`, `refactor: ...` — no bump

## Coding Style

- Use `const` / `let` — no `var`
- 2-space indentation
- Semicolons required
- JSDoc comments for exported functions
- No `console.log` in production code
