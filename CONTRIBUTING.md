# Contributing to Tameng

Thanks for your interest in contributing.

## Reporting Issues

- Search existing issues before opening a new one.
- For security vulnerabilities, please do not open a public issue. See the security policy referenced in the README instead.
- For bugs, include: Go version, OS, steps to reproduce, expected vs. actual behavior, and relevant log output.

## Development Setup

```bash
git clone https://github.com/koodoxz/tameng.git
cd tameng
cp .env.example .env
CGO_ENABLED=1 go build -o tameng ./cmd/svalinn
```

## Code Style

- Standard Go formatting: run `gofmt` and `goimports` before committing.
- Run `go vet ./...` and fix any warnings.
- Keep functions focused and files cohesive; this codebase favors many small, single-purpose files over large ones.
- No unrequested abstractions. Prefer the standard library and already-imported dependencies over new ones.

## Testing

```bash
go test ./internal/...
go test -race ./internal/...
go test -coverprofile=coverage.out ./internal/... && go tool cover -func=coverage.out
```

- New logic should come with tests. Table-driven tests are the norm in this codebase.
- Security-relevant changes (detection logic, authentication, request parsing) should include negative-path tests, not just the happy path.
- If you're touching a detection or WAF signature package, check for existing differential/fuzz tests in that package and extend them rather than only adding unit tests.

## Pull Requests

1. Fork the repo and create a feature branch.
2. Make your change with tests and a clear commit message.
3. Run `gofmt`, `go vet`, and `go test -race ./internal/...` locally before opening the PR.
4. Describe what changed and why in the PR description. If the change has security implications (even indirectly), say so explicitly.
5. Keep PRs focused — one logical change per PR is easier to review than a bundle of unrelated fixes.

## License

By contributing, you agree that your contributions will be licensed under the project's AGPL-3.0 license (see [LICENSE](LICENSE)).
