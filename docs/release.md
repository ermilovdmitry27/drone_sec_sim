# Release Process

This document describes the release workflow for the Drone Security Simulation project.

## Versioning Scheme

The project follows [Semantic Versioning (SemVer)](https://semver.org/spec/v2.0.0.html):
- **MAJOR** version (X.0.0): Incompatible changes
- **MINOR** version (0.X.0): New functionality in a backward-compatible manner
- **PATCH** version (0.0.X): Backward-compatible bug fixes

Current version is defined in `pyproject.toml`:
```toml
[project]
name = "drone-sec-sim"
version = "0.1.0"
```

## Release Steps

### 1. Update Version

Edit `pyproject.toml` and update the version field:
```toml
version = "X.Y.Z"
```

### 2. Update CHANGELOG.md

Move items from `[Unreleased]` section to a new version section:
```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...
```

### 3. Commit Version Bump

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "Release vX.Y.Z"
```

### 4. Create Git Tag

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

### 5. Create GitHub Release

1. Go to https://github.com/yourusername/drone_sec_sim/releases/new
2. Select the tag `vX.Y.Z`
3. Set release title: `vX.Y.Z`
4. Copy the CHANGELOG.md entries for this version into the description
5. Attach any binary artifacts if needed
6. Click "Publish release"

## Pre-release Checks

Before releasing, ensure:
- [ ] All tests pass: `make test`
- [ ] CI pipeline passes (GitHub Actions)
- [ ] CHANGELOG.md is updated
- [ ] Version in `pyproject.toml` is correct
- [ ] No sensitive data in commits (check with `git log --all -- .env*`)
- [ ] Documentation is up to date (`docs/` folder)

## Hotfix Releases

For urgent bug fixes on a previous release:

```bash
# Create branch from the tagged release
git checkout -b hotfix/vX.Y.Z vX.Y.0

# Make fixes, commit
git commit -am "Fix critical issue"

# Update version to X.Y.Z
# Update CHANGELOG.md
# Commit version bump
git commit -am "Bump version to vX.Y.Z"

# Tag and push
git tag -a vX.Y.Z -m "Hotfix release vX.Y.Z"
git push origin vX.Y.Z
```

## Docker Images (Optional)

If publishing Docker images:

```bash
# Build image
docker build -t drone_sec_sim:vX.Y.Z .
docker tag drone_sec_sim:vX.Y.Z drone_sec_sim:latest

# Push to registry (if configured)
docker push drone_sec_sim:vX.Y.Z
docker push drone_sec_sim:latest
```

## Version Number Examples

| Type of Change | Version Bump | Example |
|---------------|--------------|---------|
| New feature | MINOR | 0.1.0 → 0.2.0 |
| Bug fix | PATCH | 0.1.0 → 0.1.1 |
| Breaking change | MAJOR | 0.1.0 → 1.0.0 |
| Pre-release | Append identifier | 0.2.0-rc.1 |
