# Default recipe
default:
    @just --list

# Run tests
test:
    cargo test

# Build release binary
build:
    cargo build --release

# Generate changelog
changelog:
    git cliff -o CHANGELOG.md

# Release a new version
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    
    VERSION="{{version}}"
    
    # Validate version format
    if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Version must be in format X.Y.Z (e.g., 0.1.0)"
        exit 1
    fi
    
    echo "Releasing v$VERSION..."
    
    # Update Cargo.toml
    sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
    
    # Update PKGBUILD
    sed -i "s/^pkgver=.*/pkgver=$VERSION/" PKGBUILD
    
    # Update Cargo.lock
    cargo update -p vuke
    
    # Generate changelog
    git cliff --tag "v$VERSION" -o CHANGELOG.md
    
    # Commit changes
    git add Cargo.toml Cargo.lock PKGBUILD CHANGELOG.md
    git commit -m "chore(release): v$VERSION"
    
    # Create tag
    git tag -a "v$VERSION" -m "Release v$VERSION"
    
    echo ""
    echo "Release v$VERSION ready!"
    echo "Run 'git push && git push --tags' to publish"
