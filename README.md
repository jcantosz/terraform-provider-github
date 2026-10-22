# Terraform Provider GitHub

|<img src="https://cloud.githubusercontent.com/assets/98681/24211275/c4ebd04e-0ee8-11e7-8606-061d656a42df.png" width="72" height="" alt="GitHub Logo"> | <img src="https://raw.githubusercontent.com/hashicorp/terraform-website/d841a1e5fca574416b5ca24306f85a0f4f41b36d/content/source/assets/images/logo-terraform-main.svg" width="300px" alt="Terraform Logo">|

This provider manages GitHub resources — repositories, teams, branch protections, actions secrets/variables, organization settings, rulesets, deploy keys, webhooks, and more — using Terraform. It supports both GitHub.com and GitHub Enterprise Server via the REST and GraphQL APIs.

See the [GitHub Provider page on the Terraform Registry](https://registry.terraform.io/providers/integrations/github/) for installation and documentation.

## Quick Start

```hcl
provider "github" {
  owner = "my-org"
}

resource "github_repository" "example" {
  name        = "example-repo"
  description = "Managed by Terraform"
  visibility  = "private"
}
```

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) 1.x
- [Go](https://golang.org/doc/install) 1.26.x (to build the provider plugin)

## Usage

Detailed documentation for the GitHub provider can be found in the [Terraform Registry](https://registry.terraform.io/providers/integrations/github).

## Contributing

For instructions on how to contribute to the GitHub Terraform provider, see the [Contributing Guide](CONTRIBUTING.md).

## Fork prerelease binaries

The [Fork prerelease workflow](.github/workflows/fork-release.yaml) builds unsigned
development binaries without the GPG secrets used by the existing signed release
workflow. It runs only outside the upstream `integrations/terraform-provider-github`
repository and publishes to the repository where it is run.

Commit and push the workflow and all provider changes first. You can then run it
manually against a branch or tag using a new `local-v` release tag:

```sh
gh workflow run fork-release.yaml \
  --repo jcantosz/terraform-provider-github \
  --ref main \
  -f tag=local-v6.13.0-test.1
```

Alternatively, push a tag for the commit to release:

```sh
git tag local-v6.13.0-test.1
git push origin local-v6.13.0-test.1
```

Tags must have the form `local-vMAJOR.MINOR.PATCH` with an optional prerelease
suffix. For manual runs, an existing tag must point to the selected commit.
Choose a new tag for each release; existing releases are not overwritten.
The `local-v` prefix avoids triggering the signed upstream `v*` release workflow.

After unit tests pass, the workflow builds Linux, macOS, and Windows binaries for
both `amd64` and `arm64`. Each ZIP contains a versioned provider executable. The
release also includes a SHA-256 checksum file. Uploads are staged in a draft before
the release is published as a prerelease, never as the repository's latest release.
If an upload fails, inspect the draft before retrying; the workflow deliberately
does not replace existing releases or delete their assets.

The built-in `GITHUB_TOKEN` is the only required release credential; repository
Actions settings must allow the publish job's `contents: write` permission.
These builds are **not signed Terraform Registry releases**. To use one with the
existing local-provider setup, download the ZIP for your platform, verify it
against the checksum file, and extract it to a dedicated directory. Point the
`integrations/github` development override at that directory instead of the local
build directory. Keep only one provider executable in the override directory.
Terraform's development override warning is expected.

## Roadmap

This project uses [Milestones](https://github.com/integrations/terraform-provider-github/milestones) to scope upcoming features and bug fixes. Issues that receive the most recent discussion or the most reactions will be more likely to be included in an upcoming release.

## Support

GitHub Support does not provide support for this integration. This is a community-supported project. GitHub's SDK team triages issues and PRs periodically.
