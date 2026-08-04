# SecureDocSharing

Minimal secure document sharing service built around ephemeral share sessions and a GitHub Actions driven delivery flow.

## What the service does

- Creates a share for a single recipient email address.
- Accepts a caller-supplied TTL.
- Supports an optional password.
- Generates a separate six-digit PIN.
- Packages a selected folder into an encrypted ZIP payload.
- Publishes a minimal static browser UI that prompts for email, password, and PIN before decrypting the ZIP locally.
- Removes expired shares from GitHub Pages on a scheduled cleanup workflow.

## Repository layout

- `app/service.py` implements share creation, hashing, recipient validation, PIN authorization, and lifecycle teardown.
- `app/api.py` exposes the service through simple callable entry points.
- `scripts/build_share_site.py` packages a folder into an encrypted static share site.
- `scripts/cleanup_expired_shares.py` removes expired shares from the published Pages content.
- `.github/workflows/create-share.yml` creates a share from GitHub Actions workflow inputs.
- `.github/workflows/cleanup-shares.yml` prunes expired share directories from GitHub Pages.
- `web/` contains the minimal browser UI.
- `tests/test_share_service.py` covers the share lifecycle behavior.

## GitHub Actions flow

The `Create Secure Share` workflow accepts these manual inputs:

- `recipient_email`
- `ttl_seconds`
- `password`
- `folder_path`

The workflow:

1. Zips the selected folder.
2. Creates a share session with the configured recipient, TTL, and optional password.
3. Encrypts the ZIP using a key derived from the recipient email, password, PIN, and share ID.
4. Publishes the share into the `gh-pages` branch.
5. Emits the share URL and PIN in the workflow summary.

The recipient opens the link, enters their email, password, and PIN, chooses where to save the ZIP, and then sees a simple completion screen.

## AWS proxy workflows

Use this path when you want GitHub Actions to create and operate an AWS-backed file share proxy.

Required repository secrets:

- `AWS_ACCESS_KEY`
- `AWS_SECRET_KEY`

Workflows:

1. `Deploy AWS Share Proxy` (`.github/workflows/deploy-aws-share-proxy.yml`)
	- Creates or updates the proxy infrastructure in AWS:
	- S3 bucket for payload ZIP objects
	- DynamoDB table for share metadata + TTL
	- Lambda function URL proxy for recipient authentication and download handoff

2. `Create AWS File Share` (`.github/workflows/create-aws-file-share.yml`)
	- Inputs:
	- `recipient_email`
	- `ttl_seconds`
	- `password` (optional, empty allowed)
	- `folder_path`
	- `aws_region`
	- `proxy_prefix`
	- Output:
	- Share URL and PIN in the workflow summary

3. `Cleanup AWS Shares` (`.github/workflows/cleanup-aws-shares.yml`)
	- Runs every 15 minutes and can be triggered manually.
	- Removes expired or consumed shares and deletes associated objects.

4. `Destroy AWS Share Proxy` (`.github/workflows/destroy-aws-share-proxy.yml`)
	- Manual teardown workflow for all proxy resources.
	- Inputs:
	- `aws_region`
	- `proxy_prefix`
	- `confirm_destroy` (must be exactly `DESTROY`)
	- Deletes:
	- Lambda function URL and Lambda function
	- DynamoDB table
	- S3 payload bucket contents and bucket
	- IAM inline role policy and IAM role

Behavior summary:

- The recipient visits the share URL and enters email, password (if required), and PIN.
- A successful flow returns a short-lived pre-signed download and then triggers consumption cleanup.
- Expired shares are removed by scheduled cleanup even when they were never opened.

## Important limitation

GitHub-hosted Actions plus static GitHub Pages can enforce TTL-based removal, but they cannot securely perform a globally authoritative teardown immediately after the first browser download without introducing a callback-capable backend. This implementation tears down the in-memory share session on authorization and removes expired published shares automatically, but first-download removal of the published static asset still requires a backend or a follow-up cleanup trigger.

## GitHub Pages setup

Configure the repository Pages source to serve from the `gh-pages` branch root.

## Run tests

```bash
python3 -m pytest
```
