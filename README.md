# gh-os

github OSINT PII scanner. pulls every email and piece of identifying info it can find from a github account.

## what it does

enumerates a target's PII across every surface github exposes:

- **profile** - name, email, company, location, blog, twitter, bio
- **social accounts** - linked accounts via the social_accounts API
- **public events** - commit author/committer emails from push events (90 day window)
- **GPG keys** - emails embedded in public keys
- **SSH keys** - fingerprints for cross-referencing
- **repo history** - bare clones every repo + `git log` to extract all commit emails/names ever used. way more thorough than the commits API - no pagination cap, no 90 day limit.
- **gists** - regex scans gist content for email patterns

emails get deduped, merged across sources, and color-coded in the output. noreply/bot addresses shown dimmed so you can focus on real ones.

## install

```
pip install httpx rich
```

needs `git` on PATH for the repo cloning.

## usage

```
python gh_os.py <username> [-t TOKEN] [--include-forks] [--max-repos N] [--no-gists] [--json]
```

token from `-t`, `GITHUB_TOKEN`, or `GH_TOKEN` env var. without one you get 60 req/hr - with one, 5000.

```bash
python gh_os.py torvalds
python gh_os.py torvalds --json | jq '.emails[] | select(.is_noreply == false)'
python gh_os.py torvalds -t ghp_xxx --include-forks --max-repos 200
```

`--json` dumps structured JSON to stdout (status/progress goes to stderr) so you can pipe it.

## how it works

1. hits the API for profile, social accounts, events, GPG/SSH keys (parallel)
2. lists repos, filters forks unless `--include-forks`
3. bare clones each repo with `--filter=blob:none` (no blobs - just refs and commits), runs `git log` to extract every email/name. 5 concurrent clones. progress bar shown.
4. scans gist contents for email patterns (skips files >50KB)
5. deduplicates everything, merges sources/names, prints a color-coded table

the clone approach is the key thing - the commits API caps at 300 events and misses old history. `git log --all` on a bare clone gets everything.

## rate limits

unauthenticated gets you 60 API requests/hr. use a token. git clones don't count against the API rate limit - that's why the clone approach works so well even on accounts with hundreds of repos.

## license

do what you want with it.
