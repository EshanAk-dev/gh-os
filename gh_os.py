#!/usr/bin/env python3
"""gh-os - github OSINT PII scanner"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table

API_BASE = "https://api.github.com"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
NOREPLY_RE = re.compile(r"^\d+\+.+@users\.noreply\.github\.com$|^.+@users\.noreply\.github\.com$")
BOT_EMAILS = {
    "noreply@github.com",
    "action@github.com",
    "actions@github.com",
    "github-actions[bot]@users.noreply.github.com",
    "dependabot[bot]@users.noreply.github.com",
    "dependabot-preview[bot]@users.noreply.github.com",
    "renovate[bot]@users.noreply.github.com",
    "github@users.noreply.github.com",
}
MAX_GIST_FILE_SIZE = 50 * 1024  # 50KB


@dataclass
class EmailFinding:
    email: str
    sources: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)


class GitHubScanner:
    def __init__(self, username: str, token: str | None = None,
                 include_forks: bool = False, max_repos: int = 100,
                 scan_gists: bool = True):
        self.username = username
        self.token = token
        self.include_forks = include_forks
        self.max_repos = max_repos
        self._scan_gists = scan_gists
        self.console = Console(stderr=True)

        self.emails: dict[str, EmailFinding] = {}
        self.profile_data: dict = {}
        self.social_accounts: list[dict] = []
        self.ssh_keys: list[dict] = []
        self.gpg_keys: list[dict] = []
        self.repos: list[dict] = []
        self.rate_limit_remaining: int | None = None
        self.repos_scanned = 0

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gh-os/0.1",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.AsyncClient(
            base_url=API_BASE,
            headers=headers,
            timeout=30.0,
            follow_redirects=True,
        )

    async def close(self):
        await self._client.aclose()

    # -- HTTP helpers --

    async def _request(self, path: str, params: dict | None = None) -> dict | list | None:
        try:
            resp = await self._client.get(path, params=params)
        except httpx.HTTPError as exc:
            self.console.print(f"[red]request failed: {path} - {exc}[/red]")
            return None

        # track rate limit
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            self.rate_limit_remaining = int(remaining)
            if self.rate_limit_remaining <= 10:
                self.console.print(f"[yellow]warning: only {self.rate_limit_remaining} API requests remaining[/yellow]")
            if self.rate_limit_remaining <= 0:
                self.console.print("[red]rate limit exhausted - stopping API calls[/red]")
                return None

        if resp.status_code == 403:
            self.console.print(f"[red]403 on {path} - likely rate limited[/red]")
            return None
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            self.console.print(f"[red]{resp.status_code} on {path}[/red]")
            return None

        return resp.json()

    async def _paginate(self, path: str, params: dict | None = None, max_pages: int = 10) -> list:
        results = []
        params = dict(params or {})
        params.setdefault("per_page", 100)
        page = 1

        while page <= max_pages:
            params["page"] = page
            data = await self._request(path, params)
            if not data or not isinstance(data, list):
                break
            results.extend(data)
            if len(data) < params["per_page"]:
                break
            page += 1

        return results

    # -- email tracking --

    def _add_email(self, email: str, source: str, name: str | None = None):
        if not email or not isinstance(email, str):
            return
        email = email.strip().lower()
        if not EMAIL_RE.fullmatch(email):
            return

        if email not in self.emails:
            self.emails[email] = EmailFinding(email=email)
        finding = self.emails[email]
        finding.sources.add(source)
        if name and name.strip():
            finding.names.add(name.strip())

    # -- scanners --

    async def scan_profile(self):
        data = await self._request(f"/users/{self.username}")
        if not data:
            self.console.print(f"[red]user '{self.username}' not found[/red]")
            sys.exit(1)
        self.profile_data = data

        if data.get("email"):
            self._add_email(data["email"], "profile", data.get("name"))

    async def scan_social_accounts(self):
        data = await self._request(f"/users/{self.username}/social_accounts")
        if data and isinstance(data, list):
            self.social_accounts = data

    async def scan_events(self):
        events = await self._paginate(f"/users/{self.username}/events/public", max_pages=3)
        for event in events:
            if event.get("type") != "PushEvent":
                continue
            payload = event.get("payload", {})
            for commit in payload.get("commits", []):
                author = commit.get("author", {})
                self._add_email(
                    author.get("email", ""),
                    "events",
                    author.get("name"),
                )

    async def scan_gpg_keys(self):
        keys = await self._request(f"/users/{self.username}/gpg_keys")
        if not keys or not isinstance(keys, list):
            return
        self.gpg_keys = keys
        for key in keys:
            for email_entry in key.get("emails", []):
                self._add_email(
                    email_entry.get("email", ""),
                    "gpg",
                    None,
                )

    async def scan_ssh_keys(self):
        keys = await self._request(f"/users/{self.username}/keys")
        if keys and isinstance(keys, list):
            self.ssh_keys = keys

    async def scan_repos(self):
        params = {"type": "owner", "sort": "updated"}
        repos = await self._paginate(f"/users/{self.username}/repos", params, max_pages=10)
        if not self.include_forks:
            repos = [r for r in repos if not r.get("fork")]
        self.repos = repos[:self.max_repos]

    async def scan_repo_emails(self, repo: dict, sem: asyncio.Semaphore):
        async with sem:
            clone_url = repo.get("clone_url", "")
            repo_name = repo.get("full_name", repo.get("name", "unknown"))

            with tempfile.TemporaryDirectory() as tmpdir:
                repo_dir = os.path.join(tmpdir, "repo.git")
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "git", "clone", "--bare", "--filter=blob:none",
                        "--quiet", clone_url, repo_dir,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.wait_for(proc.wait(), timeout=120)
                    if proc.returncode != 0:
                        return
                except (asyncio.TimeoutError, OSError):
                    return

                try:
                    proc = await asyncio.create_subprocess_exec(
                        "git", "-C", repo_dir, "log",
                        "--format=%ae%n%an%n%ce%n%cn",
                        "--all",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                except (asyncio.TimeoutError, OSError):
                    return

            if not stdout:
                return

            lines = stdout.decode("utf-8", errors="replace").splitlines()
            # format repeats: author_email, author_name, committer_email, committer_name
            i = 0
            while i + 3 < len(lines):
                ae, an, ce, cn = lines[i], lines[i + 1], lines[i + 2], lines[i + 3]
                self._add_email(ae, f"commit:{repo_name}", an)
                self._add_email(ce, f"commit:{repo_name}", cn)
                i += 4

            self.repos_scanned += 1

    async def scan_gists(self):
        if not self._scan_gists:
            return

        gists = await self._paginate(f"/users/{self.username}/gists", max_pages=5)
        for gist in gists:
            for filename, file_info in gist.get("files", {}).items():
                size = file_info.get("size", 0)
                if size > MAX_GIST_FILE_SIZE:
                    continue
                raw_url = file_info.get("raw_url")
                if not raw_url:
                    continue
                try:
                    async with httpx.AsyncClient(timeout=15.0) as tmp_client:
                        resp = await tmp_client.get(raw_url)
                    if resp.status_code != 200:
                        continue
                    content = resp.text
                except httpx.HTTPError:
                    continue

                for match in EMAIL_RE.findall(content):
                    # basic sanity - skip things that look like version strings or paths
                    if ".." in match or match.endswith(".png") or match.endswith(".jpg"):
                        continue
                    self._add_email(match, f"gist:{gist.get('id', '')[:8]}")

    # -- orchestration --

    async def run(self):
        # phase 1 - parallel metadata
        self.console.print(f"[bold]scanning github user:[/bold] {self.username}\n")

        await self.scan_profile()
        if not self.profile_data:
            return

        await asyncio.gather(
            self.scan_social_accounts(),
            self.scan_events(),
            self.scan_gpg_keys(),
            self.scan_ssh_keys(),
        )

        # phase 2 - list repos
        await self.scan_repos()
        self.console.print(f"found {len(self.repos)} repos to scan")

        # phase 3 - clone + git log (parallel with semaphore)
        if self.repos:
            sem = asyncio.Semaphore(5)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("cloning repos", total=len(self.repos))

                async def scan_with_progress(repo):
                    await self.scan_repo_emails(repo, sem)
                    progress.advance(task)

                await asyncio.gather(*(scan_with_progress(r) for r in self.repos))

        # phase 4 - gists
        if self._scan_gists:
            self.console.print("scanning gists...")
            await self.scan_gists()

    # -- output --

    def _classify_email(self, email: str) -> str:
        """return a rich color tag for the email type"""
        if email in BOT_EMAILS or "[bot]" in email:
            return "dim"
        if NOREPLY_RE.match(email):
            return "dim"
        sources = self.emails[email].sources
        if "profile" in sources:
            return "green"
        if "gpg" in sources:
            return "cyan"
        if any(s.startswith("gist:") for s in sources):
            return "magenta"
        if any(s.startswith("commit:") for s in sources):
            return "yellow"
        return "white"

    def print_results(self):
        console = Console()

        # profile panel
        p = self.profile_data
        profile_lines = []
        if p.get("name"):
            profile_lines.append(f"[bold]name:[/bold] {p['name']}")
        if p.get("email"):
            profile_lines.append(f"[bold]email:[/bold] {p['email']}")
        if p.get("company"):
            profile_lines.append(f"[bold]company:[/bold] {p['company']}")
        if p.get("location"):
            profile_lines.append(f"[bold]location:[/bold] {p['location']}")
        if p.get("blog"):
            profile_lines.append(f"[bold]blog:[/bold] {p['blog']}")
        if p.get("twitter_username"):
            profile_lines.append(f"[bold]twitter:[/bold] @{p['twitter_username']}")
        if p.get("bio"):
            profile_lines.append(f"[bold]bio:[/bold] {p['bio']}")

        if profile_lines:
            console.print(Panel(
                "\n".join(profile_lines),
                title=f"@{self.username} (id: {p.get('id', '?')})",
                border_style="blue",
            ))

        # social accounts
        if self.social_accounts:
            table = Table(title="social accounts", show_header=True)
            table.add_column("provider")
            table.add_column("url")
            for acct in self.social_accounts:
                table.add_row(acct.get("provider", "?"), acct.get("url", ""))
            console.print(table)

        # SSH keys
        if self.ssh_keys:
            table = Table(title="SSH keys", show_header=True)
            table.add_column("id")
            table.add_column("fingerprint")
            for key in self.ssh_keys:
                raw = key.get("key", "")
                try:
                    key_bytes = base64.b64decode(raw.split()[1] if " " in raw else raw)
                    fp = hashlib.sha256(key_bytes).hexdigest()
                    fp_display = f"SHA256:{fp[:32]}"
                except Exception:
                    fp_display = raw[:40] + "..."
                table.add_row(str(key.get("id", "")), fp_display)
            console.print(table)

        # GPG keys
        if self.gpg_keys:
            table = Table(title="GPG keys", show_header=True)
            table.add_column("key ID")
            table.add_column("emails")
            for key in self.gpg_keys:
                emails = ", ".join(e.get("email", "") for e in key.get("emails", []))
                table.add_row(str(key.get("key_id", "")), emails)
            console.print(table)

        # email findings
        if self.emails:
            table = Table(title=f"email findings ({len(self.emails)})", show_header=True)
            table.add_column("email")
            table.add_column("names")
            table.add_column("sources")

            # sort - profile first, then non-noreply, then noreply/bot
            def sort_key(e: EmailFinding):
                if "profile" in e.sources:
                    return (0, e.email)
                if e.email in BOT_EMAILS or NOREPLY_RE.match(e.email):
                    return (2, e.email)
                return (1, e.email)

            for finding in sorted(self.emails.values(), key=sort_key):
                color = self._classify_email(finding.email)
                names_str = ", ".join(sorted(finding.names)) if finding.names else ""
                # collapse commit sources
                sources = set()
                commit_repos = []
                for s in finding.sources:
                    if s.startswith("commit:"):
                        commit_repos.append(s[7:])
                    else:
                        sources.add(s)
                if commit_repos:
                    if len(commit_repos) <= 3:
                        sources.add(f"commits({', '.join(commit_repos)})")
                    else:
                        sources.add(f"commits({len(commit_repos)} repos)")
                sources_str = ", ".join(sorted(sources))

                table.add_row(
                    f"[{color}]{finding.email}[/{color}]",
                    names_str,
                    sources_str,
                )

            console.print(table)
        else:
            console.print("[yellow]no emails found[/yellow]")

        # summary
        noreply_count = sum(1 for e in self.emails if NOREPLY_RE.match(e) or e in BOT_EMAILS)
        real_count = len(self.emails) - noreply_count
        console.print(
            f"\n[bold]{len(self.emails)}[/bold] unique emails "
            f"([green]{real_count} real[/green], [dim]{noreply_count} noreply/bot[/dim]) | "
            f"{self.repos_scanned} repos scanned | "
            f"rate limit remaining: {self.rate_limit_remaining or '?'}"
        )

    def to_json(self) -> dict:
        emails = []
        for finding in sorted(self.emails.values(), key=lambda f: f.email):
            emails.append({
                "email": finding.email,
                "names": sorted(finding.names),
                "sources": sorted(finding.sources),
                "is_noreply": bool(NOREPLY_RE.match(finding.email)),
                "is_bot": finding.email in BOT_EMAILS,
            })

        p = self.profile_data
        return {
            "username": self.username,
            "profile": {
                "id": p.get("id"),
                "name": p.get("name"),
                "email": p.get("email"),
                "company": p.get("company"),
                "location": p.get("location"),
                "blog": p.get("blog"),
                "twitter": p.get("twitter_username"),
                "bio": p.get("bio"),
            },
            "social_accounts": self.social_accounts,
            "ssh_keys": [{"id": k.get("id"), "key": k.get("key")} for k in self.ssh_keys],
            "gpg_keys": [
                {"key_id": k.get("key_id"), "emails": [e.get("email") for e in k.get("emails", [])]}
                for k in self.gpg_keys
            ],
            "emails": emails,
            "stats": {
                "total_emails": len(emails),
                "repos_scanned": self.repos_scanned,
                "rate_limit_remaining": self.rate_limit_remaining,
            },
        }


def parse_args():
    parser = argparse.ArgumentParser(
        prog="gh-os",
        description="github OSINT PII scanner - enumerate emails and PII from a github user",
    )
    parser.add_argument("username", help="github username to scan")
    parser.add_argument("-t", "--token", default=None,
                        help="github API token (or set GITHUB_TOKEN / GH_TOKEN)")
    parser.add_argument("--include-forks", action="store_true",
                        help="include forked repos in scan")
    parser.add_argument("--max-repos", type=int, default=100,
                        help="max repos to clone and scan (default: 100)")
    parser.add_argument("--no-gists", action="store_true",
                        help="skip gist scanning")
    parser.add_argument("--json", action="store_true",
                        help="output raw JSON to stdout")
    return parser.parse_args()


def main():
    args = parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        Console(stderr=True).print(
            "[yellow]no token provided - using unauthenticated API (60 req/hr)[/yellow]\n"
            "[yellow]set GITHUB_TOKEN or use -t for 5000 req/hr[/yellow]\n"
        )

    scanner = GitHubScanner(
        username=args.username,
        token=token,
        include_forks=args.include_forks,
        max_repos=args.max_repos,
        scan_gists=not args.no_gists,
    )

    async def _run_and_close():
        try:
            await scanner.run()
        finally:
            await scanner.close()

    try:
        asyncio.run(_run_and_close())
    except KeyboardInterrupt:
        Console(stderr=True).print("\n[yellow]interrupted[/yellow]")

    if args.json:
        print(json.dumps(scanner.to_json(), indent=2))
    else:
        scanner.print_results()


if __name__ == "__main__":
    main()
