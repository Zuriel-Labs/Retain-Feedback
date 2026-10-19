"""Import Retain's written App Store reviews into public feedback issues."""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt


APP_ID = "6816576807"
APPLE_HOST = "api.appstoreconnect.apple.com"
REVIEW_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
ISSUE_MARKER = re.compile(r"<!-- App-Store-Review-ID: ([A-Za-z0-9._-]{1,128}) -->")
MANAGED_START = "<!-- BEGIN RETAIN REVIEW IMPORT -->"
MANAGED_END = "<!-- END RETAIN REVIEW IMPORT -->"
REPOSITORY = "Zuriel-Labs/Retain-Feedback"
BOT_LOGIN = "github-actions[bot]"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


_open_without_redirects = build_opener(NoRedirect()).open


def make_token(key_id, issuer_id, private_key, now=None):
    now = int(time.time() if now is None else now)
    try:
        return jwt.encode(
            {
                "iss": issuer_id,
                "iat": now,
                "exp": now + 600,
                "aud": "appstoreconnect-v1",
                "scope": [f"GET /v1/apps/{APP_ID}/customerReviews"],
            },
            private_key,
            algorithm="ES256",
            headers={"kid": key_id, "typ": "JWT"},
        )
    except (jwt.PyJWTError, ValueError, TypeError):
        raise RuntimeError("Apple signing key is invalid") from None


def _apple_page_url(url):
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.netloc != APPLE_HOST
            or parts.path != f"/v1/apps/{APP_ID}/customerReviews" or parts.fragment):
        raise ValueError("Unexpected Apple page URL")


def list_apple_reviews(fetch):
    url = f"https://{APPLE_HOST}/v1/apps/{APP_ID}/customerReviews?limit=200"
    seen_pages = set()
    reviews = []
    while url:
        _apple_page_url(url)
        if url in seen_pages:
            raise ValueError("Repeated Apple page URL")
        seen_pages.add(url)
        page = fetch(url)
        if not isinstance(page, dict) or not isinstance(page.get("data"), list):
            raise ValueError("Malformed Apple review page")
        for item in page["data"]:
            if not isinstance(item, dict) or item.get("type") != "customerReviews":
                raise ValueError("Malformed Apple review resource")
            review_id = item.get("id")
            if not isinstance(review_id, str) or not REVIEW_ID.fullmatch(review_id):
                raise ValueError("Invalid Apple review ID")
            attrs = item.get("attributes")
            if not isinstance(attrs, dict):
                raise ValueError("Missing Apple review attributes")
            rating = attrs.get("rating")
            if type(rating) is not int or not 1 <= rating <= 5:
                raise ValueError("Invalid Apple review rating")
            for field in ("title", "body", "createdDate", "territory"):
                if not isinstance(attrs.get(field), str):
                    raise ValueError(f"Invalid Apple review {field}")
            reviews.append(item)
        links = page.get("links", {})
        if not isinstance(links, dict):
            raise ValueError("Malformed Apple review links")
        url = links.get("next")
        if url is not None and not isinstance(url, str):
            raise ValueError("Malformed Apple next page URL")
    return reviews


def _plain_text(value, limit):
    cleaned = " ".join(value.split()).replace("@", "＠")
    return cleaned[:limit]


def _safe_review_text(value):
    return value.replace("@", "＠").replace("<", "&lt;")


def _managed_review(review):
    review_id = review["id"]
    if not REVIEW_ID.fullmatch(review_id):
        raise ValueError("Invalid Apple review ID")
    attrs = review["attributes"]
    relevant = {key: attrs[key] for key in ("rating", "title", "body", "createdDate", "territory")}
    fingerprint = hashlib.sha256(json.dumps(relevant, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    excerpt = _safe_review_text(attrs["body"])
    excerpt = "\n".join("    " + line for line in excerpt.splitlines()) or "    (No written body)"
    return "\n".join((
        MANAGED_START,
        f"<!-- App-Store-Review-ID: {review_id} -->",
        f"<!-- Content-SHA256: {fingerprint} -->",
        f"Rating: {attrs['rating']}/5 · Territory: {_safe_review_text(_plain_text(attrs['territory'], 32))} · Reviewed: {_safe_review_text(_plain_text(attrs['createdDate'], 40))}",
        f"Title: {_safe_review_text(_plain_text(attrs['title'], 120))}",
        "",
        excerpt,
        MANAGED_END,
    ))


def _issue_labels(issue):
    return {label if isinstance(label, str) else label["name"] for label in issue.get("labels", [])}


def reconcile_reviews(reviews, issues, create_issue, update_issue):
    existing = {}
    for issue in issues:
        if "pull_request" in issue:
            continue
        if (issue.get("user", {}).get("login") != BOT_LOGIN
                or "app-store-review" not in _issue_labels(issue)):
            continue
        markers = ISSUE_MARKER.findall(issue.get("body") or "")
        if len(markers) > 1:
            raise ValueError("Multiple review IDs on one issue")
        if markers:
            if markers[0] in existing:
                raise ValueError("Duplicate review ID across issues")
            existing[markers[0]] = issue

    incoming = set()
    for review in reviews:
        review_id = review["id"]
        if review_id in incoming:
            raise ValueError("Duplicate review ID in Apple response")
        incoming.add(review_id)

    created = updated = 0
    for review in reviews:
        review_id = review["id"]
        managed = _managed_review(review)
        issue = existing.get(review_id)
        if issue is None:
            attrs = review["attributes"]
            title = _plain_text(f"[App Store review] {attrs['rating']}★ {attrs['title']}", 120)
            create_issue({
                "title": title,
                "body": managed + "\n\nTriage: reproduce or confirm the feedback before opening a fix issue.\n",
                "labels": ["app-store-review", "needs-triage"],
            })
            created += 1
            continue

        body = issue.get("body") or ""
        start = body.find(MANAGED_START)
        end = body.find(MANAGED_END, start + len(MANAGED_START))
        if start < 0 or end < 0:
            raise ValueError(f"Review issue {issue['number']} has no managed section")
        current = body[start:end + len(MANAGED_END)]
        if current == managed:
            continue
        labels = _issue_labels(issue) | {"app-store-review", "needs-triage"}
        patch = {"body": body[:start] + managed + body[end + len(MANAGED_END):], "labels": sorted(labels)}
        if issue.get("state") == "closed":
            patch["state"] = "open"
        update_issue(issue["number"], patch)
        updated += 1
    return created, updated


def request_json(url, token, method="GET", payload=None, opener=_open_without_redirects, sleeper=time.sleep):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers, method=method)
    host = urlsplit(url).hostname
    for attempt in range(4):
        try:
            with opener(request, timeout=30) as response:
                try:
                    return json.loads(response.read())
                except (ValueError, UnicodeDecodeError) as error:
                    raise RuntimeError(f"Invalid JSON from {host}") from error
        except HTTPError as error:
            error.close()
            if error.code in (429, 503) and attempt < 3:
                retry_after = error.headers.get("Retry-After", "")
                delay = min(int(retry_after), 30) if retry_after.isdigit() else min(2 ** attempt, 30)
                sleeper(delay)
                continue
            raise RuntimeError(f"HTTP {error.code} from {host}") from None
        except URLError:
            raise RuntimeError(f"Network error from {host}") from None
    raise RuntimeError(f"Request failed from {host}")


def list_github_issues(fetch, repository=REPOSITORY):
    issues = []
    seen_numbers = set()
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repository}/issues?state=all&per_page=100&page={page}"
        batch = fetch(url)
        if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
            raise ValueError("Malformed GitHub issues page")
        numbers = {item.get("number") for item in batch}
        if seen_numbers & numbers:
            raise ValueError("Repeated GitHub issue across pages")
        seen_numbers.update(numbers)
        issues.extend(batch)
        if len(batch) < 100:
            return issues
        page += 1


def run_import(apple_fetch, github_fetch, create_issue, update_issue):
    reviews = list_apple_reviews(apple_fetch)
    issues = list_github_issues(github_fetch)
    return reconcile_reviews(reviews, issues, create_issue, update_issue)


def main(argv=None, environ=None, request=request_json):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="create or update public feedback issues")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    if env.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError(f"GitHub repository must be {REPOSITORY}")
    required = ("ASC_KEY_ID", "ASC_ISSUER_ID", "ASC_PRIVATE_KEY", "GITHUB_TOKEN")
    missing = [name for name in required if not env.get(name)]
    if missing:
        raise ValueError("Missing environment values: " + ", ".join(missing))

    def apple_fetch(url):
        token = make_token(env["ASC_KEY_ID"], env["ASC_ISSUER_ID"], env["ASC_PRIVATE_KEY"])
        return request(url, token)

    github_base = f"https://api.github.com/repos/{REPOSITORY}/issues"
    github_fetch = lambda url: request(url, env["GITHUB_TOKEN"])
    if args.apply:
        create = lambda payload: request(github_base, env["GITHUB_TOKEN"], "POST", payload)
        update = lambda number, payload: request(f"{github_base}/{number}", env["GITHUB_TOKEN"], "PATCH", payload)
    else:
        create = lambda payload: None
        update = lambda number, payload: None
    created, updated = run_import(apple_fetch, github_fetch, create, update)
    if not args.apply:
        print(f"Would create {created} issues; would update {updated} issues")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
