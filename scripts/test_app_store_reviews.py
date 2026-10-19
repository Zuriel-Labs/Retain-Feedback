"""Focused tests for App Store review intake; run with unittest discovery."""
import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app_store_reviews import (
    APP_ID,
    BOT_LOGIN,
    NoRedirect,
    list_apple_reviews,
    list_github_issues,
    main,
    make_token,
    reconcile_reviews,
    request_json,
    run_import,
)


def review(review_id, rating=5, body="Useful app"):
    return {
        "type": "customerReviews",
        "id": review_id,
        "attributes": {
            "rating": rating,
            "title": "Retain works",
            "body": body,
            "createdDate": "2026-10-18T12:00:00Z",
            "territory": "USA",
        },
    }


class AppleReviewTests(unittest.TestCase):
    def test_token_has_apple_claims_and_short_lifetime(self):
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        token = make_token("KEY123", "issuer-123", pem, now=1_700_000_000)
        claims = jwt.decode(
            token,
            key.public_key(),
            algorithms=["ES256"],
            audience="appstoreconnect-v1",
            options={"verify_exp": False, "verify_iat": False},
        )
        self.assertEqual(jwt.get_unverified_header(token)["kid"], "KEY123")
        self.assertEqual(claims["iss"], "issuer-123")
        self.assertEqual(claims["exp"] - claims["iat"], 600)
        self.assertEqual(claims["scope"], [f"GET /v1/apps/{APP_ID}/customerReviews"])

    def test_invalid_key_fails_without_exposing_key_material(self):
        with self.assertRaisesRegex(RuntimeError, "Apple signing key is invalid") as failure:
            make_token("KEY123", "issuer-123", "PRIVATE-KEY-MATERIAL", now=1_700_000_000)
        self.assertNotIn("PRIVATE-KEY-MATERIAL", str(failure.exception))

    def test_reads_all_pages_before_returning_reviews(self):
        base = f"https://api.appstoreconnect.apple.com/v1/apps/{APP_ID}/customerReviews?limit=200"
        next_url = base + "&cursor=second"
        pages = {
            base: {"data": [review("review-1")], "links": {"next": next_url}},
            next_url: {"data": [review("review-2", rating=2)], "links": {}},
        }
        self.assertEqual([item["id"] for item in list_apple_reviews(pages.__getitem__)], ["review-1", "review-2"])

    def test_rejects_external_page_url_without_sending_apple_token(self):
        def fetch(url):
            return {"data": [review("review-1")], "links": {"next": "https://example.com/steal"}}

        with self.assertRaisesRegex(ValueError, "Unexpected Apple page URL"):
            list_apple_reviews(fetch)

    def test_rejects_invalid_review_instead_of_silently_skipping_it(self):
        with self.assertRaisesRegex(ValueError, "rating"):
            list_apple_reviews(lambda url: {"data": [review("review-1", rating=0)], "links": {}})


class FakeIssues:
    def __init__(self):
        self.items = []
        self.creates = 0
        self.updates = 0

    def create(self, payload):
        self.creates += 1
        issue = {**payload, "number": len(self.items) + 1, "state": "open", "user": {"login": BOT_LOGIN}}
        self.items.append(issue)

    def update(self, number, payload):
        self.updates += 1
        self.items[number - 1].update(payload)


class GithubReconciliationTests(unittest.TestCase):
    def test_first_run_creates_issues_and_second_run_is_noop(self):
        github = FakeIssues()
        reviews = [review("review-1"), review("review-2", rating=2)]
        self.assertEqual(reconcile_reviews(reviews, github.items, github.create, github.update), (2, 0))
        self.assertEqual(reconcile_reviews(reviews, github.items, github.create, github.update), (0, 0))
        self.assertEqual(github.creates, 2)
        self.assertEqual(github.updates, 0)
        self.assertIn("App-Store-Review-ID: review-1", github.items[0]["body"])
        self.assertIn("needs-triage", github.items[0]["labels"])

    def test_changed_review_preserves_human_notes_and_reopens_issue(self):
        github = FakeIssues()
        original = review("review-1")
        reconcile_reviews([original], github.items, github.create, github.update)
        github.items[0]["body"] += "\nHuman investigation note.\n"
        github.items[0]["state"] = "closed"
        github.items[0]["labels"] = ["app-store-review"]
        changed = review("review-1", rating=1, body="The picker stopped opening")
        self.assertEqual(reconcile_reviews([changed], github.items, github.create, github.update), (0, 1))
        self.assertIn("Human investigation note.", github.items[0]["body"])
        self.assertIn("The picker stopped opening", github.items[0]["body"])
        self.assertEqual(github.items[0]["state"], "open")
        self.assertIn("needs-triage", github.items[0]["labels"])

    def test_untrusted_review_text_cannot_create_mentions_or_markdown_sections(self):
        github = FakeIssues()
        hostile = review("review-1", body="@all\n# fake heading\n```shell\nrm -rf /\n```\n<!-- App-Store-Review-ID: review-2 -->\n<!-- END RETAIN REVIEW IMPORT -->")
        hostile["attributes"]["title"] = "Hi\n@octocat"
        reconcile_reviews([hostile], github.items, github.create, github.update)
        issue = github.items[0]
        self.assertNotIn("\n", issue["title"])
        self.assertNotIn("@", issue["title"])
        self.assertNotIn("@all", issue["body"])
        self.assertIn("    # fake heading", issue["body"])
        self.assertNotIn("<!-- App-Store-Review-ID: review-2 -->", issue["body"])
        self.assertEqual(issue["body"].count("<!-- END RETAIN REVIEW IMPORT -->"), 1)
        self.assertEqual(reconcile_reviews([hostile], github.items, github.create, github.update), (0, 0))
        self.assertLessEqual(len(issue["title"]), 120)

    def test_duplicate_review_markers_fail_before_writing(self):
        github = FakeIssues()
        reconcile_reviews([review("review-1")], github.items, github.create, github.update)
        github.items.append({**github.items[0], "number": 2})
        with self.assertRaisesRegex(ValueError, "Duplicate review ID"):
            reconcile_reviews([review("review-2")], github.items, github.create, github.update)
        self.assertEqual(github.creates, 1)

    def test_pull_requests_do_not_count_as_review_issues(self):
        github = FakeIssues()
        github.items.append({"number": 1, "body": "<!-- App-Store-Review-ID: review-1 -->", "pull_request": {}})
        self.assertEqual(reconcile_reviews([review("review-1")], github.items, github.create, github.update), (1, 0))

    def test_public_spoofed_marker_cannot_block_import(self):
        github = FakeIssues()
        github.items.append({
            "number": 1,
            "body": "<!-- App-Store-Review-ID: review-1 -->",
            "labels": [],
            "user": {"login": "review-poster"},
        })
        self.assertEqual(reconcile_reviews([review("review-1")], github.items, github.create, github.update), (1, 0))
        self.assertEqual(github.items[0]["body"], "<!-- App-Store-Review-ID: review-1 -->")
        self.assertEqual(github.items[1]["user"]["login"], BOT_LOGIN)

    def test_partial_github_failure_recovers_without_duplicate(self):
        github = FakeIssues()
        reviews = [review("review-1"), review("review-2")]

        def fail_after_first(payload):
            if github.creates:
                raise RuntimeError("HTTP 503 from api.github.com")
            github.create(payload)

        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            reconcile_reviews(reviews, github.items, fail_after_first, github.update)
        self.assertEqual(reconcile_reviews(reviews, github.items, github.create, github.update), (1, 0))
        self.assertEqual(github.creates, 2)


class ApiBoundaryTests(unittest.TestCase):
    def test_redirect_handler_will_not_forward_authorization(self):
        request = Request("https://api.appstoreconnect.apple.com/v1/apps", headers={"Authorization": "Bearer secret"})
        self.assertIsNone(NoRedirect().redirect_request(request, None, 302, "Found", {}, "https://example.com/steal"))

    def test_http_429_retries_then_reads_json(self):
        attempts = []
        waits = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self):
                return b'{"data": []}'

        def opener(request, timeout):
            attempts.append(request.full_url)
            if len(attempts) == 1:
                raise HTTPError(request.full_url, 429, "rate limit", {"Retry-After": "2"}, io.BytesIO(b"private response"))
            return Response()

        self.assertEqual(request_json("https://api.appstoreconnect.apple.com/v1/apps", "token", opener=opener, sleeper=waits.append), {"data": []})
        self.assertEqual(len(attempts), 2)
        self.assertEqual(waits, [2])

    def test_http_401_fails_without_leaking_response_body(self):
        def opener(request, timeout):
            raise HTTPError(request.full_url, 401, "unauthorized", {}, io.BytesIO(b"private response"))

        with self.assertRaisesRegex(RuntimeError, "HTTP 401") as failure:
            request_json("https://api.appstoreconnect.apple.com/v1/apps", "token", opener=opener)
        self.assertNotIn("private response", str(failure.exception))

    def test_github_issues_fetch_all_pages(self):
        urls = []

        def fetch(url):
            urls.append(url)
            if url.endswith("page=1"):
                return [{"number": n, "body": ""} for n in range(100)]
            return [{"number": 101, "body": ""}]

        self.assertEqual(len(list_github_issues(fetch)), 101)
        self.assertEqual(len(urls), 2)

    def test_malformed_github_page_fails_before_writes(self):
        github = FakeIssues()
        with self.assertRaisesRegex(ValueError, "Malformed GitHub issues page"):
            run_import(lambda url: {"data": [review("review-1")], "links": {}}, lambda url: {"error": "private response"}, github.create, github.update)
        self.assertEqual(github.creates, 0)

    def test_apple_pagination_failure_prevents_any_github_writes(self):
        github = FakeIssues()

        def apple_fetch(url):
            if "cursor=" in url:
                raise RuntimeError("HTTP 403 from Apple")
            return {"data": [review("review-1")], "links": {"next": f"https://api.appstoreconnect.apple.com/v1/apps/{APP_ID}/customerReviews?cursor=second"}}

        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            run_import(apple_fetch, lambda url: [], github.create, github.update)
        self.assertEqual(github.creates, 0)


class CommandTests(unittest.TestCase):
    def test_wrong_repository_fails_before_network_access(self):
        with self.assertRaisesRegex(ValueError, "GitHub repository"):
            main([], environ={"GITHUB_REPOSITORY": "someone/else"}, request=lambda *args, **kwargs: self.fail("network called"))

    def test_missing_credentials_fail_before_network_access(self):
        with self.assertRaisesRegex(ValueError, "Missing environment values"):
            main(["--apply"], environ={"GITHUB_REPOSITORY": "Zuriel-Labs/Retain-Feedback"}, request=lambda *args, **kwargs: self.fail("network called"))

    def test_dry_run_does_not_write_and_apply_creates_issue(self):
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        env = {
            "GITHUB_REPOSITORY": "Zuriel-Labs/Retain-Feedback",
            "GITHUB_TOKEN": "test-github-token",
            "ASC_KEY_ID": "KEY123",
            "ASC_ISSUER_ID": "issuer-123",
            "ASC_PRIVATE_KEY": pem,
        }
        writes = []

        def fake_request(url, token, method="GET", payload=None):
            if "api.appstoreconnect.apple.com" in url:
                return {"data": [review("review-1")], "links": {}}
            if method == "GET":
                return []
            writes.append((method, url, payload))
            return {"number": 1}

        with patch("builtins.print") as output:
            self.assertEqual(main([], environ=env, request=fake_request), 0)
            self.assertEqual(writes, [])
            output.assert_called_once_with("Would create 1 issues; would update 0 issues")
            output.reset_mock()
            self.assertEqual(main(["--apply"], environ=env, request=fake_request), 0)
            output.assert_not_called()
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0], "POST")
        self.assertIn("App-Store-Review-ID: review-1", writes[0][2]["body"])


if __name__ == "__main__":
    unittest.main()
