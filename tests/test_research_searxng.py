from __future__ import annotations

import json
import unittest

from aegis.research import (
    FetchResponse,
    ResearchBroker,
    SearxNGSearchProvider,
    StaticResolver,
)

PUBLIC = "93.184.216.34"


class FakeFetcher:
    def __init__(self, response_body: object, *, headers: dict[str, str] | None = None) -> None:
        self.response_body = response_body
        self.headers = headers or {"Content-Type": "application/json; charset=utf-8"}
        self.calls: list[tuple[str, tuple[str, ...], int]] = []

    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        self.calls.append((url, allowed_addresses, max_bytes))
        body = self.response_body
        encoded = body if isinstance(body, bytes) else json.dumps(body).encode()
        return FetchResponse(url, 200, self.headers, encoded)


class SequenceFetcher(FakeFetcher):
    def __init__(self, response_bodies: list[object]) -> None:
        super().__init__(response_bodies[-1])
        self.response_bodies = list(response_bodies)

    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        self.response_body = self.response_bodies.pop(0)
        return super().fetch(url, allowed_addresses=allowed_addresses, max_bytes=max_bytes)


class SearxNGSearchProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = StaticResolver({"search.example": (PUBLIC,), "safe.example": ("1.1.1.1",)})

    def test_reads_only_explicit_setting_and_encodes_query(self) -> None:
        fetcher = FakeFetcher(
            {"results": [{"url": "https://safe.example/x", "title": " A result ", "content": " text "}]}
        )
        provider = SearxNGSearchProvider.from_environment(
            fetcher=fetcher,
            resolver=self.resolver,
            environ={
                "AEGIS_SEARCH_BASE_URL": "https://search.example/private-instance/",
                "HTTPS_PROXY": "http://user:secret@127.0.0.1:8080",
                "OPENAI_API_KEY": "secret",
            },
        )
        hits = provider.search("python safety & testing", limit=1)
        self.assertEqual(hits[0].title, "A result")
        url, addresses, _ = fetcher.calls[0]
        self.assertEqual(
            url,
            "https://search.example/private-instance/search?q=python+safety+%26+testing&format=json",
        )
        self.assertEqual(addresses, (PUBLIC,))
        self.assertNotIn("secret", url)

    def test_missing_configuration_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no search provider configured"):
            SearxNGSearchProvider.from_environment(
                fetcher=FakeFetcher({"results": []}), resolver=self.resolver, environ={}
            )

    def test_explicit_loopback_search_is_narrow_and_pinned(self) -> None:
        fetcher = FakeFetcher({"results": []})
        provider = SearxNGSearchProvider.from_environment(
            fetcher=fetcher,
            environ={
                "AEGIS_SEARCH_BASE_URL": "http://127.0.0.1:8888",
                "AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK": "true",
            },
        )
        provider.search("local", limit=1)
        self.assertEqual(fetcher.calls[0][1], ("127.0.0.1",))
        self.assertEqual(fetcher.calls[0][0], "http://127.0.0.1:8888/search?q=local&format=json")

    def test_loopback_search_retries_bounded_empty_results(self) -> None:
        fetcher = SequenceFetcher(
            [
                {"results": []},
                {"results": [{"url": "https://safe.example/x", "title": "result"}]},
            ]
        )
        delays: list[float] = []
        provider = SearxNGSearchProvider(
            "http://127.0.0.1:8888",
            fetcher=fetcher,
            allow_insecure_loopback=True,
            empty_result_attempts=3,
            empty_result_delay_seconds=2.0,
            sleeper=delays.append,
        )
        hits = provider.search("local", limit=1)
        self.assertEqual([hit.title for hit in hits], ["result"])
        self.assertEqual(len(fetcher.calls), 2)
        self.assertEqual(delays, [2.0])

    def test_loopback_search_empty_retry_is_bounded(self) -> None:
        fetcher = SequenceFetcher([{"results": []}, {"results": []}])
        delays: list[float] = []
        provider = SearxNGSearchProvider(
            "http://127.0.0.1:8888",
            fetcher=fetcher,
            allow_insecure_loopback=True,
            empty_result_attempts=2,
            empty_result_delay_seconds=1.0,
            sleeper=delays.append,
        )
        self.assertEqual(provider.search("local", limit=1), [])
        self.assertEqual(len(fetcher.calls), 2)
        self.assertEqual(delays, [1.0])

    def test_loopback_search_requires_exact_opt_in_address_and_port(self) -> None:
        fetcher = FakeFetcher({"results": []})
        with self.assertRaisesRegex(ValueError, "scheme"):
            SearxNGSearchProvider.from_environment(
                fetcher=fetcher,
                environ={"AEGIS_SEARCH_BASE_URL": "http://127.0.0.1:8888"},
            )
        for base in (
            "http://localhost:8888",
            "http://127.0.0.2:8888",
            "http://192.168.1.2:8888",
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8888",
        ):
            with self.subTest(base=base), self.assertRaises(ValueError):
                SearxNGSearchProvider.from_environment(
                    fetcher=fetcher,
                    environ={
                        "AEGIS_SEARCH_BASE_URL": base,
                        "AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK": "true",
                    },
                )
        with self.assertRaisesRegex(ValueError, "must be true or false"):
            SearxNGSearchProvider.from_environment(
                fetcher=fetcher,
                environ={
                    "AEGIS_SEARCH_BASE_URL": "https://search.example",
                    "AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK": "yes",
                },
                resolver=self.resolver,
            )

    def test_rejects_private_search_endpoint(self) -> None:
        resolver = StaticResolver({"search.internal": ("127.0.0.1",)})
        with self.assertRaisesRegex(ValueError, "non-public"):
            SearxNGSearchProvider(
                "https://search.internal", fetcher=FakeFetcher({"results": []}), resolver=resolver
            )

    def test_broker_still_validates_every_result_url(self) -> None:
        provider = SearxNGSearchProvider(
            "https://search.example",
            fetcher=FakeFetcher(
                {"results": [{"url": "https://127.0.0.1/secret", "title": "unsafe", "content": ""}]}
            ),
            resolver=self.resolver,
        )
        with self.assertRaisesRegex(ValueError, "non-public"):
            ResearchBroker(search_provider=provider, resolver=self.resolver).search("query")

    def test_skips_malformed_results_and_keeps_later_valid_result(self) -> None:
        provider = SearxNGSearchProvider(
            "https://search.example",
            fetcher=FakeFetcher(
                {
                    "results": [
                        {"url": 1, "title": "invalid"},
                        {"url": "https://safe.example/x", "title": "valid", "content": ""},
                    ]
                }
            ),
            resolver=self.resolver,
        )
        self.assertEqual([item.title for item in provider.search("q", limit=1)], ["valid"])

    def test_strict_schema_content_type_and_result_count(self) -> None:
        invalid_payloads: list[object] = [
            [],
            {},
            {"results": "not-list"},
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, "schema"):
                SearxNGSearchProvider(
                    "https://search.example",
                    fetcher=FakeFetcher(payload),
                    resolver=self.resolver,
                ).search("q", limit=1)

        with self.assertRaisesRegex(ValueError, "application/json"):
            SearxNGSearchProvider(
                "https://search.example",
                fetcher=FakeFetcher({"results": []}, headers={"Content-Type": "text/html"}),
                resolver=self.resolver,
            ).search("q", limit=1)

        too_many = {"results": [{"url": "https://safe.example", "title": "x"}] * 3}
        with self.assertRaisesRegex(ValueError, "too many"):
            SearxNGSearchProvider(
                "https://search.example",
                fetcher=FakeFetcher(too_many),
                resolver=self.resolver,
                max_results=2,
            ).search("q", limit=1)


if __name__ == "__main__":
    unittest.main()
