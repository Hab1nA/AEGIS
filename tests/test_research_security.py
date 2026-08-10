from __future__ import annotations

import hashlib
import io
import unittest
import zipfile

from aegis.research import (
    ArchiveLimits,
    FetchResponse,
    ResearchBroker,
    SearchHit,
    StaticResolver,
    UrlPolicy,
    validate_archive,
    validate_url,
)

PUBLIC = "93.184.216.34"


class FakeSearch:
    def __init__(self, hits: list[SearchHit]) -> None:
        self.hits = hits

    def search(self, query: str, *, limit: int) -> list[SearchHit]:
        return self.hits[:limit]


class FakeFetcher:
    def __init__(self, responses: dict[str, FetchResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def fetch(self, url: str, *, allowed_addresses: tuple[str, ...], max_bytes: int) -> FetchResponse:
        self.calls.append((url, allowed_addresses))
        return self.responses[url]


class UrlSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = StaticResolver(
            {
                "example.com": (PUBLIC,),
                "cdn.example.com": ("1.1.1.1",),
                "private.example": ("10.0.0.1",),
                "mixed.example": (PUBLIC, "127.0.0.1"),
            }
        )

    def test_accepts_public_https_and_normalizes_host(self) -> None:
        self.assertEqual(
            validate_url("https://EXAMPLE.com/docs?q=1", self.resolver),
            "https://example.com/docs?q=1",
        )

    def test_rejects_private_literal_dns_and_mixed_dns(self) -> None:
        for url in (
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://private.example/",
            "https://mixed.example/",
            "https://169.254.169.254/latest/meta-data/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url, self.resolver)

    def test_rejects_credentials_bad_port_fragment_and_http(self) -> None:
        for url in (
            "https://user@example.com/",
            "https://example.com:8443/",
            "https://example.com/#fragment",
            "http://example.com/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url, self.resolver)

    def test_custom_http_policy(self) -> None:
        policy = UrlPolicy(frozenset({"http"}), frozenset({80}))
        self.assertEqual(validate_url("http://example.com", self.resolver, policy), "http://example.com/")


class BrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = StaticResolver({"example.com": (PUBLIC,), "cdn.example.com": ("1.1.1.1",)})

    def test_redirect_is_validated_and_provenance_hashed(self) -> None:
        start = "https://example.com/start"
        final = "https://cdn.example.com/file.txt"
        fetcher = FakeFetcher(
            {
                start: FetchResponse(start, 302, {}, b"", "https://cdn.example.com/file.txt"),
                final: FetchResponse(final, 200, {"Content-Type": "text/plain; charset=utf-8"}, b"hello"),
            }
        )
        artifact = ResearchBroker(fetcher=fetcher, resolver=self.resolver).fetch(start)
        self.assertEqual(fetcher.calls, [(start, (PUBLIC,)), (final, ("1.1.1.1",))])
        self.assertEqual(artifact.provenance.final_url, final)
        self.assertEqual(artifact.provenance.redirect_chain, (final,))
        self.assertEqual(artifact.provenance.sha256, hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(artifact.provenance.media_type, "text/plain")

    def test_redirect_to_private_address_is_rejected_before_fetch(self) -> None:
        start = "https://example.com/start"
        fetcher = FakeFetcher({start: FetchResponse(start, 302, {}, b"", "https://127.0.0.1/secret")})
        with self.assertRaises(ValueError):
            ResearchBroker(fetcher=fetcher, resolver=self.resolver).fetch(start)
        self.assertEqual(fetcher.calls, [(start, (PUBLIC,))])

    def test_default_implementations_do_not_access_network(self) -> None:
        broker = ResearchBroker(resolver=self.resolver)
        with self.assertRaisesRegex(RuntimeError, "no search"):
            broker.search("python testing")
        with self.assertRaisesRegex(RuntimeError, "no fetcher"):
            broker.fetch("https://example.com/")

    def test_search_results_are_validated(self) -> None:
        broker = ResearchBroker(
            search_provider=FakeSearch([SearchHit("https://127.0.0.1/x", "unsafe")]),
            resolver=self.resolver,
        )
        with self.assertRaises(ValueError):
            broker.search("query")


class ArchiveTests(unittest.TestCase):
    @staticmethod
    def make_zip(name: str, content: bytes, compression: int = zipfile.ZIP_STORED) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            archive.writestr(name, content)
        return output.getvalue()

    def test_accepts_safe_archive_without_extracting(self) -> None:
        self.assertEqual(validate_archive(self.make_zip("src/main.py", b"print(1)")), ("src/main.py",))

    def test_rejects_traversal_and_windows_absolute_path(self) -> None:
        for name in ("../escape", "safe/../../escape", "C:\\escape.txt", "/root/escape"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_archive(self.make_zip(name, b"x"))

    def test_rejects_zip_bomb_ratio_and_expanded_size(self) -> None:
        compressed = self.make_zip("huge.txt", b"0" * 100_000, zipfile.ZIP_DEFLATED)
        with self.assertRaisesRegex(ValueError, "compression ratio"):
            validate_archive(compressed, ArchiveLimits(max_compression_ratio=5))
        stored = self.make_zip("large.bin", b"x" * 20)
        with self.assertRaisesRegex(ValueError, "size limit"):
            validate_archive(stored, ArchiveLimits(max_single_file_bytes=10))


if __name__ == "__main__":
    unittest.main()
