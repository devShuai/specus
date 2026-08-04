from __future__ import annotations

import unittest

from migrate_s3_prefix import migrate_prefix, normalize_prefix


class FakeS3Client:
    def __init__(self, objects: dict[str, int]) -> None:
        self.objects = dict(objects)
        self.copies: list[tuple[str, str]] = []

    def list_objects_v2(self, *, Bucket: str, Prefix: str, **_: object) -> dict:
        contents = [
            {"Key": key, "Size": size}
            for key, size in sorted(self.objects.items())
            if key.startswith(Prefix)
        ]
        return {"Contents": contents, "IsTruncated": False}

    def copy_object(
        self,
        *,
        Bucket: str,
        CopySource: dict[str, str],
        Key: str,
        MetadataDirective: str,
    ) -> None:
        source = CopySource["Key"]
        self.copies.append((source, Key))
        self.objects[Key] = self.objects[source]


class S3PrefixMigrationTests(unittest.TestCase):
    def test_plan_is_read_only(self) -> None:
        client = FakeS3Client({"shuai-tunnel/http-media/a": 12})
        messages: list[str] = []
        migrate_prefix(
            client,
            bucket="media",
            source_prefix="shuai-tunnel/http-media",
            destination_prefix="specus/http-media",
            apply=False,
            emit=messages.append,
        )
        self.assertEqual([], client.copies)
        self.assertTrue(messages[0].startswith("plan "))

    def test_apply_copies_and_verifies_objects(self) -> None:
        client = FakeS3Client(
            {
                "shuai-tunnel/http-media/a": 12,
                "shuai-tunnel/http-media/nested/b": 34,
            }
        )
        migrate_prefix(
            client,
            bucket="media",
            source_prefix="shuai-tunnel/http-media",
            destination_prefix="specus/http-media",
            apply=True,
            emit=lambda _: None,
        )
        self.assertEqual(
            12, client.objects["specus/http-media/a"]
        )
        self.assertEqual(
            34, client.objects["specus/http-media/nested/b"]
        )

    def test_non_empty_destination_requires_resume(self) -> None:
        client = FakeS3Client(
            {
                "shuai-tunnel/http-media/a": 12,
                "specus/http-media/a": 12,
            }
        )
        with self.assertRaisesRegex(RuntimeError, "not empty"):
            migrate_prefix(
                client,
                bucket="media",
                source_prefix="shuai-tunnel/http-media",
                destination_prefix="specus/http-media",
                apply=True,
                emit=lambda _: None,
            )

    def test_resume_skips_matching_objects(self) -> None:
        client = FakeS3Client(
            {
                "shuai-tunnel/http-media/a": 12,
                "specus/http-media/a": 12,
            }
        )
        migrate_prefix(
            client,
            bucket="media",
            source_prefix="shuai-tunnel/http-media",
            destination_prefix="specus/http-media",
            apply=True,
            resume=True,
            emit=lambda _: None,
        )
        self.assertEqual([], client.copies)

    def test_rejects_unsafe_prefixes(self) -> None:
        for value in ("", "../media", "media/./part", r"media\part"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_prefix(value)


if __name__ == "__main__":
    unittest.main()
