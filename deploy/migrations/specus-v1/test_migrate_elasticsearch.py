from __future__ import annotations

import unittest

from migrate_elasticsearch import INDEX_RENAMES, migrate_indices


class FakeElasticsearchClient:
    def __init__(self, counts: dict[str, int], blocked: bool = False) -> None:
        self.counts = dict(counts)
        self.blocked = blocked
        self.operations: list[tuple[str, ...]] = []

    def exists(self, index: str) -> bool:
        return index in self.counts

    def count(self, index: str) -> int:
        return self.counts[index]

    def write_blocked(self, index: str) -> bool:
        self.operations.append(("write_blocked", index))
        return self.blocked

    def add_write_block(self, index: str) -> None:
        self.operations.append(("add_write_block", index))

    def remove_write_block(self, index: str) -> None:
        self.operations.append(("remove_write_block", index))

    def clone(self, source: str, destination: str) -> None:
        self.operations.append(("clone", source, destination))
        self.counts[destination] = self.counts[source]

    def wait_until_available(self, index: str) -> None:
        self.operations.append(("wait_until_available", index))

    def refresh(self, index: str) -> None:
        self.operations.append(("refresh", index))


class ElasticsearchMigrationTests(unittest.TestCase):
    def test_plan_is_read_only(self) -> None:
        source, _ = INDEX_RENAMES[0]
        client = FakeElasticsearchClient({source: 12})
        messages: list[str] = []
        migrate_indices(client, apply=False, emit=messages.append)
        self.assertEqual([], client.operations)
        self.assertTrue(any(message.startswith("plan ") for message in messages))

    def test_apply_clones_verifies_and_restores_write_state(self) -> None:
        source, destination = INDEX_RENAMES[0]
        client = FakeElasticsearchClient({source: 12})
        migrate_indices(client, apply=True, emit=lambda _: None)
        self.assertEqual(12, client.counts[destination])
        self.assertIn(("add_write_block", source), client.operations)
        self.assertIn(("clone", source, destination), client.operations)
        self.assertIn(("remove_write_block", source), client.operations)

    def test_apply_preserves_an_existing_write_block(self) -> None:
        source, _ = INDEX_RENAMES[0]
        client = FakeElasticsearchClient({source: 2}, blocked=True)
        migrate_indices(client, apply=True, emit=lambda _: None)
        self.assertFalse(
            any(operation[0] == "add_write_block" for operation in client.operations)
        )
        self.assertFalse(
            any(
                operation[0] == "remove_write_block"
                for operation in client.operations
            )
        )

    def test_existing_destination_must_have_same_count(self) -> None:
        source, destination = INDEX_RENAMES[0]
        client = FakeElasticsearchClient({source: 3, destination: 2})
        with self.assertRaisesRegex(RuntimeError, "destination"):
            migrate_indices(client, apply=True, emit=lambda _: None)


if __name__ == "__main__":
    unittest.main()
