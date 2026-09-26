import types
import unittest
from unittest.mock import Mock

from lab import Lab, Proc


class RoleCommandTests(unittest.TestCase):
    def lab(self, **overrides):
        instance = Lab.__new__(Lab)
        instance.args = types.SimpleNamespace(client="/default-client", **overrides)
        return instance

    def test_default_go_client_is_used_for_both_roles(self):
        instance = self.lab()
        self.assertEqual("/default-client", instance.client_binary("consumer"))
        self.assertEqual("/default-client", instance.client_binary("egress"))
        self.assertEqual("Go", instance.client_label("egress"))

    def test_override_does_not_change_other_role_or_claim_go(self):
        instance = self.lab(egress_client="/dotnet-client")
        self.assertEqual("/default-client", instance.client_binary("consumer"))
        self.assertEqual("/dotnet-client", instance.client_binary("egress"))
        self.assertEqual("custom", instance.client_label("egress"))

    def test_start_uses_literal_executable_and_role_environment(self):
        instance = self.lab(consumer_client="/path with spaces/java-client", consumer_implementation="Java")
        instance.start = Mock()
        instance.client_env = Mock(return_value=["env", "HOME=/fixture/consumer"])
        instance.start_client("consumer", "/fixture/config.jsonc")
        role, command = instance.start.call_args.args
        self.assertEqual("consumer", role)
        self.assertIn("/path with spaces/java-client", command)
        self.assertNotIn("/default-client", command)
        self.assertEqual("Java", instance.client_label("consumer"))

    def test_policy_evidence_accepts_dotnet_boolean_case(self):
        proc = Proc.__new__(Proc)
        proc.label = "egress"
        proc.log_since = Mock(return_value="[peer-egress] policy applied enabled=True revision=2")
        proc.lab = types.SimpleNamespace(wait_for=lambda _, predicate, timeout: (predicate(), 0))
        self.assertIsNotNone(proc.wait_log(r"policy applied enabled=true", 1))


if __name__ == "__main__":
    unittest.main()
