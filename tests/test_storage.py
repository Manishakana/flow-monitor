import tempfile
import unittest
from pathlib import Path

from flow_monitor.storage import Repository


class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repository = Repository(Path(self.temporary_directory.name) / "telemetry.db")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_connection_lifecycle_is_recorded(self) -> None:
        observation = {
            "connection_key": "10.0.0.2:5000>1.1.1.1:443:42",
            "local_host": "10.0.0.2",
            "local_port": 5000,
            "remote_host": "1.1.1.1",
            "remote_port": 443,
            "process_id": 42,
        }
        self.repository.record_observation(100, [observation])
        active = self.repository.connections("active", 10)
        self.assertEqual(1, len(active))
        self.assertEqual("active", active[0]["state"])

        self.repository.record_observation(110, [])
        closed = self.repository.connections("closed", 10)
        self.assertEqual(1, len(closed))
        self.assertEqual(110, closed[0]["closed_at"])

    def test_neighbor_details_and_insights_are_persisted(self) -> None:
        self.repository.record_neighbors(
            100,
            [{"host": "192.168.1.20", "mac_address": "aa:bb:cc:dd:ee:ff", "hostname": "printer", "discovery_source": "passive-arp-cache"}],
        )
        device = self.repository.device("192.168.1.20")
        self.assertIsNotNone(device)
        self.assertEqual("printer", device["device"]["hostname"])
        self.assertEqual(1, self.repository.insights()["local_devices"])


if __name__ == "__main__":
    unittest.main()
