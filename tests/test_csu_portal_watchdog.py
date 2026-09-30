"""Safety and recovery tests. Never send real authentication requests."""
import importlib.util
import io
import logging
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).resolve().parents[1] / "csu_portal_watchdog.py"
spec = importlib.util.spec_from_file_location("watchdog", SCRIPT)
w = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = w
spec.loader.exec_module(w)
OFFLINE = w.Context(False, "192.0.2.10")


class Probe:
    def __init__(self, values):
        self.values = list(values)

    def healthy(self):
        if not self.values:
            raise AssertionError("unexpected additional probe")
        return self.values.pop(0)


class Portal:
    def __init__(self, contexts, reply=None):
        self.contexts = list(contexts)
        self.reply = reply or {"result": 1}
        self.auth_calls = 0
        self.parameter_calls = 0

    def context(self):
        return self.contexts.pop(0)

    def login_parameters(self, credentials, context):
        self.parameter_calls += 1
        return {"user_account": credentials.username, "user_password": credentials.password}

    def authenticate(self, parameters):
        self.auth_calls += 1
        return self.reply


class CycleTests(unittest.TestCase):
    def setUp(self):
        self.buffer = io.StringIO()
        self.log = logging.Logger("test")
        self.log.addHandler(logging.StreamHandler(self.buffer))
        self.loads = 0

    def credentials(self):
        self.loads += 1
        return w.Credentials("test-account", "sample-secret-only")

    def run_cycle(self, portal, probes, **kwargs):
        return w.cycle(portal, Probe(probes), self.credentials, self.log,
                       pause=lambda _: None, **kwargs)

    def test_online_internet_never_reads_credentials_or_portal(self):
        portal = Portal([])
        self.assertEqual(self.run_cycle(portal, [True]), "healthy")
        self.assertEqual((self.loads, portal.auth_calls, portal.parameter_calls), (0, 0, 0))

    def test_transient_probe_failure_recovers_without_authentication(self):
        portal = Portal([])
        self.assertEqual(self.run_cycle(portal, [False, True]), "healthy")
        self.assertEqual((self.loads, portal.auth_calls), (0, 0))

    def test_internet_outage_while_portal_online_preserves_login(self):
        portal = Portal([w.Context(True, OFFLINE.ip)])
        self.assertEqual(self.run_cycle(portal, [False, False]), "still_online")
        self.assertEqual((self.loads, portal.auth_calls), (0, 0))

    def test_unknown_status_cannot_authenticate(self):
        portal = Portal([w.Context(None)])
        self.assertEqual(self.run_cycle(portal, [False, False]), "unknown")
        self.assertEqual((self.loads, portal.auth_calls), (0, 0))

    def test_dry_run_offline_never_loads_password(self):
        portal = Portal([OFFLINE])
        self.assertEqual(self.run_cycle(portal, [False, False], read_only=True), "dry_run")
        self.assertEqual((self.loads, portal.auth_calls, portal.parameter_calls), (0, 0, 0))

    def test_user_logs_in_during_preparation(self):
        portal = Portal([OFFLINE, w.Context(True, OFFLINE.ip)])
        self.assertEqual(self.run_cycle(portal, [False, False]), "state_changed")
        self.assertEqual(portal.auth_calls, 0)

    def test_address_changes_during_preparation(self):
        portal = Portal([OFFLINE, w.Context(False, "192.0.2.11")])
        self.assertEqual(self.run_cycle(portal, [False, False]), "state_changed")
        self.assertEqual(portal.auth_calls, 0)

    def test_network_recovers_just_before_authentication(self):
        portal = Portal([OFFLINE, OFFLINE])
        self.assertEqual(self.run_cycle(portal, [False, False, True]), "healthy")
        self.assertEqual(portal.auth_calls, 0)

    def test_real_outage_permits_exactly_one_login_then_checks_internet(self):
        portal = Portal([OFFLINE, OFFLINE])
        self.assertEqual(self.run_cycle(portal, [False, False, False, True]), "recovered")
        self.assertEqual(portal.auth_calls, 1)
        self.assertNotIn("sample-secret-only", self.buffer.getvalue())
        self.assertNotIn("test-account", self.buffer.getvalue())

    def test_successful_api_response_is_not_network_recovery(self):
        portal = Portal([OFFLINE, OFFLINE])
        self.assertEqual(self.run_cycle(portal, [False, False, False, False]), "not_recovered")
        self.assertEqual(portal.auth_calls, 1)
        self.assertNotIn("网络已恢复", self.buffer.getvalue())


class InterfaceTests(unittest.TestCase):
    def test_jsonp_is_parsed_without_execution(self):
        self.assertEqual(w.parse_jsonp('dr1003({"result":1});'), {"result": 1})
        with self.assertRaises(w.RequestError):
            w.parse_jsonp('alert("unsafe"); dr1003({"result":1});')

    def test_only_two_negative_observations_mean_offline(self):
        class Client:
            def __init__(self, page, status):
                self.page, self.status = page, status
            def portal_text(self, url):
                return '<!--Dr.COMWebLoginID_%s.htm--> v4ip="192.0.2.10";' % self.page
            def portal_json(self, *args):
                return {"result": self.status}
        self.assertFalse(w.Portal(Client(0, 0)).context().online)
        self.assertTrue(w.Portal(Client(1, 0)).context().online)
        self.assertTrue(w.Portal(Client(0, 1)).context().online)
        self.assertIsNone(w.Portal(Client(0, 7)).context().online)

    def test_payload_matches_current_source_and_uses_current_address(self):
        class Client:
            def portal_json(self, url, params):
                self.query = params
                return {"data": {"login_method": "1", "account_prefix": "1",
                                 "account_suffix": "", "en_md5": "0", "password_cut": "0"}}
            def portal_text(self, url):
                return "var jsVersion='4.1.3';"
        client = Client()
        payload = w.Portal(client).login_parameters(w.Credentials("user", "p&+?#中文"), OFFLINE)
        self.assertEqual(payload["user_account"], ",0,user")
        self.assertEqual(payload["user_password"], "p&+?#中文")
        self.assertEqual(payload["wlan_user_ip"], OFFLINE.ip)
        self.assertEqual(payload["wlan_ac_ip"], "")
        self.assertEqual(payload["terminal_type"], "1")
        self.assertEqual(payload["jsVersion"], "4.1.3")
        self.assertNotIn("DDDDD", payload)
        self.assertEqual(w.base64.b64decode(client.query["wlan_user_ip"]).decode(), OFFLINE.ip)

    def test_changed_protocol_is_rejected_before_login(self):
        class Client:
            def portal_json(self, *args):
                return {"data": {"login_method": "14"}}
        with self.assertRaises(w.RequestError):
            w.Portal(Client()).login_parameters(w.Credentials("user", "secret"), OFFLINE)

    def test_arbitrary_portal_endpoint_is_blocked_before_transport(self):
        client = w.HttpClient()
        client.fetch = lambda _: self.fail("transport must not be called")
        with self.assertRaises(w.RequestError):
            client.portal_text(w.PORTAL + "/not-an-allowed-endpoint")

    def test_redirect_is_never_followed(self):
        visited = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                visited.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/must-not-be-visited")
                self.end_headers()
            def log_message(self, *args):
                pass
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(w.RequestError):
                w.HttpClient().fetch("http://127.0.0.1:%s/start" % server.server_port)
            self.assertEqual(visited, ["/start"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI required")
    def test_windows_dpapi_roundtrip(self):
        sample = "local-test-only-中文".encode("utf-8")
        protected = w.dpapi(sample)
        self.assertNotEqual(protected, sample)
        self.assertEqual(w.dpapi(protected, decrypt=True), sample)

    def test_task_runs_every_five_minutes_as_interactive_user(self):
        tree = ET.fromstring(w.scheduled_task_xml("S-1-5-21-123-1001", Path("C:/Python/pythonw.exe")))
        ns = {"t": w.TASK_NS}
        self.assertEqual(tree.findtext("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval", namespaces=ns), "PT5M")
        self.assertEqual(tree.findtext("t:Settings/t:MultipleInstancesPolicy", namespaces=ns), "IgnoreNew")
        self.assertEqual(tree.findtext("t:Principals/t:Principal/t:LogonType", namespaces=ns), "InteractiveToken")
        args = tree.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns)
        self.assertIn(str(w.SCRIPT), args)
        self.assertTrue(args.endswith(" once"))

    def test_task_query_accepts_utf8_output_with_utf16_declaration(self):
        xml = w.scheduled_task_xml("S-1-5-21-123-1001", Path("C:/Python/pythonw.exe"))
        stdout = xml.decode("utf-16").encode("utf-8")
        tree = w.parse_task_xml(stdout)
        ns = {"t": w.TASK_NS}
        self.assertEqual(tree.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns),
                         w.subprocess.list2cmdline([str(w.SCRIPT), "once"]))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI required")
    def test_reconfiguration_does_not_need_to_decrypt_the_old_password(self):
        portal = Portal([w.Context(None)])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "credentials.json"
            config.write_text('{"username":"old-user","password_dpapi":"unreadable-old-value"}', encoding="utf-8")
            with patch.object(w, "STATE", Path(directory)), patch.object(w, "CONFIG", config), \
                 patch.object(w, "load_credentials", side_effect=AssertionError("must not decrypt old password")), \
                 patch("builtins.input", return_value="new-user"), \
                 patch.object(w.getpass, "getpass", side_effect=["test-only-password", "test-only-password"]), \
                 patch("sys.stdout", io.StringIO()):
                w.configure(portal)
                saved = w.json.loads(config.read_text(encoding="utf-8"))
                self.assertEqual(saved["username"], "new-user")
                self.assertNotIn("test-only-password", config.read_text(encoding="utf-8"))
                decrypted = w.dpapi(w.base64.b64decode(saved["password_dpapi"]), decrypt=True)
                self.assertEqual(decrypted.decode("utf-8"), "test-only-password")


if __name__ == "__main__":
    unittest.main(verbosity=2)
