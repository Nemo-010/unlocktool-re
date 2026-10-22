"""Tests for the local account/licence check."""
import datetime
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import auth  # noqa: E402

NOW = datetime.datetime(2026, 10, 22, 12, 0, 0)

SHIPPED = [{
    'UserName': 'owner',
    'Email': 'owner',
    'Password': 'owner',
    'Userid': 'OFFLINE-0001',
    'Hwid': 'F88600C83906',
    'Status': 'Active',
    'Info': 'Offline build',
    'Starttime': '2026-09-29 11:11:56',
    'Expired': '2036-09-26',
    'Lastlogin': '2026-10-02 14:11:17',
}]


class TestAccountStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'accounts', 'accounts.json')
        self.store = auth.AccountStore(self.path)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_missing_file_is_empty(self):
        self.assertEqual(self.store.load(), [])

    def test_roundtrip(self):
        self.store.save(SHIPPED)
        self.assertEqual(self.store.load(), SHIPPED)

    def test_find_is_case_insensitive_on_username_and_email(self):
        accts = SHIPPED
        self.assertIsNotNone(auth.AccountStore.find(accts, 'OWNER'))
        self.assertIsNotNone(auth.AccountStore.find(accts, ' owner '))
        self.assertIsNone(auth.AccountStore.find(accts, 'nobody'))
        self.assertIsNone(auth.AccountStore.find(accts, ''))
        self.assertIsNone(auth.AccountStore.find(accts, None))

    def test_find_by_email_when_it_differs(self):
        accts = [{'UserName': 'bob', 'Email': 'bob@example.org',
                  'Password': 'x'}]
        self.assertIs(auth.AccountStore.find(accts, 'BOB@EXAMPLE.ORG'),
                      accts[0])


class TestCheck00(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'accounts.json')
        self.store = auth.AccountStore(self.path)
        self.store.save([dict(SHIPPED[0])])

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_success(self):
        ok, state = auth.check00(self.store, 'owner', 'owner', now=NOW)
        self.assertTrue(ok)
        self.assertEqual(state.reportlogin, auth.REPORT_OK)
        self.assertEqual(state.userid, 'OFFLINE-0001')
        self.assertEqual(state.status, 'Active')

    def test_unknown_account(self):
        ok, state = auth.check00(self.store, 'ghost', 'owner', now=NOW)
        self.assertFalse(ok)
        self.assertEqual(state.reportlogin, auth.REPORT_NO_ACCOUNT)

    def test_wrong_password(self):
        ok, state = auth.check00(self.store, 'owner', 'nope', now=NOW)
        self.assertFalse(ok)
        self.assertEqual(state.reportlogin, auth.REPORT_BAD_PASSWORD)

    def test_password_is_case_sensitive(self):
        ok, _ = auth.check00(self.store, 'owner', 'OWNER', now=NOW)
        self.assertFalse(ok)

    def test_hwid_is_bound_on_first_login(self):
        accts = self.store.load()
        accts[0]['Hwid'] = ''
        self.store.save(accts)
        ok, state = auth.check00(self.store, 'owner', 'owner',
                                 hwid='XF88600C83906AA', now=NOW)
        self.assertTrue(ok)
        self.assertEqual(state.hwid, 'F88600C83906')
        self.assertEqual(self.store.load()[0]['Hwid'], 'F88600C83906')

    def test_hwid_not_overwritten_when_present(self):
        ok, state = auth.check00(self.store, 'owner', 'owner',
                                 hwid='XZZZZZZZZZZZZZ', now=NOW)
        self.assertTrue(ok)
        self.assertEqual(state.hwid, 'F88600C83906')

    def test_expired_field_parsed(self):
        _, state = auth.check00(self.store, 'owner', 'owner', now=NOW)
        self.assertEqual(state.expired, datetime.datetime(2036, 9, 26))

    def test_unparseable_dates_fall_back_to_now(self):
        accts = self.store.load()
        accts[0]['Expired'] = 'not a date'
        self.store.save(accts)
        _, state = auth.check00(self.store, 'owner', 'owner', now=NOW)
        self.assertEqual(state.expired,
                         NOW + datetime.timedelta(days=3650))


class TestLicenceEvaluation(unittest.TestCase):
    def _state(self, **kw):
        s = auth.LoginState()
        s.status = kw.get('status', 'Active')
        s.expired = kw.get('expired', datetime.datetime(2036, 9, 26))
        return s

    def test_active_and_in_date(self):
        self.assertEqual(auth.evaluate_licence(self._state(), now=NOW),
                         auth.LoginOutcome.OK)

    def test_not_active(self):
        self.assertEqual(
            auth.evaluate_licence(self._state(status='Suspended'), now=NOW),
            auth.LoginOutcome.NOT_ACTIVE)

    def test_expired(self):
        self.assertEqual(
            auth.evaluate_licence(
                self._state(expired=datetime.datetime(2020, 1, 1)), now=NOW),
            auth.LoginOutcome.EXPIRED)

    def test_boundary_is_expired_on_the_day(self):
        st = self._state(expired=NOW - datetime.timedelta(seconds=1))
        self.assertEqual(auth.evaluate_licence(st, now=NOW),
                         auth.LoginOutcome.EXPIRED)


class TestConfigIni(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'config.ini')

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_write_read(self):
        auth.write_config_ini(self.path, 'owner', 'owner')
        cfg = auth.read_config_ini(self.path)
        self.assertEqual(cfg[('Setting Config', 'user')], 'owner')
        self.assertEqual(cfg[('Setting Config', 'pass')], 'owner')

    def test_shipped_layout_parses(self):
        with open(self.path, 'w') as fh:
            fh.write('[Setting Config]\nuser=owner\npass=owner\n')
        cfg = auth.read_config_ini(self.path)
        self.assertEqual(len(cfg), 2)

    def test_missing_file(self):
        self.assertEqual(auth.read_config_ini(self.path + '.nope'), {})


if __name__ == '__main__':
    unittest.main()
