"""The tool's local account/licence check, reproduced.

Recovered from `ColokTool.RDA.RegDate.UserReg::Check00(string, string, string)`
and `ColokTool.OfflineData`:

    Check00(_, email, password):
        if not GetserverTime("datetime.php"): return false
        accounts = OfflineData.LoadAccounts()            # data/accounts/accounts.json
        acct = OfflineData.FindAccount(accounts, email)   # UserName or Email, ci
        if acct is null:  Reportlogin = "filed: this email is not registered"; false
        if acct.Password != password:
                          Reportlogin = "filed: wrong password"; false
        if IsNullOrWhiteSpace(acct.Hwid):
            acct.Hwid = Get_HWID().Substring(1, 12)       # bind on first login
            SaveAccounts(accounts)
        ... copy the remaining fields into the Login singleton ...
        Reportlogin = "sucsess"
        return true

`GetserverTime` is a stub in the offline build: it just records the local
clock and returns true, so no network call is made.  That is why this build
authenticates entirely from `data/accounts/accounts.json`.

`LoginPage.Btn_Login_Click` then checks `Status == "Active"` and
`Expired` against the clock before opening the main window, and writes
`config.ini` `[Setting Config] user= / pass=` when "save" is ticked.
"""

import datetime
import json
import os

REPORT_OK = 'sucsess'                      # the tool's own spelling
REPORT_NO_ACCOUNT = 'filed: this email is not registered'
REPORT_BAD_PASSWORD = 'filed: wrong password'

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'          # matches the shipped accounts.json


class LoginState:
    """The mutable singleton the tool fills in during login."""

    __slots__ = ('userid', 'username', 'email', 'password', 'hwid', 'status',
                 'info', 'starttime', 'expired', 'lastlogin', 'reportlogin')

    def __init__(self):
        for name in self.__slots__:
            setattr(self, name, None)
        self.reportlogin = ''

    def as_dict(self):
        return {n: getattr(self, n) for n in self.__slots__}


class AccountStore:
    """`data/accounts/accounts.json`."""

    def __init__(self, path):
        self.path = path

    def load(self):
        if not os.path.isfile(self.path):
            return []
        with open(self.path, encoding='utf-8') as fh:
            return json.load(fh)

    def save(self, accounts):
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        with open(self.path, 'w', encoding='utf-8') as fh:
            json.dump(accounts, fh, indent=2)

    @staticmethod
    def find(accounts, user):
        """OfflineData.FindAccount: match UserName or Email, case-insensitive."""
        needle = (user or '').strip().lower()
        if not needle:
            return None
        for acct in accounts:
            for field in ('UserName', 'Email'):
                if str(acct.get(field, '')).strip().lower() == needle:
                    return acct
        return None


def parse_date(text, now=None):
    """`UserReg.ParseDate`: tolerant, falls back to `now` on failure."""
    if not text:
        return now or datetime.datetime.now()
    for fmt in (DATE_FORMAT, '%Y-%m-%d', '%d/%m/%Y'):
        try:
            return datetime.datetime.strptime(str(text).strip(), fmt)
        except ValueError:
            continue
    return now or datetime.datetime.now()


def check00(store, user, password, hwid=None, now=None):
    """Reproduce `UserReg.Check00`.  Returns (ok, LoginState)."""
    now = now or datetime.datetime.now()
    state = LoginState()

    # GetserverTime is a no-op stub in the offline build and always succeeds.
    accounts = store.load()
    acct = AccountStore.find(accounts, user)
    if acct is None:
        state.reportlogin = REPORT_NO_ACCOUNT
        return False, state
    if str(acct.get('Password', '')) != password:
        state.reportlogin = REPORT_BAD_PASSWORD
        return False, state

    if not str(acct.get('Hwid') or '').strip():
        # Get_HWID().Substring(1, 12): drop the first character, take 12
        if hwid:
            acct['Hwid'] = hwid[1:13]
            store.save(accounts)

    state.userid = acct.get('Userid')
    state.username = acct.get('UserName')
    state.email = acct.get('Email')
    state.password = acct.get('Password')
    state.hwid = acct.get('Hwid')
    state.status = acct.get('Status')
    state.info = acct.get('Info')
    state.starttime = parse_date(acct.get('Starttime'), now)
    state.expired = parse_date(acct.get('Expired'), now + datetime.timedelta(days=3650))
    state.lastlogin = parse_date(acct.get('Lastlogin'), now - datetime.timedelta(days=1))
    state.reportlogin = REPORT_OK
    return True, state


class LoginOutcome:
    OK = 'ok'
    NOT_ACTIVE = 'account is not activated'
    EXPIRED = 'account expired'


def evaluate_licence(state, now=None):
    """The post-login checks in `LoginPage.Btn_Login_Click`."""
    now = now or datetime.datetime.now()
    if str(state.status or '').strip() != 'Active':
        return LoginOutcome.NOT_ACTIVE
    if state.expired is not None and state.expired < now:
        return LoginOutcome.EXPIRED
    return LoginOutcome.OK


def read_config_ini(path):
    """`mIni` writes an INI; read back `[Setting Config] user/pass`."""
    out = {}
    if not os.path.isfile(path):
        return out
    section = None
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1]
                continue
            if '=' in line and section:
                k, v = line.split('=', 1)
                out[(section, k.strip())] = v.strip()
    return out


def write_config_ini(path, user, password):
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('[Setting Config]\nuser=%s\npass=%s\n' % (user, password))
