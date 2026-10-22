"""Operation dispatch: from an operation name to a workflow family.

The tool decides which protocol family to drive from the operation *name* and
from the brand index's `EDL`/`Broom` attributes.  Measured over the shipped
tree there are exactly 55 distinct operation names, and 2 034 of the 2 228
`method` slots use an `[EDL]` prefix.

The classification below is the one the IL implies:

    Loader_Thread.OperationSupported(folder)   ->  reads operations.xml
    Qctool.operation                            ->  the button caption
    caption prefix                              ->  family
    "misc" / "misc_emmc" / "misc_ufs" / "kernel"
    / "config" / "1" / "2" / "3" / "4" / "90" / "91"
                                                ->  payload filenames that were
                                                    mistakenly indexed as
                                                    operations (see KNOWN_BAD)
"""

import re

FAMILY_EDL = 'qualcomm-edl'
FAMILY_BROM = 'mediatek-brom'
FAMILY_META = 'mediatek-meta'
FAMILY_SIDELOAD = 'adb-sideload'
FAMILY_OFP = 'oppo-ofp'
FAMILY_FASTBOOT = 'fastboot'
FAMILY_ADB = 'adb'
FAMILY_UNKNOWN = 'unknown'

PREFIX_MAP = [
    ('[EDL]', FAMILY_EDL),
    ('[BROM]', FAMILY_BROM),
    ('[META]', FAMILY_META),
    ('[SIDELOAD]', FAMILY_SIDELOAD),
    ('[OFP]', FAMILY_OFP),
    ('[FASTBOOT]', FAMILY_FASTBOOT),
    ('[ADB]', FAMILY_ADB),
]

# Operation names in the shipped tree that are payload filenames, not
# operations.  They are indexed as if they were workflows, so clicking one
# asks the tool for a script called `misc`, which is the payload for a
# `filename="misc"` program row elsewhere.
KNOWN_BAD = {'misc', 'misc_emmc', 'misc_ufs', 'kernel', 'config',
             'persist_0', '1', '2', '3', '4', '90', '91'}

# Unprefixed legacy captions that are real operations: the older brand indexes
# predate the `[EDL]`/`[BROM]` convention.  The IL routes these through the
# same EDL worker, so they are classified `qualcomm-edl`.
LEGACY_CAPTIONS = {'RESET FRP', 'FORMAT DATA', 'FACTORY RESET - FRP',
                   'IMEI 0', 'IMEI TO 0', 'PATCHING_UBL'}

# Families whose device side we could not reconstruct from artefacts.
SIMULATED_ONLY = {FAMILY_BROM, FAMILY_META, FAMILY_SIDELOAD, FAMILY_OFP,
                  FAMILY_FASTBOOT, FAMILY_ADB}

_EDL_TAG = re.compile(r'^\[EDL\]\s*(.*)$', re.I)


def family_of(operation):
    """Map an operation caption to a workflow family."""
    if not operation:
        return FAMILY_UNKNOWN
    if operation.strip() in KNOWN_BAD:
        return FAMILY_UNKNOWN
    upper = operation.strip().upper()
    for prefix, family in PREFIX_MAP:
        if upper.startswith(prefix):
            return family
    # Unprefixed legacy captions predate the prefix convention; the IL sends
    # them through the same EDL worker.
    for legacy in LEGACY_CAPTIONS:
        if legacy.upper() in upper:
            return FAMILY_EDL
    return FAMILY_UNKNOWN


def normalise(operation):
    """Strip the family prefix and collapse whitespace."""
    m = _EDL_TAG.match(operation.strip())
    name = m.group(1) if m else operation.strip()
    return re.sub(r'\s+', ' ', name).strip()


def action_of(operation):
    """The lock/restriction the operation addresses, as a stable token."""
    name = normalise(operation).upper()
    table = [
        ('RESET FRP', 'frp-erase'),
        ('FACTORY RESET + FRP', 'factory-reset+frp'),
        ('FACTORY RESET', 'factory-reset'),
        ('FORMAT DATA', 'format-data'),
        ('SAFE FORMAT', 'safe-format'),
        ('RESET EFS', 'efs-reset'),
        ('UNLOCK BOOTLOADER', 'bootloader-unlock'),
        ('UNLOCK BOOTOADER', 'bootloader-unlock'),   # vendor typo, shipped
        ('RELOCK BOOTLOADER', 'bootloader-relock'),
        ('UNLOCK MI CLOUD', 'cloud-lock-remove'),
        ('DISABLE MI CLOUD', 'cloud-lock-disable'),
        ('DISABLE MICLOUD', 'cloud-lock-disable'),
        ('UNLOCK DEMO', 'demo-mode-remove'),
        ('FIX SENSOR', 'sensor-fix'),
        ('DECRYPT TOKEN', 'token-decrypt'),
        ('IMEI', 'imei-write'),
    ]
    for needle, token in table:
        if needle in name:
            return token
    return 'other'


class Dispatch:
    """Result of resolving a (brand, model, operation) triple."""

    __slots__ = ('brand', 'model', 'operation', 'family', 'action',
                 'simulated', 'reason')

    def __init__(self, brand, model, operation, family, action, simulated,
                 reason=''):
        self.brand = brand
        self.model = model
        self.operation = operation
        self.family = family
        self.action = action
        self.simulated = simulated
        self.reason = reason

    def as_dict(self):
        return {n: getattr(self, n) for n in self.__slots__}

    def __repr__(self):
        return 'Dispatch(%s/%s %r -> %s/%s%s)' % (
            self.brand, self.model, self.operation, self.family, self.action,
            ' [simulated]' if self.simulated else '')


def resolve(tree, brand, model_key, operation):
    """Resolve one operation, reporting why it would or would not run."""
    family = family_of(operation)
    action = action_of(operation)
    reasons = []

    idx = tree.brand(brand)
    entry = idx.model(*_split_key(model_key))
    if entry is None:
        reasons.append('model not in brand index')
    if not idx.has_payload(model_key):
        reasons.append('not advertised in <program>')
    if not tree.has_payload_dir(brand, model_key):
        reasons.append('payload folder missing')
    script = tree.read_operation_script(brand, model_key, operation)
    if script is None:
        reasons.append('operation script missing')
    if family == FAMILY_UNKNOWN:
        reasons.append('operation is not a recognised workflow')

    return Dispatch(brand, model_key, operation, family, action,
                    family in SIMULATED_ONLY, '; '.join(reasons))


def _split_key(key):
    """`Devices Models` -> (Devices, Models) using the brand index."""
    if ' ' not in key:
        return key, ''
    head, _, tail = key.rpartition(' ')
    return head, tail
