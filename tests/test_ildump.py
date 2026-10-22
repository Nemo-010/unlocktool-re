"""The IL tooling must reproduce every IL citation in docs/.

These tests run only when a decoded ColokTool.exe is available (set
UNLOCKTOOL_COLOKTOOL, or let them be skipped).  They exist so the claims in
docs/protocol-report.md and docs/research-registry.md can be re-checked by
anyone, without dotnet/ilspy/mono.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))
sys.path.insert(0, os.path.join(HERE, '..', 'tools', 'il'))

from unlocktool_re import inno  # noqa: E402

try:
    from assembly import Assembly
    from il import disassemble
except ImportError:                       # pragma: no cover
    Assembly = None

EXE = os.environ.get('UNLOCKTOOL_COLOKTOOL')
PIECES = os.environ.get('UNLOCKTOOL_CHUNKS', '/workspace/src/chunks')


def _locate():
    """Return a path to a decoded ColokTool.exe, or None."""
    if EXE and os.path.isfile(EXE):
        return EXE
    decoded = os.path.join(os.path.dirname(EXE or ''), 'ColokTool.decoded.exe')
    if os.path.isfile(decoded):
        return decoded
    return None


DECODED = _locate()


def need_exe(obj):
    return unittest.skipUnless(DECODED and Assembly,
                              'set UNLOCKTOOL_COLOKTOOL to a decoded '
                              'ColokTool.exe')(obj)


def _load():
    return Assembly(DECODED)


def _il(asm, type_name, method_name):
    rid = asm.find_type(type_name)
    if rid is None:
        raise AssertionError('type %r not found' % type_name)
    for mid in asm.type_methods(rid):
        if asm.md.string(asm.row(asm.md, 6, mid)['Name']) == method_name:
            code = asm.body(mid)
            if code is None:
                raise AssertionError('%s::%s has no body'
                                     % (type_name, method_name))
            return disassemble(asm, code)
    raise AssertionError('%s::%s not found' % (type_name, method_name))


def _text(ins):
    return [(op, arg) for _off, op, arg, _raw in ins]


@need_exe
class TestTooling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.asm = _load()

    def test_assembly_shape(self):
        self.assertEqual(self.asm.assembly_name(), 'ColokTool')
        self.assertEqual(self.asm.md.runtime_version, 'v4.0.30319')
        self.assertEqual(self.asm.md.rows[2], 339)       # TypeDef
        self.assertEqual(self.asm.md.rows[6], 4101)      # MethodDef
        self.assertEqual(self.asm.md.rows[4], 4052)      # Field
        self.assertEqual(self.asm.md.rows[10], 1568)     # MemberRef
        self.assertEqual(len(self.asm.assembly_refs()), 21)
        self.assertEqual(len(self.asm.pinvokes()), 89)
        self.assertEqual(len(self.asm.field_rva_arrays()), 18)
        self.assertEqual(len(self.asm.manifest_resources()), 60)

    def test_module_refs_match_the_docs(self):
        refs = set(self.asm.module_refs().values())
        for expected in ('QMSL_MSVC10R.dll', 'kernel32.dll',
                         '\\data\\meta\\SPMETA_DLL.dll',
                         'data\\Unisoc\\spdio-1.0.dll',
                         'data\\Unisoc\\PhoneCommand.dll'):
            self.assertIn(expected, refs)

    def test_every_method_body_resolves(self):
        """A decoded image must have zero unmapped method RVAs."""
        bad = 0
        for rid in range(1, self.asm.md.rows[6] + 1):
            rva = self.asm.row(self.asm.md, 6, rid)['RVA']
            if not rva:
                continue
            try:
                off = self.asm.rva2off(rva)
                if self.asm.raw[off] & 3 not in (2, 3):
                    bad += 1
            except ValueError:
                bad += 1
        self.assertEqual(bad, 0)


@need_exe
class TestEncryptionClaims(unittest.TestCase):
    """docs/protocol-report.md section 3.1."""

    @classmethod
    def setUpClass(cls):
        cls.asm = _load()
        cls.ins = _text(_il(cls.asm, 'ColokTool.Loader_Thread', 'Encryption'))

    def test_sha256_precedes_the_kdf(self):
        flat = self.ins
        self.assertIn(('call', 'System.Security.Cryptography.SHA256::Create'), flat)
        # ComputeHash is applied to the password argument (ldarg.1) ...
        idx = next(i for i, (op, a) in enumerate(flat)
                   if op == 'callvirt'
                   and a == 'System.Security.Cryptography.HashAlgorithm::ComputeHash')
        self.assertEqual(flat[idx - 1], ('ldarg.1', ''))
        # ... and the digest replaces that argument, so the KDF gets the digest
        self.assertEqual(flat[idx + 1], ('starg.s', '1'))
        # the KDF is constructed after this, reading ldarg.1 (now the digest)
        kdf = next(i for i, (op, a) in enumerate(flat)
                   if op == 'newobj'
                   and a == 'System.Security.Cryptography.Rfc2898DeriveBytes::.ctor')
        self.assertGreater(kdf, idx)
        self.assertIn(('ldarg.1', ''), flat[idx:kdf])

    def test_kdf_parameters(self):
        flat = self.ins
        i = next(i for i, (op, a) in enumerate(flat)
                 if op == 'newobj'
                 and a == 'System.Security.Cryptography.Rfc2898DeriveBytes::.ctor')
        window = flat[i - 4:i]
        self.assertIn(('ldarg.1', ''), window)          # the digest
        self.assertIn(('ldsfld', 'field:saltBytes'), window)
        self.assertIn(('ldc.i4', '1000'), window)

    def test_aes_parameters(self):
        flat = self.ins
        self.assertIn(('ldc.i4', '256'),
                      [x for x in flat if x[0] == 'ldc.i4'])
        self.assertIn(('ldc.i4', '128'),
                      [x for x in flat if x[0] == 'ldc.i4'])
        # Key and IV come from the same Rfc2898DeriveBytes instance
        gets = [i for i, (op, a) in enumerate(flat)
                if op == 'callvirt'
                and a == 'System.Security.Cryptography.Rfc2898DeriveBytes::GetBytes']
        self.assertEqual(len(gets), 2)
        # both calls load the same local (the prf), no new instance between
        between = flat[gets[0]:gets[1]]
        self.assertNotIn('newobj', [op for op, _a in between])

    def test_mode_is_cbc(self):
        flat = self.ins
        i = next(i for i, (op, a) in enumerate(flat)
                 if op == 'callvirt'
                 and a == 'System.Security.Cryptography.SymmetricAlgorithm::set_Mode')
        self.assertIn(flat[i - 1], (('ldc.i4', '1'), ('ldc.i4.1', '')))


@need_exe
class TestLoaderCheck(unittest.TestCase):
    """docs/research-registry.md R25."""

    @classmethod
    def setUpClass(cls):
        cls.asm = _load()

    def test_loader_check_is_a_substring_test(self):
        ins = _text(_il(self.asm, 'ColokTool.Loader_Thread', 'EMMCBootFlash'))
        ops = [a for op, a in ins]
        # the literal is quoted by the disassembler
        self.assertIn('"ELF"', ops)
        self.assertIn('System.String::ToUpper', ops)
        self.assertIn('System.String::Contains', ops)
        # the 20-byte window: ldc.i4.s 20 precedes GetString
        i = ops.index('"ELF"')
        self.assertIn(('ldc.i4.s', '20'), ins[max(0, i - 8):i])

    def test_downloadbytes_is_local_only(self):
        ins = _il(self.asm, 'ColokTool.Loader_Thread', 'DownloadBytes')
        calls = [a for _o, op, a, _r in ins if op in ('call', 'callvirt')]
        # the only data source is the local offline tree; the rest is VB's
        # error bookkeeping (try/catch), not I/O
        self.assertEqual(
            [c for c in calls if 'OfflineData' in c],
            ['ColokTool.OfflineData::ReadAllBytes'])
        self.assertFalse([c for c in calls if 'System.Net' in c])
        self.assertFalse([c for c in calls if 'WebClient' in c])


@need_exe
class TestMtkFraming(unittest.TestCase):
    """docs/research-registry.md R18/R21."""

    @classmethod
    def setUpClass(cls):
        cls.asm = _load()

    def test_format_sector_uses_a_56_byte_frame(self):
        ins = _text(_il(self.asm, 'ColokTool.xflash_lib', 'ForMatSector'))
        literals = [a for op, a in ins if op == 'ldstr']
        self.assertIn('"EF EE EE FE 01 00 00 00 38 00 00 00"', literals)

    def test_cmdformat_field_layout(self):
        ins = _text(_il(self.asm, 'ColokTool.xflash_lib', 'cmdformat'))
        literals = [a.strip('"') for op, a in ins if op == 'ldstr']
        self.assertIn('01 00 00 00', literals)       # command
        self.assertIn('08 00 00 00', literals)       # userarea selector
        self.assertIn('boot1', literals)
        self.assertIn('userarea', literals)
        # two 16-byte zero runs -> 32 reserved bytes
        self.assertEqual(literals.count('00' * 16 + ' ' * 0), 0)
        self.assertEqual(
            sum(1 for x in literals if x.replace(' ', '') == '00' * 16), 2)

    def test_mtk_callers_hardcode_512(self):
        """The *MTK* callers use a literal 512; the firehose path does not."""
        ins = _text(_il(self.asm, 'ColokTool.thread_handling', 'FormatFRP'))
        reals = [a for op, a in ins if op == 'ldc.r8']
        self.assertIn('512.0', reals)

    def test_firehose_path_reads_sector_size_from_the_script(self):
        """Contrast with the MTK path: here SECTOR_SIZE_IN_BYTES is honoured."""
        ins = _text(_il(self.asm, 'ColokTool.Loader_Thread', 'EMMCBootFlash'))
        lits = [a.strip('"') for op, a in ins if op == 'ldstr']
        self.assertIn('SECTOR_SIZE_IN_BYTES', lits)
        self.assertIn('512', lits)
        self.assertIn('4096', lits)
        self.assertIn('emmc', lits)
        self.assertIn('ufs', lits)


@need_exe
class TestOperationResolution(unittest.TestCase):
    """docs/research-registry.md R23."""

    def test_operations_xml_and_script_paths(self):
        asm = _load()
        ins = _text(_il(asm, 'ColokTool.Loader_Thread', 'EMMCBootFlash'))
        literals = [a.strip('"') for op, a in ins if op == 'ldstr']
        self.assertIn('\\\\', literals)          # the path separator
        self.assertIn('Operation payload missing for this model', literals)
        self.assertIn('Operation not supported by this model', literals)
        # OperationSupported is consulted before giving up
        calls = [a for op, a in ins if op in ('call', 'callvirt')]
        self.assertIn('ColokTool.Loader_Thread::OperationSupported', calls)


@need_exe
class TestSamsungWrapper(unittest.TestCase):
    """docs/research-registry.md R28."""

    def test_odin_shells_out_to_dn_exe(self):
        asm = _load()
        ins = _text(_il(asm, 'ColokTool.Tread_SAMSUNG', 'ExecuteOdin'))
        literals = [a.strip('"') for op, a in ins if op == 'ldstr']
        self.assertIn('/data/dn.exe', literals)
        self.assertIn('runas',
                      [a.strip('"') for op, a in
                       _text(_il(asm, 'ColokTool.Tread_SAMSUNG', 'OdinDetect'))
                       if op == 'ldstr'])


if __name__ == '__main__':
    unittest.main()


@need_exe
class TestMergedLayoutsAreNotReferenced(unittest.TestCase):
    """docs/data-layouts.md: the merged-in layouts are foreign to this binary.

    This is the decisive test for the whole "data/ is a merge" claim: if the
    binary mentioned any of these filenames it would be reading them, and the
    four extra layouts would be part of *its* contract.
    """

    # `dn.exe` is deliberately NOT in this list: ColokTool *does* reference it
    # (Tread_SAMSUNG shells out to it), which is R28, not a counter-example.
    FOREIGN = ['device_info', 'model.json', 'qualcomm.pyd', 'PrimeToolX',
               'MotoKing', 'DA_BR', 'auth_sv5', 'loader.elf',
               '_MERGE-BACKUP', 'prime']

    def test_no_foreign_layout_is_referenced(self):
        raw = self._exe()
        for lit in self.FOREIGN:
            self.assertFalse(self._has(raw, lit),
                             'ColokTool.exe references %r' % lit)

    def test_the_layouts_it_does_reference(self):
        raw = self._exe()
        for lit in ('programs.bin', 'operations.xml', 'fdl1', 'fdl2',
                    'accounts.json', 'config.ini', 'dn.exe'):
            self.assertTrue(self._has(raw, lit),
                            'expected %r in the image' % lit)

    @staticmethod
    def _has(raw, lit):
        """Managed string literals live in the #US heap as UTF-16LE."""
        return lit.encode() in raw or lit.encode('utf-16le') in raw

    @staticmethod
    def _exe():
        with open(DECODED, 'rb') as fh:
            return fh.read()
