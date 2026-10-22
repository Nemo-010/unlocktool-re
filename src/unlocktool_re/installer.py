"""Open an Inno Setup installer and enumerate / extract its payload files."""

import os
import struct

from . import inno, setup0

SETUP_ID_LEN = 64
ENCRYPTION_CRC_LEN = 4
ENCRYPTION_HEADER_LEN = 49      # TSetupEncryptionHeader, 6.7.0 layout


class Installer:
    def __init__(self, source):
        if isinstance(source, (list, tuple)):
            self.src = inno.ChunkSource.from_paths(source)
        else:
            self.src = inno.ChunkSource.from_paths([source])
        self._load()

    # -- loading -----------------------------------------------------------
    def _load(self):
        table = inno.find_loader_offset_table(self.src)
        raw = self.src.read(table['offset'], table['size'])
        if raw[:12] != inno.OFFSET_TABLE_ID:
            raise inno.InnoFormatError('offset table magic mismatch')
        # TSetupLdrOffsetTable:
        #   ID[12], Version:UInt32, TotalSize:Int64, OffsetEXE:Int64,
        #   UncompressedSizeEXE:UInt32, CRCEXE:Int32,
        #   Offset0:Int64, Offset1:Int64, ReservedPadding:UInt32, TableCRC:Int32
        (ver, total_size, offset_exe, unc_exe, crc_exe,
         offset0, offset1) = struct.unpack_from('<IqqIIqq', raw, 12)
        self.table = {'version': ver, 'total_size': total_size,
                      'offset_exe': offset_exe,
                      'uncompressed_exe': unc_exe, 'crc_exe': crc_exe,
                      'offset0': offset0, 'offset1': offset1}
        self.header_offset = offset0
        self.slice_offset = offset1

        version = self.src.read(offset0, SETUP_ID_LEN).split(b'\0')[0].decode('latin1')
        self.version = version
        enc_crc = self.src.read(offset0 + SETUP_ID_LEN, ENCRYPTION_CRC_LEN)
        enc_at = offset0 + SETUP_ID_LEN + ENCRYPTION_CRC_LEN
        enc = self.src.read(enc_at, ENCRYPTION_HEADER_LEN)
        self.encryption = {
            'crc': struct.unpack('<I', enc_crc)[0],
            'use': enc[0],                        # 0 = none, 1 = files, 2 = full
            'kdf_salt': enc[1:17],
            'kdf_iterations': struct.unpack('<i', enc[17:21])[0],
            'base_nonce': enc[21:41],
            'password_test': struct.unpack('<i', enc[41:45])[0],
        }
        b1 = inno.BlockReader(
            self.src, enc_at + ENCRYPTION_HEADER_LEN)
        block1 = b1.read(self.src)
        b2 = inno.BlockReader(self.src, b1.end_offset)
        block2 = b2.read(self.src)
        self.setup0 = setup0.parse_setup0(block1, block2, version)
        self._slice = inno.SliceReader(self.src, self.slice_offset)

    # -- queries -----------------------------------------------------------
    @property
    def header(self):
        return self.setup0['header']

    @property
    def files(self):
        return self.setup0['files']

    @property
    def locations(self):
        return self.setup0['locations']

    def dest_names(self):
        out = []
        for f in self.files:
            name = f['DestName']
            if name:
                out.append(name.replace('{app}\\', '').replace('\\', '/'))
        return out

    def read_file(self, entry):
        """Return the raw (still call-instruction-transformed) bytes."""
        li = entry['LocationEntry']
        if li < 0 or li >= len(self.locations):
            raise KeyError('no data for %r' % entry['DestName'])
        return self._slice.read(self.locations[li])

    def read_path(self, rel):
        rel = rel.replace('/', '\\')
        for f in self.files:
            name = f['DestName']
            if name and name.replace('{app}\\', '') == rel:
                return self.read_file(f)
        raise KeyError(rel)

    def close(self):
        self.src.close()
