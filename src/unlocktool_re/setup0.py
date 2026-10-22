"""Parser for the Inno Setup 6.7.0 setup-0 header blocks.

Field order and sizes are transcribed from jrsoftware/issrc tag is-6_7_0,
Projects/Src/Shared.Struct.pas.  `SECompressedBlockWrite` (Shared.SetupEntFunc)
writes each record as: every `String` field as UInt32 byte-length + UTF-16LE
bytes, then every `AnsiString` field as UInt32 byte-length + bytes, then the
remaining fixed-size fields.

Verified property of this parser: both header blocks are consumed to the exact
byte, with zero trailing data.  That is the acceptance test in
tests/test_inno670.py.
"""

import struct

# --- TSetupHeader -----------------------------------------------------------

HEADER_STRINGS = [
    'AppName', 'AppVerName', 'AppId', 'AppCopyright', 'AppPublisher',
    'AppPublisherURL', 'AppSupportPhone', 'AppSupportURL', 'AppUpdatesURL',
    'AppVersion', 'DefaultDirName', 'DefaultGroupName', 'BaseFilename',
    'UninstallFilesDir', 'UninstallDisplayName', 'UninstallDisplayIcon',
    'AppMutex', 'DefaultUserInfoName', 'DefaultUserInfoOrg',
    'DefaultUserInfoSerial', 'AppReadmeFile', 'AppContact', 'AppComments',
    'AppModifyPath', 'CreateUninstallRegKey', 'Uninstallable',
    'CloseApplicationsFilter', 'SetupMutex', 'ChangesEnvironment',
    'ChangesAssociations', 'ArchitecturesAllowed',
    'ArchitecturesInstallIn64BitMode', 'CloseApplicationsFilterExcludes',
    'SevenZipLibraryName', 'UsePreviousAppDir', 'UsePreviousGroup',
    'UsePreviousSetupType', 'UsePreviousTasks', 'UsePreviousUserInfo',
]
HEADER_ANSI = ['LicenseText', 'InfoBeforeText', 'InfoAfterText',
               'CompiledCodeText']
HEADER_INTS = [
    'NumLanguageEntries', 'NumCustomMessageEntries', 'NumPermissionEntries',
    'NumTypeEntries', 'NumComponentEntries', 'NumTaskEntries', 'NumDirEntries',
    'NumISSigKeyEntries', 'NumFileEntries', 'NumFileLocationEntries',
    'NumIconEntries', 'NumIniEntries', 'NumRegistryEntries',
    'NumInstallDeleteEntries', 'NumUninstallDeleteEntries', 'NumRunEntries',
    'NumUninstallRunEntries',
]

# TSetupHeaderOption has 49 real members plus padding up to 57, so the packed
# set is 8 bytes in both 32- and 64-bit builds.
HEADER_OPTION_BITS = 57
# TSetupFileEntryOption likewise pads to 57.
FILE_OPTION_BITS = 57

TASK_OPTION_BITS = 5
DIR_OPTION_BITS = 5
ICON_OPTION_BITS = 6
REGISTRY_OPTION_BITS = 12
RUN_OPTION_BITS = 12
LOCATION_OPTION_BITS = 5


class Cursor:
    def __init__(self, data, name='<block>'):
        self.d = data
        self.p = 0
        self.name = name

    def take(self, n):
        b = self.d[self.p:self.p + n]
        if len(b) != n:
            raise EOFError('%s: short read at %d (need %d)' % (self.name, self.p, n))
        self.p += n
        return b

    def u8(self):
        return self.take(1)[0]

    def i8(self):
        return struct.unpack('<b', self.take(1))[0]

    def u16(self):
        return struct.unpack('<H', self.take(2))[0]

    def i16(self):
        return struct.unpack('<h', self.take(2))[0]

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def i32(self):
        return struct.unpack('<i', self.take(4))[0]

    def u64(self):
        return struct.unpack('<Q', self.take(8))[0]

    def i64(self):
        return struct.unpack('<q', self.take(8))[0]

    def string(self):
        n = self.u32()
        if n == 0:
            return ''
        return self.take(n).decode('utf-16le', 'replace')

    def astring(self):
        n = self.u32()
        if n == 0:
            return b''
        return self.take(n)

    def flags(self, nbits):
        nbytes = (nbits + 7) // 8
        if nbytes == 3:
            nbytes = 4          # 3-byte sets are padded to 4
        return int.from_bytes(self.take(nbytes), 'little')

    def version_data(self):
        """TSetupVersionData: WinVersion, NTVersion: Cardinal; NTServicePack: Word"""
        return {'WinVersion': self.u32(), 'NTVersion': self.u32(),
                'NTServicePack': self.u16()}

    def remaining(self):
        return len(self.d) - self.p


def parse_header(cur):
    h = {}
    for name in HEADER_STRINGS:
        h[name] = cur.string()
    for name in HEADER_ANSI:
        h[name] = cur.astring()
    for name in HEADER_INTS:
        h[name] = cur.i32()
    h['MinVersion'] = cur.version_data()
    h['OnlyBelowVersion'] = cur.version_data()
    h['WizardSizePercentX'] = cur.i32()
    h['WizardSizePercentY'] = cur.i32()
    h['WizardDarkStyle'] = cur.u8()
    h['WizardImageAlphaFormat'] = cur.u8()
    for name in ('WizardImageBackColor', 'WizardSmallImageBackColor',
                 'WizardBackColor', 'WizardImageBackColorDynamicDark',
                 'WizardSmallImageBackColorDynamicDark',
                 'WizardBackColorDynamicDark'):
        h[name] = cur.i32()
    h['WizardImageOpacity'] = cur.u8()
    h['WizardBackImageOpacity'] = cur.u8()
    h['WizardLightControlStyling'] = cur.u8()
    h['ExtraDiskSpaceRequired'] = cur.i64()
    h['SlicesPerDisk'] = cur.i32()
    h['UninstallLogMode'] = cur.u8()
    h['DirExistsWarning'] = cur.u8()
    h['PrivilegesRequired'] = cur.u8()
    h['PrivilegesRequiredOverridesAllowed'] = cur.u8()
    h['ShowLanguageDialog'] = cur.u8()
    h['LanguageDetectionMethod'] = cur.u8()
    h['CompressMethod'] = cur.u8()
    h['DisableDirPage'] = cur.u8()
    h['DisableProgramGroupPage'] = cur.u8()
    h['UninstallDisplaySize'] = cur.i64()
    h['Options'] = cur.flags(HEADER_OPTION_BITS)
    return h


# --- entry records ----------------------------------------------------------

def parse_language(cur):
    e = {}
    for name in ('Name', 'LanguageName', 'DialogFontName', 'WelcomeFontName'):
        e[name] = cur.string()
    for name in ('Data', 'LicenseText', 'InfoBeforeText', 'InfoAfterText'):
        e[name] = cur.astring()
    e['LanguageID'] = cur.u16()
    e['DialogFontSize'] = cur.i32()
    e['DialogFontBaseScaleHeight'] = cur.i32()
    e['DialogFontBaseScaleWidth'] = cur.i32()
    e['WelcomeFontSize'] = cur.i32()
    e['RightToLeft'] = cur.u8()
    return e


def parse_custom_message(cur):
    return {'Name': cur.string(), 'Value': cur.string(),
            'LangIndex': cur.i32()}


def parse_permission(cur):
    return {'Permissions': cur.astring()}


def parse_type(cur):
    e = {}
    for name in ('Name', 'Description', 'Languages', 'CheckOnce'):
        e[name] = cur.string()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['Options'] = cur.flags(1)
    e['Typ'] = cur.u8()
    e['Size'] = cur.i64()
    return e


def parse_component(cur):
    e = {}
    for name in ('Name', 'Description', 'Types', 'Languages', 'CheckOnce'):
        e[name] = cur.string()
    e['ExtraDiskSpaceRequired'] = cur.i64()
    e['Level'] = cur.u8()
    e['Used'] = cur.u8()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['Options'] = cur.flags(5)
    e['Size'] = cur.i64()
    return e


def parse_task(cur):
    e = {}
    for name in ('Name', 'Description', 'GroupDescription', 'Components',
                 'Languages', 'Check'):
        e[name] = cur.string()
    e['Level'] = cur.u8()
    e['Used'] = cur.u8()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['Options'] = cur.flags(TASK_OPTION_BITS)
    return e


def parse_dir(cur):
    e = {}
    for name in ('DirName', 'Components', 'Tasks', 'Languages', 'Check',
                 'AfterInstall', 'BeforeInstall'):
        e[name] = cur.string()
    e['Attribs'] = cur.i32()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['PermissionsEntry'] = cur.i16()
    e['Options'] = cur.flags(DIR_OPTION_BITS)
    return e


def parse_issigkey(cur):
    return {'PublicX': cur.string(), 'PublicY': cur.string(),
            'RuntimeID': cur.string()}


def parse_file(cur):
    e = {}
    for name in ('SourceFilename', 'DestName', 'InstallFontName',
                 'StrongAssemblyName', 'Components', 'Tasks', 'Languages',
                 'Check', 'AfterInstall', 'BeforeInstall', 'Excludes',
                 'DownloadISSigSource', 'DownloadUserName', 'DownloadPassword',
                 'ExtractArchivePassword'):
        e[name] = cur.string()
    # TSetupFileVerification: ISSigAllowedKeys (AnsiString) first, then hash
    e['ISSigAllowedKeys'] = cur.astring()
    e['Hash'] = cur.take(32)
    e['VerifyType'] = cur.u8()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['LocationEntry'] = cur.i32()
    e['Attribs'] = cur.i32()
    e['ExternalSize'] = cur.i64()
    e['PermissionsEntry'] = cur.i16()
    e['Options'] = cur.flags(FILE_OPTION_BITS)
    e['FileType'] = cur.u8()
    return e


def parse_icon(cur):
    e = {}
    for name in ('IconName', 'Filename', 'Parameters', 'WorkingDir',
                 'IconFilename', 'Comment', 'Components', 'Tasks', 'Languages',
                 'Check', 'AfterInstall', 'BeforeInstall', 'AppUserModelID'):
        e[name] = cur.string()
    e['ToastCLSID'] = cur.take(16)
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['IconIndex'] = cur.i32()
    e['ShowCmd'] = cur.i32()
    e['CloseOnExit'] = cur.u8()
    e['HotKey'] = cur.u16()
    e['Options'] = cur.flags(ICON_OPTION_BITS)
    return e


def parse_ini(cur):
    e = {}
    for name in ('Filename', 'Section', 'Entry', 'Value', 'Components',
                 'Tasks', 'Languages', 'Check', 'AfterInstall',
                 'BeforeInstall'):
        e[name] = cur.string()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['Options'] = cur.flags(5)
    return e


def parse_registry(cur):
    e = {}
    for name in ('Subkey', 'ValueName', 'ValueData', 'Components', 'Tasks',
                 'Languages', 'Check', 'AfterInstall', 'BeforeInstall'):
        e[name] = cur.string()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['RootKey'] = cur.u32()
    e['PermissionsEntry'] = cur.i16()
    e['Typ'] = cur.u8()
    e['Options'] = cur.flags(REGISTRY_OPTION_BITS)
    return e


def parse_delete(cur):
    e = {}
    for name in ('Name', 'Components', 'Tasks', 'Languages', 'Check',
                 'AfterInstall', 'BeforeInstall'):
        e[name] = cur.string()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['DeleteType'] = cur.u8()
    return e


def parse_run(cur):
    e = {}
    for name in ('Name', 'Parameters', 'WorkingDir', 'RunOnceId', 'StatusMsg',
                 'Verb', 'Description', 'Components', 'Tasks', 'Languages',
                 'Check', 'AfterInstall', 'BeforeInstall'):
        e[name] = cur.string()
    e['MinVersion'] = cur.version_data()
    e['OnlyBelowVersion'] = cur.version_data()
    e['ShowCmd'] = cur.i32()
    e['Wait'] = cur.u8()
    e['Options'] = cur.flags(RUN_OPTION_BITS)
    return e


def parse_location(cur):
    """TSetupFileLocationEntry (issrc 6.7.0)."""
    e = {}
    e['FirstSlice'] = cur.i32()
    e['LastSlice'] = cur.i32()
    e['StartOffset'] = cur.i64()
    e['ChunkSuboffset'] = cur.i64()
    e['OriginalSize'] = cur.i64()
    e['ChunkCompressedSize'] = cur.i64()
    e['SHA256Sum'] = cur.take(32)
    e['TimeStamp'] = cur.i64()
    e['FileVersionMS'] = cur.u32()
    e['FileVersionLS'] = cur.u32()
    e['Flags'] = cur.flags(LOCATION_OPTION_BITS)
    return e


# --- wizard image groups ----------------------------------------------------

WIZARD_IMAGE_GROUPS = 6   # images, small, back, images-dark, small-dark, back-dark


def parse_wizard_images(cur):
    """count == -1 means 'identical to the previous group'."""
    count = cur.i32()
    if count == -1:
        return None
    if count < 0:
        raise ValueError('bad wizard image count %d' % count)
    images = []
    for _ in range(count):
        n = cur.u32()
        images.append(cur.take(n) if n else b'')
    return images


def parse_setup0(block1, block2, version_string):
    """Parse both setup-0 blocks into a plain dict."""
    out = {'version': version_string}
    cur = Cursor(block1, 'block1')
    h = parse_header(cur)
    out['header'] = h
    out['languages'] = [parse_language(cur)
                        for _ in range(h['NumLanguageEntries'])]
    out['custom_messages'] = [parse_custom_message(cur)
                              for _ in range(h['NumCustomMessageEntries'])]
    out['permissions'] = [parse_permission(cur)
                          for _ in range(h['NumPermissionEntries'])]
    out['types'] = [parse_type(cur) for _ in range(h['NumTypeEntries'])]
    out['components'] = [parse_component(cur)
                         for _ in range(h['NumComponentEntries'])]
    out['tasks'] = [parse_task(cur) for _ in range(h['NumTaskEntries'])]
    out['dirs'] = [parse_dir(cur) for _ in range(h['NumDirEntries'])]
    out['issigkeys'] = [parse_issigkey(cur)
                        for _ in range(h['NumISSigKeyEntries'])]
    out['files'] = [parse_file(cur) for _ in range(h['NumFileEntries'])]
    out['icons'] = [parse_icon(cur) for _ in range(h['NumIconEntries'])]
    out['ini'] = [parse_ini(cur) for _ in range(h['NumIniEntries'])]
    out['registry'] = [parse_registry(cur)
                       for _ in range(h['NumRegistryEntries'])]
    out['install_delete'] = [parse_delete(cur)
                             for _ in range(h['NumInstallDeleteEntries'])]
    out['uninstall_delete'] = [parse_delete(cur)
                               for _ in range(h['NumUninstallDeleteEntries'])]
    out['run'] = [parse_run(cur) for _ in range(h['NumRunEntries'])]
    out['uninstall_run'] = [parse_run(cur)
                            for _ in range(h['NumUninstallRunEntries'])]
    out['wizard_images'] = [parse_wizard_images(cur)
                            for _ in range(WIZARD_IMAGE_GROUPS)]
    if h['SevenZipLibraryName']:
        n = cur.u32()
        out['sevenzip_dll'] = cur.take(n)
    out['block1_consumed'] = cur.p
    out['block1_trailing'] = cur.remaining()

    cur2 = Cursor(block2, 'block2')
    out['locations'] = [parse_location(cur2)
                        for _ in range(h['NumFileLocationEntries'])]
    out['block2_consumed'] = cur2.p
    out['block2_trailing'] = cur2.remaining()
    return out
