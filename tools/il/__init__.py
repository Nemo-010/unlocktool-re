"""A dependency-free ECMA-335 metadata and IL reader.

Used by `tools/ildump.py` so every IL citation in `docs/` can be re-checked
without external tooling (no dotnet, no ilspy, no mono).
"""

from assembly import Assembly
from il import disassemble
from metadata import Metadata, TABLE_NAMES
