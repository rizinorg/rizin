from Binary import Binary

from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


class ELFBinary(Binary):
    def __init__(self, bin_path: Path):
        super().__init__(bin_path)

    def _load_obj(self):
        self.obj = ELFFile.load_from_path(self.path)

    def can_load(bin_path: Path) -> bool:
        try:
            ELFFile.load_from_path(bin_path)
            return True
        except ELFError:
            return False
