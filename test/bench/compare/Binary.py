from abc import ABC, abstractmethod
from pathlib import Path
from elftools.elf.elffile import ELFFile


class Binary(ABC):
    obj: ELFFile

    def __init__(self, bin_path: Path):
        self.path: Path = bin_path
        if not self.path.exists():
            raise ValueError(f"Binary path '{self.path}' doesn't exist.")
        self._load_obj()

    @abstractmethod
    def _load_obj(self):
        raise NotImplementedError("_load_bin isn't implemented.")

    @staticmethod
    def can_load(bin_path: Path) -> bool:
        raise NotImplementedError("_can_load isn't implemented.")


def init_binary(bin_path: Path) -> Binary:
    if not bin_path.exists():
        raise ValueError(f"Binary path '{bin_path}' doesn't exist.")

    from ELFBinary import ELFBinary

    if ELFBinary.can_load(bin_path):
        return ELFBinary(bin_path)
    else:
        raise NotImplementedError(f"Found no binary handler for {bin_path}")
