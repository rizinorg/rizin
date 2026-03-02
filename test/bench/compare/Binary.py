from abc import ABC, abstractmethod
from pathlib import Path
from elftools.elf.elffile import ELFFile


class Object(ABC):
    obj: ELFFile

    def __init__(self, bin_path: Path) -> None:
        self.path: Path = bin_path
        if not self.path.exists():
            raise ValueError(f"Binary path '{self.path}' doesn't exist.")

    @abstractmethod
    def _load_obj(self):
        raise NotImplementedError("_load_bin isn't implemented.")

    @abstractmethod
    def can_load(bin_path: Path) -> bool:
        raise NotImplementedError("_can_load isn't implemented.")


class Binary:
    def __init__(self, bin_path: Path) -> None:
        self.path: Path = bin_path
        if not self.path.exists():
            raise ValueError(f"Binary path '{self.path}' doesn't exist.")

        self.bin: ELFFile

        from ELFObject import ELFObject

        if ELFObject.can_load(self.path):
            self.obj = ELFObject(self.path)
        else:
            raise NotImplementedError(f"Found no binary handler for {self.path}")
