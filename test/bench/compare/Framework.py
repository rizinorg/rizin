from abc import ABC, abstractmethod
from Binary import Binary

FRAMEWORK_RIZIN = "rz"
FRAMEWORK_RIZIN_OLD_ANALYSIS = "rz_old_ana"
FRAMEWORK_IDA = "IDA"
FRAMEWORK_GHIDRA = "Ghidra"
FRAMEWORK_RADARE2 = "r2"
FRAMEWORK_BINARY_NINJA = "binja"

FRAMEWORK_NAMES = [
    FRAMEWORK_RIZIN,
    # FRAMEWORK_RIZIN_OLD_ANALYSIS,
    # FRAMEWORK_IDA,
    # FRAMEWORK_GHIDRA,
    # FRAMEWORK_RADARE2,
    # FRAMEWORK_BINARY_NINJA
]


class Framework(ABC):
    def __init__(self, name: str):
        self.name = name
        self.init_framework()

    @abstractmethod
    def init_framework(self):
        raise NotImplementedError("init_framework isn't implemented.")

    @abstractmethod
    def auto_analyze_bin(self, bin: Binary):
        raise NotImplementedError("analyze_bin isn't implemented.")


def init_framework_by_name(framework_name: str) -> Framework:
    if framework_name == FRAMEWORK_RIZIN:
        from RizinFramework import RizinFramework

        return RizinFramework()
    else:
        raise NotImplementedError(f"{framework_name} not implemented yet.")
