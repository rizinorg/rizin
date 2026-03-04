from enum import Enum
from time import monotonic_ns


class DPTypeDuration(Enum):
    RUNTIME_OPEN_FILE = 0
    RUNTIME_ANALYZE_ALL = 1


class DPDuration:
    """
    Duration data point.
    """

    def __init__(self, type: DPTypeDuration, start_ns: int = monotonic_ns()):
        self.type: DPTypeDuration = type
        self.start_ns: int = start_ns
        self.end_ns: int = 0

    def set_end(self):
        self.end_ns: int = monotonic_ns()

    def get_delta_ns(self) -> int:
        if self.end_ns == 0:
            raise ValueError("end_ns wasn't set yet.")
        return self.end_ns - self.start_ns

    def get_delta_ms(self) -> int:
        return self.get_delta_ns() / 1000
