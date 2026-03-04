from datapoints.Data import Addr

from enum import Enum


class SymbolType(Enum):
    UNSPECIFIED = 0
    FUNCTION = 1
    OBJECT = 2


class Symbol:
    def __init__(self, name: str, type: SymbolType, size: int, location: Addr):
        self.name = name
        self.type = type
        self.size = size
        self.location = location
        # Tuple of address ranges a symbol covers.
        # Each range is an right open interval: [low, high)
        self.ranges: list[tuple[Addr, Addr]] = list()

        self.entry_points: list[Addr] = list()

    def add_range(self, range: tuple[Addr, Addr]):
        self.ranges.append(range)

    def add_entry_point(self, entry_point: Addr):
        self.entry_points.append(entry_point)

    def set_size(self, size: int):
        self.size = size

    def __repr__(self):
        return f"SYMBOL<{self.name} | type: {self.type} | entries: {[e for e in self.entry_points]} | ranges: {[e for e in self.ranges]}>"
