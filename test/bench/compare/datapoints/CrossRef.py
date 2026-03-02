from datapoints.Data import Addr

from enum import Enum


class CrossRefType(Enum):
    CODE = 0
    CALL = 1
    MEM_WRITE = 2
    MEM_READ = 4
    # Unknown either memory read or write
    DATA = 6


class CrossRef:
    from_addr: Addr
    to_addr: Addr

    def __init__(self, from_addr: Addr, to_addr: Addr, type: CrossRefType):
        self.type = type
        self.from_addr = from_addr
        self.to_addr = to_addr
