from numpy import uint64
from typing import TypeAlias

Addr: TypeAlias = uint64

# Tuple of address depicting a range between low and high address.
# Each range is an right open interval: [low, high)
AddrRange: TypeAlias = tuple[Addr, Addr]
