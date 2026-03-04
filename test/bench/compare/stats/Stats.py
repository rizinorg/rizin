from stats.DPDuration import DPDuration
from stats.Symbol import Symbol


class Stats:
    """
    A statistics object with a collection of data points.
    """

    def __init__(self):
        # The duration data points for a given library.
        self.duration_dps: list[DPDuration] = list()
        self.symbols: dict[str, Symbol] = dict()

    def add_dps_duration(self, dps: list[DPDuration]):
        self.duration_dps += dps

    def add_symbols(self, symbols: dict[str, Symbol]):
        self.symbols.update(symbols)
