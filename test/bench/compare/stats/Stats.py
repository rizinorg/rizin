from stats.DPDuration import DPDuration, DPTypeDuration
from stats.Symbol import Symbol


class Stats:
    """
    A statistics object with a collection of data points.
    """

    def __init__(self):
        # The duration data points for a given library.
        self.duration_dps: dict[DPTypeDuration, DPDuration] = dict()
        self.symbols: dict[str, Symbol] = dict()

    def add_dps_duration(self, dps: dict[DPTypeDuration, DPDuration]):
        self.duration_dps.update(dps)

    def add_symbols(self, symbols: dict[str, Symbol]):
        self.symbols.update(symbols)

    def get_runtime_ms(self, type: DPTypeDuration) -> int | None:
        if type not in self.duration_dps:
            return None
        return self.duration_dps[type].get_delta_ms()
