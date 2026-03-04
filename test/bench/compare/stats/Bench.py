from stats.DPDuration import DPDuration


class Stats:
    """
    A statistics object with a collection of data points.
    """

    def __init__(self):
        # The duration data points for a given library.
        self.duration_dps: list[DPDuration] = list()

    def add_dps_duration(self, dps: list[DPDuration]):
        self.duration_dps += dps
