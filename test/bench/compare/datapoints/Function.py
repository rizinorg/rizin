from datapoints.Data import Addr


class Function:
    # Tuple of address ranges a function covers.
    # Each range is an right open interval: [low, high)
    ranges: list[tuple[Addr, Addr]] = list()

    entry_points: list[Addr] = list()

    def add_range(self, range: tuple[Addr, Addr]):
        self.ranges.append(range)

    def add_entry_point(self, entry_point: Addr):
        self.entry_points.append(entry_point)
