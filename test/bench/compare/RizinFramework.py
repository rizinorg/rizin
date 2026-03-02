from Binary import Binary
from Framework import FRAMEWORK_RIZIN, Framework


class RizinFramework(Framework):
    def __init__(self):
        super().__init__(FRAMEWORK_RIZIN)

    def init_framework(self):
        pass

    def auto_analyze_bin(self, bin: Binary):
        raise NotImplementedError("analyze_bin isn't implemented.")
