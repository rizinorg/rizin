from Binary import Binary
from Framework import FRAMEWORK_RIZIN, Framework
from stats.Symbol import Symbol, SymbolType
from stats.DPDuration import DPDuration, DPTypeDuration
from stats.Data import Addr

import logging as log
import json
import rzpipe


class RizinFramework(Framework):
    def __init__(self):
        super().__init__(FRAMEWORK_RIZIN)

    def init_framework(self):
        pass

    def analyze_bin(self, bin: Binary) -> dict[DPTypeDuration, DPDuration]:
        dps = dict()

        open_dp = DPDuration(DPTypeDuration.RUNTIME_OPEN_FILE)
        pipe = rzpipe.open(str(bin.path))
        open_dp.set_end()
        dps[DPTypeDuration.RUNTIME_OPEN_FILE] = open_dp

        aaa_dp = DPDuration(DPTypeDuration.RUNTIME_ANALYZE_ALL)
        pipe.cmd("e log.level=5")
        pipe.cmd("aaaaIp")
        aaa_dp.set_end()
        dps[DPTypeDuration.RUNTIME_ANALYZE_ALL] = aaa_dp

        # Add references and functions and all to
        all_fcns_json = pipe.cmd("aflj")
        all_fcns = json.loads(all_fcns_json)
        for fcn in all_fcns:
            fcn_addr = fcn["offset"]
            fcn_bbs = json.loads(pipe.cmd(f"afbj @ {fcn_addr:#x}"))
            fcn_size = fcn["size"]
            fcn_name = fcn["name"].strip("sym.")
            symbol = Symbol(fcn_name, SymbolType.FUNCTION, fcn_size, Addr(fcn_addr))
            symbol.add_entry_point(fcn_addr)

            size_check = 0
            for bb in fcn_bbs:
                size_check += bb["size"]
                symbol.add_range((Addr(bb["addr"]), Addr(bb["addr"] + bb["size"])))
            if size_check != symbol.size:
                log.warning(
                    f"Function {fcn_name} accumulated BBs have a different size than assigned in Rizin."
                )
            self.symbols[fcn_name] = symbol

        pipe.quit()
        return dps
