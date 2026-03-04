from Binary import Binary
from Framework import FRAMEWORK_RIZIN, Framework
from datapoints.Bench import DPDuration, DPTypeDuration

import json
import rzpipe


class RizinFramework(Framework):
    def __init__(self):
        super().__init__(FRAMEWORK_RIZIN)

    def init_framework(self):
        pass

    def auto_analyze_bin(self, bin: Binary) -> list[DPDuration]:
        dps = list()

        open_dp = DPDuration(DPTypeDuration.RUNTIME_OPEN_FILE)
        pipe = rzpipe.open(str(bin.path))
        open_dp.set_end()
        dps.append(open_dp)

        aaa_dp = DPDuration(DPTypeDuration.RUNTIME_ANALYZE_ALL)
        pipe.cmd("aaaaIp")
        aaa_dp.set_end()
        dps.append(aaa_dp)

        # Add references and functions and all to
        all_fcns_json = pipe.cmd("aflj")
        all_fcns = json.loads(all_fcns_json)
        for fcn in all_fcns:
            pass

        pipe.quit()
        return dps
