#include "rx.h"

/**
 * Parse binary data to RxInst according to RxDesc
 * @param inst
 * @param bytes_read
 * @param buf
 * @param buf_len
 * @return
 */
bool rx_dis(RxInst RZ_OUT *inst, size_t RZ_OUT *bytes_read, const ut8 *buf, size_t buf_len) {
    /**
     * Pseudo code
     * offset = 0
     * prefetch_bytes = read8(buf) // instruction max size is 8B
     * if fail, prefetch_bytes = read_remain(buf)
     *
     * for desc in desc_map
     *     if (try_match_and_parse(inst, desc, offset, prefetch_bytes))
     *          *bytes_read = offset
     *          break;
     * return false;
     */
}
