#include "rx.h"

static ut64 prefetch_bytes(const ut8 *buf, size_t buf_len) {
	ut64 result = 0;
	size_t i;
	size_t end = buf_len < 8 ? buf_len : 8; // Determine end based on buf_len
	for (i = 0; i < end; i++) {
		result |= ((ut64)buf[i]) << ((7 - i) * 8); // Shift and combine
	}
	return result;
}

bool rx_inst_stringify(RxInst *inst, RzStrBuf *buf) {
}

/**
 * Parse binary data to RxInst according to RxDesc
 * @param inst
 * @param bytes_read
 * @param buf
 * @param buf_len
 * @return
 */
bool rx_dis(RxInst RZ_OUT *inst, st32 RZ_OUT *bytes_read, const ut8 *buf, size_t buf_len) {
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
	// rx instruction length vary from 1 to 8 Bytes
	ut64 prefetched_bytes = prefetch_bytes(buf, buf_len);
	RxInst current_inst = { 0 };
	st32 bytes_read_real = 0;
	for (ut32 desc_id = 0; desc_id < RX_DESC_SIZE; ++desc_id) {
		bool is_valid = rx_try_match_and_parse(&current_inst, &rx_inst_descs[desc_id],
			&bytes_read_real, prefetched_bytes);
		if (is_valid) {
			*inst = current_inst;
			*bytes_read = bytes_read_real;
			return true;
		}
	}

	// nothing matched known instruction
	return false;
}
