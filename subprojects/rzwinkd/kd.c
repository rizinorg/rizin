// SPDX-FileCopyrightText: 2014-2017 LemonBoy <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kd.h"
#include <rz_util/rz_log.h>

#define KD_DBG if (false)

ut32 kd_data_checksum(const ut8 *buf, const ut64 buf_len) {
	ut32 i, acc;

	if (!buf || !buf_len) {
		return 0;
	}

	for (i = acc = 0; i < buf_len; i++) {
		acc += buf[i];
	}

	return acc;
}

int kd_send_ctrl_packet(io_desc_t *desc, const ut32 type, const ut32 id) {
	kd_packet_t pkt;

	pkt.leader = KD_PACKET_CTRL;
	pkt.length = 0;
	pkt.checksum = 0;
	pkt.id = id;
	pkt.type = type;

	if (iob_write(desc, (ut8 *)&pkt, sizeof(kd_packet_t)) < 0) {
		return KD_E_IOERR;
	}

	return KD_E_OK;
}

int kd_send_data_packet(io_desc_t *desc, const ut32 type, const ut32 id, const ut8 *req,
	const int req_len, const ut8 *buf, const ut32 buf_len) {
	kd_packet_t pkt;

	if (req_len + buf_len > KD_MAX_PAYLOAD) {
		return KD_E_MALFORMED;
	}

	RZ_LOG_DEBUG("==== Send Data ====\n");
	RZ_LOG_DEBUG("ID: 0x%" PFMT32x "\n", id);
	RZ_LOG_DEBUG("Type: 0x%" PFMT32x "\n", type);

	pkt.leader = KD_PACKET_DATA;
	pkt.length = req_len + buf_len;
	pkt.checksum = kd_data_checksum(req, req_len) + kd_data_checksum(buf, buf_len);
	pkt.id = id;
	pkt.type = type;

	if (iob_write(desc, (ut8 *)&pkt, sizeof(kd_packet_t)) < 0) {
		return KD_E_IOERR;
	}

	if (iob_write(desc, (ut8 *)req, req_len) < 0) {
		return KD_E_IOERR;
	}

	if (buf && iob_write(desc, (ut8 *)buf, buf_len) < 0) {
		return KD_E_IOERR;
	}

	if (desc->iob->type == KD_IO_PIPE) {
		if (iob_write(desc, (ut8 *)"\xAA", 1) < 0) {
			return KD_E_IOERR;
		}
	}

	return KD_E_OK;
}

int kd_read_packet(io_desc_t *desc, kd_packet_t **p) {
	kd_packet_t pkt;
	ut8 *buf;

	*p = NULL;

	if (iob_read(desc, (ut8 *)&pkt, sizeof(kd_packet_t)) <= 0) {
		return KD_E_IOERR;
	}

	if (!kd_packet_is_valid(&pkt)) {
		KD_DBG eprintf("invalid leader %08x, trying to recover\n", pkt.leader);
		while (!kd_packet_is_valid(&pkt)) {
			kd_send_ctrl_packet(desc, KD_PACKET_TYPE_RESEND, 0);
			char sig[4];
			// Read byte-by-byte searching for the start of a packet
			int ret;
			while ((ret = iob_read(desc, (ut8 *)&sig, 1)) > 0) {
				if (sig[0] == '0' || sig[0] == 'i') {
					if (iob_read(desc, (ut8 *)&sig + 1, 3) == 3) {
						if (strncmp(sig, "000", 3) && strncmp(sig, "iii", 3)) {
							continue;
						}
						memcpy(&pkt, sig, sizeof(sig));
						if (iob_read(desc, (ut8 *)&pkt + 4, sizeof(kd_packet_t) - 4) <= 0) {
							return KD_E_IOERR;
						}
						break;
					} else {
						return KD_E_IOERR;
					}
				}
			}
			if (!ret) {
				return KD_E_IOERR;
			}
		}
	}

	buf = malloc(sizeof(kd_packet_t) + pkt.length);
	if (!buf) {
		return KD_E_IOERR;
	}
	memcpy(buf, &pkt, sizeof(kd_packet_t));

	if (pkt.length) {
		iob_read(desc, (ut8 *)buf + sizeof(kd_packet_t), pkt.length);
	}

	if (pkt.checksum != kd_data_checksum(buf + sizeof(kd_packet_t), pkt.length)) {
		KD_DBG eprintf("Checksum mismatch!\n");
		free(buf);
		return KD_E_MALFORMED;
	}

	if (pkt.leader == KD_PACKET_DATA) {
		if (desc->iob->type == KD_IO_PIPE) {
			ut8 trailer;
			iob_read(desc, (ut8 *)&trailer, 1);

			if (trailer != 0xAA) {
				KD_DBG eprintf("Missing trailer 0xAA\n");
				free(buf);
				return KD_E_MALFORMED;
			}
		}
	}
	kd_send_ctrl_packet(desc, KD_PACKET_TYPE_ACKNOWLEDGE, pkt.id);

	*p = (kd_packet_t *)buf;

	return KD_E_OK;
}

bool kd_packet_is_valid(const kd_packet_t *p) {
	return p->leader == KD_PACKET_CTRL || p->leader == KD_PACKET_DATA || p->leader == KD_PACKET_UNUSED;
}

int kd_packet_is_ack(const kd_packet_t *p) {
	return p->leader == KD_PACKET_CTRL && p->type == KD_PACKET_TYPE_ACKNOWLEDGE;
}
