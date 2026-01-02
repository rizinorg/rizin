// SPDX-FileCopyrightText: 2014-2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <errno.h>

#include <rz_crypto.h>
#include <rz_hash.h>
#include <rz_socket.h>
#include <rz_util.h>

#include "kd.h"
#include "transport.h"

#define BUF_SIZE 4096

typedef struct iobnet_t {
	RzSocket *sock;
	bool hasDatakey;

	// Internal write buffer
	ut8 write_buf[BUF_SIZE];
	ut32 write_off;
	int write_size;
	// Internal read buffer
	ut8 read_buf[BUF_SIZE];
	ut32 read_off;
	int read_size;

	// AES-256 Control Key for enc/decrypting KDNet packets of type KDNET_PACKET_TYPE_CONTROL
	ut8 key[32];
	// AES-256 Data Key for enc/decrypting KDNet packets of type KDNET_PACKET_TYPE_DATA
	ut8 datakey[32];
	// HMAC Key
	ut8 hmackey[KDNET_HMACKEY_SIZE];
	// Lock that protects the above key fields
	RzThreadLock *key_lock;
	// KDNet Protocol version of the debuggee
	ut8 version;
	RzHash *hash;
	RzCrypto *crypto;
} iobnet_t;

/*
 * \brief Initialize the key for enc/decrypting KDNet packet with the type Data.
 *
 * \param resbuf, the buffer that contains the KDNet Data of a Response packet.
 */
static bool _initializeDatakey(iobnet_t *obj, ut8 *resbuf, int size) {
	RzHashSize digest_size = 0;
	const ut8 *digest = NULL;
	RzHashCfg *md = rz_hash_cfg_new_with_algo2(obj->hash, "sha256");
	if (!md) {
		return false;
	}

	if (!rz_hash_cfg_update(md, obj->key, 32) ||
		!rz_hash_cfg_update(md, resbuf, size) ||
		!rz_hash_cfg_final(md) ||
		!(digest = rz_hash_cfg_get_result(md, "sha256", &digest_size))) {

		rz_hash_cfg_free(md);
		return false;
	}

	memcpy(obj->datakey, digest, digest_size);
	rz_hash_cfg_free(md);

	return true;
}

static void *iob_net_open(const char *path) {
	size_t i;

	iobnet_t *obj = RZ_NEW0(iobnet_t);
	if (!obj) {
		return NULL;
	}
	obj->hash = rz_hash_new();
	obj->crypto = rz_crypto_new();
	obj->key_lock = rz_th_lock_new(false);
	if (!obj->key_lock) {
		free(obj);
		return NULL;
	}

	char *host = strdup(path);
	char *port = strchr(host, ':');
	if (RZ_STR_ISEMPTY(port)) {
		free(host);
		free(obj);
		return NULL;
	}
	*port++ = 0;
	char *key = strchr(port, ':');
	if (RZ_STR_ISEMPTY(key)) {
		free(host);
		free(obj);
		return NULL;
	}
	*key++ = 0;

	// Decode AES-256 Control Key (x.x.x.x) from base36
	char *nkey;
	for (i = 0; i < 4 && key; key = nkey, i++) {
		nkey = strchr(key, '.');
		if (nkey) {
			*nkey++ = 0;
		}

		ut64 decoded_val = 0;
		st64 ret = rz_base36_decode(&decoded_val, key, strlen(key));
		decoded_val = ret >= 0 ? decoded_val : 0;
		rz_write_le64(obj->key + i * 8, (ut64)decoded_val);
	}

	// HMAC Key is the negation of AES-256 Control Key bytes
	for (i = 0; i < 32; i++) {
		obj->hmackey[i] = ~(obj->key[i]);
	}

	RzSocket *sock = rz_socket_new(0);
	if (!rz_socket_connect_udp(sock, host, port, 1)) {
		free(host);
		free(obj);
		return NULL;
	}
	obj->sock = sock;

	free(host);
	return (void *)obj;
}

static bool iob_net_close(void *p) {
	int ret = true;
	iobnet_t *obj = (iobnet_t *)p;

	if (rz_socket_close(obj->sock)) {
		ret = false;
	}

	rz_socket_free(obj->sock);
	rz_hash_free(obj->hash);
	rz_crypto_free(obj->crypto);
	free(obj);
	return ret;
}

static bool _encrypt(iobnet_t *obj, ut8 *buf, int size, int type) {
	bool ret = false;
	rz_crypto_reset(obj->crypto);
	if (!rz_crypto_use(obj->crypto, "aes-cbc")) {
		goto end;
	}

	// Set AES-256 Key based on the KDNet packet type
	switch (type) {
	case KDNET_PACKET_TYPE_DATA:
		if (!rz_crypto_set_key(obj->crypto, obj->datakey, sizeof(obj->datakey), 0, 0)) {
			goto end;
		}
		break;
	case KDNET_PACKET_TYPE_CONTROL: // Control Channel
		if (!rz_crypto_set_key(obj->crypto, obj->key, sizeof(obj->key), 0, 0)) {
			goto end;
		}
		break;
	default:
		goto end;
	}

	// Set IV to the 16 bytes HMAC at the end of KDNet packet
	if (!rz_crypto_set_iv(obj->crypto, buf + size - KDNET_HMAC_SIZE, KDNET_HMAC_SIZE)) {
		goto end;
	}

	// Encrypt the buffer except HMAC
	if (rz_crypto_final(obj->crypto, buf, size - KDNET_HMAC_SIZE) == 0) {
		goto end;
	}
	// Overwrite the buffer with encrypted data
	int sz;
	const ut8 *encbuf = rz_crypto_get_output(obj->crypto, &sz);
	if (!encbuf) {
		goto end;
	}
	memcpy(buf, encbuf, size - KDNET_HMAC_SIZE);

	ret = true;
end:
	return ret;
}

/*
 * KDNet packet format:
 * - KDNet Header, struct kdnet_packet_t
 * - KDNet Data, 8 bytes (seqno (7 bytes) | direction (4 bits) | padsize (4 bits))
 * - KD packet (16-byte aligned)
 * - KDNet HMAC, HMAC generated with the decrypted KDNet Data and KD Packet.
 *
 * The KDNet Data and KD packet are encrypted together with key based on
 * the packet type in KDNet Header.
 */
static ut8 *_createKDNetPacket(iobnet_t *obj, const ut8 *buf, int size, int *osize, ut64 seqno, ut8 type) {
	// Calculate the pad size for KD packet.
	// The KD packet is 16-byte aligned in KDNet.
	ut8 padsize = -(size + 8) & 0x0F;

	int encsize = sizeof(kdnet_packet_t) + KDNET_DATA_SIZE + size + padsize + KDNET_HMAC_SIZE;
	ut8 *encbuf = calloc(1, encsize);
	if (!encbuf) {
		return NULL;
	}

	// Write KDNet Header
	rz_write_at_be32(encbuf, KDNET_MAGIC, 0); // Magic
	rz_write_at_be8(encbuf, obj->version, 4); // Protocol Number
	rz_write_at_be8(encbuf, type, 5); // Channel Type
	// Write KDNet Data (8 bytes)
	// seqno (7 bytes) | direction (4 bits) | padsize (4 bits)
	// seqno - sequence number
	// direction - 0x0 Debuggee -> Debugger, 0x8 Debugger -> Debuggee
	rz_write_at_be64(encbuf, ((seqno << 8) | 0x8 << 4 | padsize), 6);

	// Copy KD Packet from buffer
	memcpy(encbuf + sizeof(kdnet_packet_t) + KDNET_DATA_SIZE, buf, size);

	// Generate HMAC from KDNet Data to KD packet
	int off = sizeof(kdnet_packet_t) + KDNET_DATA_SIZE + size + padsize;

	const ut8 *digest = NULL;
	RzHashCfg *md = rz_hash_cfg_new_with_algo(obj->hash, "sha256", obj->hmackey, KDNET_HMACKEY_SIZE);
	if (!md) {
		free(encbuf);
		return NULL;
	}

	if (!rz_hash_cfg_update(md, encbuf, off) ||
		!rz_hash_cfg_final(md) ||
		!(digest = rz_hash_cfg_get_result(md, "sha256", NULL))) {
		free(encbuf);
		rz_hash_cfg_free(md);
		return NULL;
	}

	memcpy(encbuf + off, digest, KDNET_HMAC_SIZE);
	rz_hash_cfg_free(md);

	// Encrypt the KDNet Data, KD Packet and padding
	if (!_encrypt(obj, encbuf + sizeof(kdnet_packet_t), encsize - sizeof(kdnet_packet_t), type)) {
		free(encbuf);
		return NULL;
	}

	if (osize) {
		*osize = encsize;
	}
	return encbuf;
}

static bool _decrypt(iobnet_t *obj, ut8 *buf, int size, int type) {
	bool ret = false;
	rz_crypto_reset(obj->crypto);
	if (!rz_crypto_use(obj->crypto, "aes-cbc")) {
		goto end;
	}

	// Set AES-256 Key based on the KDNet packet type
	switch (type) {
	case KDNET_PACKET_TYPE_DATA:
		if (!rz_crypto_set_key(obj->crypto, obj->datakey, sizeof(obj->datakey), 0, 1)) {
			goto end;
		}
		break;
	case KDNET_PACKET_TYPE_CONTROL:
		if (!rz_crypto_set_key(obj->crypto, obj->key, sizeof(obj->key), 0, 1)) {
			goto end;
		}
		break;
	default:
		goto end;
	}

	// Set IV to the 16 bytes HMAC at the end of KDNet packet
	if (!rz_crypto_set_iv(obj->crypto, buf + size - KDNET_HMAC_SIZE, KDNET_HMAC_SIZE)) {
		goto end;
	}

	// Decrypt the buffer except HMAC
	if (rz_crypto_final(obj->crypto, buf, size - KDNET_HMAC_SIZE) == 0) {
		goto end;
	}
	// Overwrite it with decrypted data
	int sz;
	const ut8 *decbuf = rz_crypto_get_output(obj->crypto, &sz);
	if (!decbuf) {
		goto end;
	}
	memcpy(buf, decbuf, size - KDNET_HMAC_SIZE);
	ret = true;

end:
	return ret;
}

/*
 * \brief Respond to the Poke packet with a Response packet
 *
 * \param pokedata, the buffer than contains the KDNet Data of a Poke packet
 */
static bool _sendResponsePacket(iobnet_t *obj, const ut8 *pokedata) {
	size_t i;
	int size;

	// Create the following buffer as the KD packet in the KDNet Response packet:
	// 0x01
	// 0x02
	// 32 bytes of Client Key from the first 32 bytes data of the Poke packet,
	// 32 bytes of Randomly generated Host Key,
	// 256 bytes of zeroes
	ut8 *resbuf = calloc(1, 322);
	if (!resbuf) {
		return false;
	}
	// 0x01 0x02
	resbuf[0] = 0x01;
	resbuf[1] = 0x02;
	// Copy 32 bytes Client Key after the KDNet Data
	memcpy(resbuf + 2, pokedata + 10, 32);
	// Generate 32 bytes random Host Key
	for (i = 0; i < 32; i++) {
		int rand = rz_num_rand32(0xFF);
		resbuf[i + 34] = rand & 0xFF;
	}

	// Set seqno to the same seqno in Poke packet
	ut64 seqno = rz_read_be64(pokedata) >> 8;
	ut8 *pkt = _createKDNetPacket(obj, resbuf, 322, &size, seqno, 1);
	if (!pkt) {
		free(resbuf);
		return false;
	}
	rz_th_lock_enter(obj->key_lock);
	if (rz_socket_write(obj->sock, (void *)pkt, size) < 0) {
		free(pkt);
		free(resbuf);
		return false;
	}

	_initializeDatakey(obj, resbuf, 322);
	obj->hasDatakey = true;
	rz_th_lock_leave(obj->key_lock);

	free(pkt);
	free(resbuf);
	return true;
}

static bool _processControlPacket(iobnet_t *obj, const ut8 *ctrlbuf, int size) {
	if (obj->hasDatakey) {
		return true;
	}
	// Read KDNet Data to verify direction flag
	ut64 kdnetdata = rz_read_be64(ctrlbuf);
	if ((kdnetdata & 0x80) != 0) {
		eprintf("Error: KdNet wrong direction flag\n");
		return false;
	}

	// Respond to the control packet
	if (!_sendResponsePacket(obj, ctrlbuf)) {
		eprintf("Error: KdNet sending the response packet\n");
		return false;
	}

	return true;
}

bool _verifyhmac(iobnet_t *obj) {
	const ut8 *digest = NULL;
	RzHashCfg *md = rz_hash_cfg_new_with_algo(obj->hash, "sha256", obj->hmackey, KDNET_HMACKEY_SIZE);
	if (!md) {
		return false;
	}

	if (!rz_hash_cfg_update(md, obj->read_buf, obj->read_size - KDNET_HMAC_SIZE) ||
		!rz_hash_cfg_final(md) ||
		!(digest = rz_hash_cfg_get_result(md, "sha256", NULL))) {
		rz_hash_cfg_free(md);
		return false;
	}

	bool result = !memcmp(digest, obj->read_buf + obj->read_size - KDNET_HMAC_SIZE, KDNET_HMAC_SIZE);
	rz_hash_cfg_free(md);

	return result;
}

static int iob_net_read(void *p, uint8_t *obuf, const uint64_t count, const int timeout) {
	kdnet_packet_t pkt = { 0 };
	iobnet_t *obj = (iobnet_t *)p;

	if (obj->read_size == 0) {
		do {
			obj->read_size = rz_socket_read(obj->sock, obj->read_buf, BUF_SIZE);
			if (obj->read_size < sizeof(kdnet_packet_t) + KDNET_HMAC_SIZE) {
				// Continue if RzCons breaks
				if (errno == EINTR) {
					continue;
				}
				goto fail;
			}
			memcpy(&pkt, obj->read_buf, sizeof(kdnet_packet_t));

			// Verify the KDNet Header magic
			if (rz_read_be32(obj->read_buf) != KDNET_MAGIC) {
				eprintf("Error: KdNet bad magic\n");
				goto fail;
			}

			// Decrypt the KDNet Data and KD Packet
			if (!_decrypt(obj, obj->read_buf + sizeof(kdnet_packet_t), obj->read_size - sizeof(kdnet_packet_t), pkt.type)) {
				goto fail;
			}

			// Verify the KDNet HMAC
			if (!_verifyhmac(obj)) {
				eprintf("Error: KdNet failed authentication\n");
				goto fail;
			}

			// Process KDNet Control Packets
			if (pkt.type == KDNET_PACKET_TYPE_CONTROL) {
				obj->version = pkt.version;
				if (!_processControlPacket(obj, obj->read_buf + sizeof(kdnet_packet_t), obj->read_size)) {
					eprintf("Error: KdNet failed to process Control packet\n");
					goto fail;
				};
				obj->read_size = 0;
			}
		} while (pkt.type == KDNET_PACKET_TYPE_CONTROL);

		// Remove padding from the buffer
		ut8 padsize = rz_read_at_be64(obj->read_buf, sizeof(kdnet_packet_t)) & 0xF;
		obj->read_size -= KDNET_HMAC_SIZE + padsize;

		// Seek to KD packet
		obj->read_off = sizeof(kdnet_packet_t) + KDNET_DATA_SIZE;

		// KD_PACKET_TYPE_UNUSED KD packet does not have a checksum,
		// but kd_read_packet always read for the 4-byte checksum
		if (rz_read_at_be16(obj->read_buf, obj->read_off + 4) == KD_PACKET_TYPE_UNUSED) {
			obj->read_size += 4;
		}
	}

	if (count + obj->read_off > obj->read_size) {
		eprintf("Error: KdNet out-of-bounds read\n");
		goto fail;
	}

	// Copy remaining data in buffer
	size_t c = RZ_MIN(count, obj->read_size - obj->read_off);
	memcpy(obuf, obj->read_buf + obj->read_off, c);
	obj->read_off += c;

	// Reset the internal buffer when finished
	if (obj->read_off == obj->read_size) {
		obj->read_size = 0;
	}

	return count;
fail:
	obj->read_size = 0;
	return -1;
}

static int iob_net_write(void *p, const uint8_t *buf, const uint64_t count, const int timeout) {
	static ut64 seqno = 1;
	iobnet_t *obj = (iobnet_t *)p;
	if (obj->write_size == 0) {
		// kd_packet_t
		if (count == sizeof(kd_packet_t)) {
			kd_packet_t pkt;
			memcpy(&pkt, buf, sizeof(kd_packet_t));

			obj->write_size = sizeof(kd_packet_t) + pkt.length;
			obj->write_off = count;
			memcpy(obj->write_buf, buf, count);
		} else { // breakin packet "b"
			memcpy(obj->write_buf, buf, count);
			obj->write_size = count;
			obj->write_off = count;
		}
	} else {
		memcpy(obj->write_buf + obj->write_off, buf, count);
		obj->write_off += count;
	}

	if (obj->write_off == obj->write_size) {
		int size;
		rz_th_lock_enter(obj->key_lock);
		ut8 *pkt = _createKDNetPacket(obj, obj->write_buf, obj->write_size, &size, seqno, 0);
		if (!pkt) {
			rz_th_lock_leave(obj->key_lock);
			return -1;
		}
		if (rz_socket_write(obj->sock, (void *)pkt, size) < 0) {
			free(pkt);
			rz_th_lock_leave(obj->key_lock);
			return -1;
		}
		rz_th_lock_leave(obj->key_lock);
		seqno++;

		obj->write_size = 0;
		free(pkt);
	}

	return count;
}

io_backend_t iob_net = {
	.name = "kdnet",
	.type = KD_IO_NET,
	.init = NULL,
	.deinit = NULL,
	.config = NULL,
	.open = &iob_net_open,
	.close = &iob_net_close,
	.read = &iob_net_read,
	.write = &iob_net_write,
};
