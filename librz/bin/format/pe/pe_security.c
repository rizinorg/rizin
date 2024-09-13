// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"
#include <rz_hash.h>

static const char *PE_(bin_pe_get_claimed_authentihash)(RzBinPEObj *bin) {
	if (!bin->spcinfo) {
		return NULL;
	}
	RzASN1Binary *digest = bin->spcinfo->messageDigest.digest;
	if (!digest) {
		return NULL;
	}
	return rz_hex_bin2strdup(digest->binary, digest->length);
}

static ut64 buf_fwd_hash(const ut8 *buf, ut64 size, void *user) {
	return rz_hash_cfg_update((RzHashCfg *)user, buf, size) ? size : 0;
}

char *PE_(bin_pe_compute_authentihash)(RzBinPEObj *bin) {
	if (!bin->spcinfo || !bin->spcinfo->messageDigest.digestAlgorithm.algorithm) {
		return NULL;
	}

	char *hashtype = rz_str_dup(bin->spcinfo->messageDigest.digestAlgorithm.algorithm->string);
	rz_str_replace_char(hashtype, '-', 0);

	RzHashCfg *md = rz_hash_cfg_new_with_algo2(bin->hash, hashtype);
	if (!md) {
		free(hashtype);
		return NULL;
	}
	ut32 checksum_paddr = bin->nt_header_offset + 4 + sizeof(PE_(image_file_header)) + 0x40;
	ut32 security_entry_offset = bin->nt_header_offset + sizeof(PE_(image_nt_headers)) - 96;
	PE_(image_data_directory) *data_dir_security = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_SECURITY];
	PE_DWord security_dir_offset = data_dir_security->VirtualAddress;
	ut32 security_dir_size = data_dir_security->Size;
	rz_buf_fwd_scan(bin->b, 0, checksum_paddr, buf_fwd_hash, md);
	rz_buf_fwd_scan(bin->b, checksum_paddr + 4, security_entry_offset - checksum_paddr - 4, buf_fwd_hash, md);
	rz_buf_fwd_scan(bin->b, security_entry_offset + 8, security_dir_offset - security_entry_offset - 8, buf_fwd_hash, md);
	rz_buf_fwd_scan(bin->b, security_dir_offset + security_dir_size, rz_buf_size(bin->b) - security_dir_offset - security_dir_size, buf_fwd_hash, md);

	RzHashSize digest_size = 0;
	const ut8 *digest = NULL;
	if (!rz_hash_cfg_final(md) ||
		!(digest = rz_hash_cfg_get_result(md, hashtype, &digest_size))) {

		free(hashtype);
		rz_hash_cfg_free(md);
		return NULL;
	}

	char *hashstr = rz_hex_bin2strdup(digest, digest_size);
	free(hashtype);
	rz_hash_cfg_free(md);
	return hashstr;
}

const char *PE_(bin_pe_get_authentihash)(RzBinPEObj *bin) {
	if (!bin->authentihash) {
		bin->authentihash = PE_(bin_pe_compute_authentihash)(bin);
	}
	return bin->authentihash;
}

int PE_(bin_pe_is_authhash_valid)(RzBinPEObj *bin) {
	return bin->is_authhash_valid;
}

int PE_(bin_pe_init_security)(RzBinPEObj *bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	if (bin->nt_headers->optional_header.NumberOfRvaAndSizes < 5) {
		return false;
	}
	PE_(image_data_directory) *data_dir_security = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_SECURITY];
	PE_DWord paddr = data_dir_security->VirtualAddress;
	ut32 size = data_dir_security->Size;
	if (size < 8 || paddr > bin->size || paddr + size > bin->size) {
		RZ_LOG_INFO("Invalid certificate table\n");
		return false;
	}

	Pe_image_security_directory *security_directory = RZ_NEW0(Pe_image_security_directory);
	if (!security_directory) {
		return false;
	}
	bin->security_directory = security_directory;

	PE_DWord offset = paddr;
	while (offset < paddr + size) {
		Pe_certificate **tmp = (Pe_certificate **)realloc(security_directory->certificates, (security_directory->length + 1) * sizeof(Pe_certificate *));
		if (!tmp) {
			return false;
		}
		security_directory->certificates = tmp;
		Pe_certificate *cert = RZ_NEW0(Pe_certificate);
		if (!cert) {
			return false;
		}
		if (!rz_buf_read_le32_at(bin->b, offset, &cert->dwLength)) {
			RZ_FREE(cert);
			return false;
		}
		cert->dwLength += (8 - (cert->dwLength & 7)) & 7; // align32
		if (offset + cert->dwLength > paddr + size) {
			RZ_LOG_INFO("Invalid certificate entry\n");
			RZ_FREE(cert);
			return false;
		}
		if (!rz_buf_read_le16_at(bin->b, offset + 4, &cert->wRevision)) {
			RZ_FREE(cert);
			return false;
		}
		if (!rz_buf_read_le16_at(bin->b, offset + 6, &cert->wCertificateType)) {
			RZ_FREE(cert);
			return false;
		}
		if (cert->dwLength < 6) {
			RZ_LOG_ERROR("Invalid cert.dwLength (must be > 6)\n");
			RZ_FREE(cert);
			return false;
		}
		if (!(cert->bCertificate = malloc(cert->dwLength - 6))) {
			RZ_FREE(cert);
			return false;
		}
		rz_buf_read_at(bin->b, offset + 8, cert->bCertificate, cert->dwLength - 6);

		if (!bin->cms && cert->wCertificateType == PE_WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
			bin->cms = rz_pkcs7_cms_parse(cert->bCertificate, cert->dwLength - 6);
			bin->spcinfo = bin->cms ? rz_pkcs7_spcinfo_parse(bin->cms) : NULL;
		}
		if (!bin->cms || !bin->spcinfo) {
			RZ_FREE(cert->bCertificate);
			RZ_FREE(cert);
			return false;
		}

		security_directory->certificates[security_directory->length] = cert;
		security_directory->length++;
		offset += cert->dwLength;
	}

	if (bin->cms && bin->spcinfo) {
		const char *actual_authentihash = PE_(bin_pe_get_authentihash)(bin);
		const char *claimed_authentihash = PE_(bin_pe_get_claimed_authentihash)(bin);
		if (actual_authentihash && claimed_authentihash) {
			bin->is_authhash_valid = !strcmp(actual_authentihash, claimed_authentihash);
		} else {
			bin->is_authhash_valid = false;
		}
		free((void *)claimed_authentihash);
	}
	bin->is_signed = bin->cms != NULL;
	return true;
}

void PE_(free_security_directory)(Pe_image_security_directory *security_directory) {
	if (!security_directory) {
		return;
	}
	size_t numCert = 0;
	for (; numCert < security_directory->length; numCert++) {
		free(security_directory->certificates[numCert]);
	}
	free(security_directory->certificates);
	free(security_directory);
}
