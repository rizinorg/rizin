// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

static bool tls_va_to_rva(RzBinPEObj *bin, PE_DWord va, PE_DWord *rva_out) {
	PE_DWord rva = PE_(bin_pe_va_to_rva)(bin, va);
	if (bin->optional_header->SizeOfImage) {
		PE_DWord image_base = PE_(rz_bin_pe_get_image_base)(bin);
		if (va < image_base || rva >= bin->optional_header->SizeOfImage) {
			return false;
		}
	}
	*rva_out = rva;
	return true;
}

static void bin_pe_store_tls_callbacks(RzBinPEObj *bin, PE_DWord callbacks) {
	PE_DWord paddr, haddr;
	int count = 0;
	PE_DWord addressOfTLSCallback = 1;
	char *key;
	char tmpbuf[64];

	while (addressOfTLSCallback != 0) {
		if (!RZ_BUF_READ_PE_DWORD_AT(bin->b, callbacks, &addressOfTLSCallback)) {
			RZ_LOG_INFO("read (tls_callback)\n");
			return;
		}
		if (!addressOfTLSCallback) {
			break;
		}
		PE_DWord rva_callback = 0;
		if (!tls_va_to_rva(bin, addressOfTLSCallback, &rva_callback)) {
			break;
		}
		key = rz_strf(tmpbuf, "pe.tls_callback%d_vaddr", count);
		sdb_num_set(bin->kv, key, addressOfTLSCallback);
		key = rz_strf(tmpbuf, "pe.tls_callback%d_paddr", count);
		paddr = PE_(bin_pe_rva_to_paddr)(bin, rva_callback);
		sdb_num_set(bin->kv, key, paddr);
		key = rz_strf(tmpbuf, "pe.tls_callback%d_haddr", count);
		haddr = callbacks;
		sdb_num_set(bin->kv, key, haddr);
		count++;
		callbacks += sizeof(addressOfTLSCallback);
	}
}

static bool read_tls_directory_aux(RzBuffer *b, PE_(image_tls_directory) * tls_directory) {
	return RZ_BUF_READ_PE_DWORD(b, &tls_directory->StartAddressOfRawData) &&
		RZ_BUF_READ_PE_DWORD(b, &tls_directory->EndAddressOfRawData) &&
		RZ_BUF_READ_PE_DWORD(b, &tls_directory->AddressOfIndex) &&
		RZ_BUF_READ_PE_DWORD(b, &tls_directory->AddressOfCallBacks) &&
		rz_buf_read_le32(b, &tls_directory->SizeOfZeroFill) &&
		rz_buf_read_le32(b, &tls_directory->Characteristics);
}

static int read_tls_directory(RzBuffer *b, ut64 addr, PE_(image_tls_directory) * tls_directory) {
	st64 tmp = rz_buf_tell(b);
	if (tmp < 0) {
		return -1;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}

	if (!read_tls_directory_aux(b, tls_directory)) {
		return -1;
	}

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return -1;
	}

	return sizeof(PE_(image_tls_directory));
}

int PE_(bin_pe_init_tls)(RzBinPEObj *bin) {
	PE_(image_tls_directory) * image_tls_directory;
	PE_(image_data_directory) *data_dir_tls = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_TLS];
	if (!data_dir_tls->VirtualAddress) {
		return 0;
	}
	PE_DWord tls_paddr = PE_(bin_pe_rva_to_paddr)(bin, data_dir_tls->VirtualAddress);

	image_tls_directory = RZ_NEW0(PE_(image_tls_directory));
	if (read_tls_directory(bin->b, tls_paddr, image_tls_directory) < 0) {
		RZ_LOG_INFO("read (image_tls_directory)\n");
		free(image_tls_directory);
		return 0;
	}
	bin->tls_directory = image_tls_directory;
	if (!image_tls_directory->AddressOfCallBacks) {
		return 0;
	}
	if (image_tls_directory->EndAddressOfRawData < image_tls_directory->StartAddressOfRawData) {
		return 0;
	}
	PE_DWord callbacks_rva = 0;
	if (tls_va_to_rva(bin, image_tls_directory->AddressOfCallBacks, &callbacks_rva)) {
		PE_DWord callbacks_paddr = PE_(bin_pe_rva_to_paddr)(bin, callbacks_rva);
		bin_pe_store_tls_callbacks(bin, callbacks_paddr);
	}
	return 0;
}
