
static bool DebugAddr_get_address(RzBinDwarfDebugAddr *self, ut64 address,
	ut8 address_size, bool big_endian, ut64 base, ut64 index) {
	RzBuffer *buffer = rz_buf_new_with_buf(self->buffer);
	RET_FALSE_IF_FAIL(buffer);
	rz_buf_seek(buffer, (st64)base, RZ_BUF_CUR);
	rz_buf_seek(buffer, (st64)(index * address_size), RZ_BUF_CUR);
	UX_OR_RET_FALSE(address, address_size);
	return true;
}
