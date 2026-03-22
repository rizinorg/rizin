// SPDX-FileCopyrightText: 2026 Abdallh <abdallhdawi3@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "core_private.h"
#include <rz_core.h>
#include <rz_heap_uclibc.h>

/**
 \brief Read a uClibc heap_free_area struct from memory at addr.
 \param core RzCore instance
 \param addr address to read from
 \param out pointer to store the result
 \return true on success, false on failure
*/

static bool uclibc_read_free_area(RzCore *core, ut64 addr, RzHeapFreeAreaUClibc *out){
    rz_return_val_if_fail(core && out, false);
    ut8 bits = (ut8)core->rasm->bits;
    int ptr_size = bits / 8;
    // struct layout -> size, next, prev - all pointer sized
    int struct_size = 3 * ptr_size;
    ut8 buf[24] = {0};

    if(!rz_io_read_at_mapped(core->io, addr, buf, struct_size)){
        RZ_LOG_ERROR("Error, Failed to read heap_free_area at 0x%" PFMT64x "\n", addr);
        return false;
    }

    if(bits == 64){
        out->size = rz_read_le64(buf);
        out->next = rz_read_le64(buf + 8);
        out->prev = rz_read_le64(buf + 16);
    } else {
        out->prev = rz_read_le32(buf);
        out->prev = rz_read_le32(buf + 4);
        out->prev = rz_read_le32(buf + 8);
    }
    return true;
}

/**
 \brief Print uClibc heap free list starting at addr.
 Walks the doubly-linked free list and prints each chunk.
*/
RZ_IPI RzCmdStatus rz_heap_uclibc_print_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core, RZ_CMD_STATUS_ERROR);

	ut64 addr = argc > 1 ? rz_num_math(core->num, argv[1]) : core->offset;
	ut64 start = addr;
	int count = 0;
    
	int max_chunks = 1024; // no infinite loop on corrupt heap

    rz_cons_println("uClibc Heap Free List:");
	rz_cons_println("Addr               Size               Next               Prev");
	rz_cons_println("----------------------------------------------------------------");

	do {
		RzHeapFreeAreaUClibc chunk = {0};
		if (!uclibc_read_free_area(core, addr, &chunk)) {
			break;
		}
		rz_cons_printf("0x%016" PFMT64x "  0x%016" PFMT64x "  0x%016" PFMT64x
			       "  0x%016" PFMT64x "\n",
			addr, chunk.size, chunk.next, chunk.prev);
		if (chunk.next == 0 || chunk.next == start) {
			break; // end of list or circular
		}
		addr = chunk.next;
		count++;
	} while (count < max_chunks);

	rz_cons_printf("\nTotal free chunks: %d\n", count + 1);
	return RZ_CMD_STATUS_OK;
}
