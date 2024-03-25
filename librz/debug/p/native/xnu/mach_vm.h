// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Like <mach/mach_vm.h> but with a fallback to a manual definition for iOS
 */

#ifndef RZ_MACH_VM_H
#define RZ_MACH_VM_H

#include <rz_types.h>

#if TARGET_OS_IPHONE
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_inherit(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_inherit_t new_inheritance);
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *data_cnt);
kern_return_t mach_vm_read_list(vm_map_t target_task, mach_vm_read_entry_t data_list, natural_t count);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t data_cnt);
kern_return_t mach_vm_copy(vm_map_t target_task, mach_vm_address_t source_address, mach_vm_size_t size, mach_vm_address_t dest_address);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data,
	mach_vm_size_t *outsize);
kern_return_t mach_vm_msync(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_sync_t sync_flags);
kern_return_t mach_vm_behavior_set(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_behavior_t new_behavior);
kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags,
	mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection,
	vm_inherit_t inheritance);
kern_return_t mach_vm_machine_attribute(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_machine_attribute_t attribute,
	vm_machine_attribute_val_t *value);
kern_return_t mach_vm_remap(vm_map_t target_task, mach_vm_address_t *target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags,
	vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection,
	vm_inherit_t inheritance);
kern_return_t mach_vm_page_query(vm_map_t target_map, mach_vm_offset_t offset, integer_t *disposition, integer_t *ref_count);
kern_return_t mach_vm_region_recurse(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth,
	vm_region_recurse_info_t info, mach_msg_type_number_t *info_cnt);
kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor,
	vm_region_info_t info, mach_msg_type_number_t *info_cnt, mach_port_t *object_name);
kern_return_t _mach_make_memory_entry(vm_map_t target_task, memory_object_size_t *size, memory_object_offset_t offset, vm_prot_t permission,
	mem_entry_name_port_t *object_handle, mem_entry_name_port_t parent_handle);
kern_return_t mach_vm_purgable_control(vm_map_t target_task, mach_vm_address_t address, vm_purgable_t control, int *state);
kern_return_t mach_vm_page_info(vm_map_t target_task, mach_vm_address_t address, vm_page_info_flavor_t flavor, vm_page_info_t info,
	mach_msg_type_number_t *info_cnt);
kern_return_t mach_vm_page_range_query(vm_map_t target_map, mach_vm_offset_t address, mach_vm_size_t size, mach_vm_address_t dispositions,
	mach_vm_size_t *dispositions_count);
#else
#include <mach/mach_vm.h>
#endif

#endif
