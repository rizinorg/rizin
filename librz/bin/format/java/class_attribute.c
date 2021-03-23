// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "class_attribute.h"

static ut8 *copy_buffer(RzBuffer *buf, st64 size, bool null_terminator) {
	ut8 *buffer;
	if (null_terminator) {
		buffer = (ut8 *)malloc(size + 1);
	} else {
		buffer = (ut8 *)malloc(size);
	}
	if (!buffer || rz_buf_read(buf, buffer, size) < (size - 1)) {
		rz_warn_if_reached();
		free(buffer);
		return NULL;
	}
	if (null_terminator) {
		buffer[size] = 0;
	}
	return buffer;
}

static char *resolve_const_pool_index(ConstPool **pool, ut32 poolsize, ut32 index) {
	const ConstPool *cpool;
	if (index >= poolsize || !(cpool = pool[index])) {
		return NULL;
	}
	return java_constant_pool_stringify(cpool);
}

bool java_attribute_set_unknown(Attribute *attr, RzBuffer *buf) {
	attr->type = ATTRIBUTE_TYPE_UNKNOWN;
	if (attr->attribute_length < 1) {
		return true;
	}
	st64 size = (st64)attr->attribute_length;
	attr->info = copy_buffer(buf, size, false);
	return true;
}

bool java_attribute_set_constantvalue(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length == 2);
	AttributeConstantValue *acv = RZ_NEW0(AttributeConstantValue);
	if (!acv) {
		rz_warn_if_reached();
		return false;
	}
	acv->index = rz_buf_read_be16(buf);
	attr->type = ATTRIBUTE_TYPE_CONSTANTVALUE;
	attr->info = (void *)acv;
	return true;
}

bool java_attribute_set_code(ConstPool **pool, ut32 poolsize, Attribute *attr, RzBuffer *buf, bool is_oak) {
	AttributeCode *ac = RZ_NEW0(AttributeCode);
	if (!ac) {
		rz_warn_if_reached();
		return false;
	}
	ac->max_stack = is_oak ? rz_buf_read8(buf) : rz_buf_read_be16(buf);
	ac->max_locals = is_oak ? rz_buf_read8(buf) : rz_buf_read_be16(buf);
	ac->code_length = is_oak ? rz_buf_read_be16(buf) : rz_buf_read_be32(buf);
	ac->code_offset = attr->offset + (is_oak ? 10 : 14); // 6 bytes for attribute + 8 as code
	ac->code = copy_buffer(buf, ac->code_length, false);
	if (!ac->code) {
		free(ac);
		rz_warn_if_reached();
		return false;
	}
	ac->exceptions_count = rz_buf_read_be16(buf);
	if (ac->exceptions_count > 0) {
		ac->exceptions = RZ_NEWS0(ExceptionTable, ac->exceptions_count);
		if (!ac->exceptions) {
			free(ac->code);
			free(ac);
			rz_warn_if_reached();
			return false;
		}
		for (ut32 i = 0; i < ac->exceptions_count; ++i) {
			ac->exceptions[i].start_pc = rz_buf_read_be16(buf);
			ac->exceptions[i].end_pc = rz_buf_read_be16(buf);
			ac->exceptions[i].handler_pc = rz_buf_read_be16(buf);
			ac->exceptions[i].catch_type = rz_buf_read_be16(buf);
		}
	}

	ac->attributes_count = rz_buf_read_be16(buf);
	if (ac->attributes_count > 0) {
		ac->attributes = RZ_NEWS0(Attribute *, ac->attributes_count);
		if (!ac->attributes) {
			free(ac->exceptions);
			free(ac->code);
			free(ac);
			rz_warn_if_reached();
			return NULL;
		}

		for (ut32 i = 0; i < ac->attributes_count; ++i) {
			Attribute *attr = java_attribute_new(buf, UT64_MAX);
			if (attr && java_attribute_resolve(pool, poolsize, attr, buf, false)) {
				ac->attributes[i] = attr;
			} else {
				java_attribute_free(attr);
				break;
			}
		}
	}

	attr->type = ATTRIBUTE_TYPE_CODE;
	attr->info = (void *)ac;
	return true;
}

bool java_attribute_set_sourcefile(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length == 2);
	AttributeSourceFile *asf = RZ_NEW0(AttributeSourceFile);
	if (!asf) {
		rz_warn_if_reached();
		return false;
	}
	asf->index = rz_buf_read_be16(buf);
	attr->type = ATTRIBUTE_TYPE_SOURCEFILE;
	attr->info = (void *)asf;
	return true;
}

bool java_attribute_set_sourcedebugextension(Attribute *attr, RzBuffer *buf) {
	attr->type = ATTRIBUTE_TYPE_SOURCEDEBUGEXTENSION;
	if (attr->attribute_length < 1) {
		return true;
	}
	st64 size = (st64)attr->attribute_length;
	attr->info = copy_buffer(buf, size, true);
	if (!attr->info) {
		rz_warn_if_reached();
		return false;
	}
	return true;
}

bool java_attribute_set_linenumbertable(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length >= 2);
	AttributeLineNumberTable *alnt = RZ_NEW0(AttributeLineNumberTable);
	if (!alnt) {
		rz_warn_if_reached();
		return false;
	}
	alnt->table_length = rz_buf_read_be16(buf);
	if (alnt->table_length > 0) {
		alnt->table = RZ_NEWS0(LineNumberTable, alnt->table_length);
		if (!alnt->table) {
			free(alnt);
			rz_warn_if_reached();
			return false;
		}
		for (ut32 i = 0; i < alnt->table_length; ++i) {
			alnt->table[i].start_pc = rz_buf_read_be16(buf);
			alnt->table[i].line_number = rz_buf_read_be16(buf);
		}
	}

	attr->type = ATTRIBUTE_TYPE_LINENUMBERTABLE;
	attr->info = (void *)alnt;
	return true;
}

bool java_attribute_set_localvariabletable(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length >= 2);
	AttributeLocalVariableTable *alvt = RZ_NEW0(AttributeLocalVariableTable);
	if (!alvt) {
		rz_warn_if_reached();
		return false;
	}
	alvt->table_length = rz_buf_read_be16(buf);
	if (alvt->table_length > 0) {
		alvt->table = RZ_NEWS0(LocalVariableTable, alvt->table_length);
		if (!alvt->table) {
			free(alvt);
			rz_warn_if_reached();
			return false;
		}
		for (ut32 i = 0; i < alvt->table_length; ++i) {
			alvt->table[i].start_pc = rz_buf_read_be16(buf);
			alvt->table[i].length = rz_buf_read_be16(buf);
			alvt->table[i].name_index = rz_buf_read_be16(buf);
			alvt->table[i].descriptor_index = rz_buf_read_be16(buf);
			alvt->table[i].index = rz_buf_read_be16(buf);
		}
	}

	attr->type = ATTRIBUTE_TYPE_LOCALVARIABLETABLE;
	attr->info = (void *)alvt;
	return true;
}

bool java_attribute_set_localvariabletypetable(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length >= 2);
	AttributeLocalVariableTypeTable *alvtt = RZ_NEW0(AttributeLocalVariableTypeTable);
	if (!alvtt) {
		rz_warn_if_reached();
		return false;
	}
	alvtt->table_length = rz_buf_read_be16(buf);
	if (alvtt->table_length > 0) {
		alvtt->table = RZ_NEWS0(LocalVariableTypeTable, alvtt->table_length);
		if (!alvtt->table) {
			free(alvtt);
			rz_warn_if_reached();
			return false;
		}
		for (ut32 i = 0; i < alvtt->table_length; ++i) {
			alvtt->table[i].start_pc = rz_buf_read_be16(buf);
			alvtt->table[i].length = rz_buf_read_be16(buf);
			alvtt->table[i].name_index = rz_buf_read_be16(buf);
			alvtt->table[i].signature_index = rz_buf_read_be16(buf);
			alvtt->table[i].index = rz_buf_read_be16(buf);
		}
	}

	attr->type = ATTRIBUTE_TYPE_LOCALVARIABLETYPETABLE;
	attr->info = (void *)alvtt;
	return true;
}

bool java_attribute_set_module(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length >= 16);
	AttributeModule *am = RZ_NEW0(AttributeModule);
	if (!am) {
		rz_warn_if_reached();
		return false;
	}
	ut16 *tmp16 = NULL;
	am->module_name_index = rz_buf_read_be16(buf);
	am->module_flags = rz_buf_read_be16(buf);
	am->module_version_index = rz_buf_read_be16(buf);

	am->requires_count = rz_buf_read_be16(buf);
	if (am->requires_count > 0) {
		am->requires = RZ_NEWS0(ModuleRequire, am->requires_count);
		if (!am->requires) {
			goto java_attribute_set_module_bad;
		}
		for (ut32 i = 0; i < am->requires_count; ++i) {
			am->requires[i].index = rz_buf_read_be16(buf);
			am->requires[i].flags = rz_buf_read_be16(buf);
			am->requires[i].version_index = rz_buf_read_be16(buf);
		}
	}

	am->exports_count = rz_buf_read_be16(buf);
	if (am->exports_count > 0) {
		am->exports = RZ_NEWS0(ModuleExport, am->exports_count);
		if (!am->exports) {
			goto java_attribute_set_module_bad;
		}
		for (ut32 i = 0; i < am->exports_count; ++i) {
			am->exports[i].index = rz_buf_read_be16(buf);
			am->exports[i].flags = rz_buf_read_be16(buf);
			am->exports[i].to_count = rz_buf_read_be16(buf);
			tmp16 = RZ_NEWS0(ut16, am->exports[i].to_count);
			if (!tmp16) {
				goto java_attribute_set_module_bad;
			}
			am->exports[i].to_indices = tmp16;
			for (ut32 k = 0; k < am->exports[i].to_count; ++k) {
				tmp16[k] = rz_buf_read_be16(buf);
			}
		}
	}

	am->opens_count = rz_buf_read_be16(buf);
	if (am->opens_count > 0) {
		am->opens = RZ_NEWS0(ModuleOpen, am->opens_count);
		if (!am->opens) {
			goto java_attribute_set_module_bad;
		}
		for (ut32 i = 0; i < am->opens_count; ++i) {
			am->opens[i].index = rz_buf_read_be16(buf);
			am->opens[i].flags = rz_buf_read_be16(buf);
			am->opens[i].to_count = rz_buf_read_be16(buf);
			tmp16 = RZ_NEWS0(ut16, am->opens[i].to_count);
			if (!tmp16) {
				goto java_attribute_set_module_bad;
			}
			am->opens[i].to_indices = tmp16;
			for (ut32 k = 0; k < am->opens[i].to_count; ++k) {
				tmp16[k] = rz_buf_read_be16(buf);
			}
		}
	}

	am->uses_count = rz_buf_read_be16(buf);
	if (am->uses_count > 0) {
		am->uses_index = RZ_NEWS0(ut16, am->uses_count);
		if (!am->uses_index) {
			goto java_attribute_set_module_bad;
		}
		am->uses_index = tmp16;
		for (ut32 i = 0; i < am->uses_count; ++i) {
			tmp16[i] = rz_buf_read_be16(buf);
		}
	}

	am->provides_count = rz_buf_read_be16(buf);
	if (am->provides_count > 0) {
		am->provides = RZ_NEWS0(ModuleProvide, am->provides_count);
		if (!am->provides) {
			goto java_attribute_set_module_bad;
		}
		for (ut32 i = 0; i < am->provides_count; ++i) {
			am->provides[i].index = rz_buf_read_be16(buf);
			am->provides[i].with_count = rz_buf_read_be16(buf);
			tmp16 = RZ_NEWS0(ut16, am->provides[i].with_count);
			if (!tmp16) {
				goto java_attribute_set_module_bad;
			}
			am->provides[i].with_indices = tmp16;
			for (ut32 k = 0; k < am->provides[i].with_count; ++k) {
				tmp16[k] = rz_buf_read_be16(buf);
			}
		}
	}

	attr->type = ATTRIBUTE_TYPE_MODULE;
	attr->info = (void *)am;
	return true;

java_attribute_set_module_bad:
	rz_warn_if_reached();
	for (ut32 i = 0; i < am->exports_count; ++i) {
		free(am->exports[i].to_indices);
	}
	for (ut32 i = 0; i < am->opens_count; ++i) {
		free(am->opens[i].to_indices);
	}
	for (ut32 i = 0; i < am->provides_count; ++i) {
		free(am->provides[i].with_indices);
	}
	free(am->uses_index);
	free(am->exports);
	free(am->requires);
	free(am);
	return false;
}

bool java_attribute_set_modulepackages(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length >= 2);
	AttributeModulePackages *amp = RZ_NEW0(AttributeModulePackages);
	if (!amp) {
		rz_warn_if_reached();
		return false;
	}
	amp->package_count = rz_buf_read_be16(buf);
	if (amp->package_count > 0) {
		amp->package_index = RZ_NEWS0(ut16, amp->package_count);
		if (!amp->package_index) {
			free(amp);
			rz_warn_if_reached();
			return false;
		}
		for (ut32 k = 0; k < amp->package_count; ++k) {
			amp->package_index[k] = rz_buf_read_be16(buf);
		}
	}

	attr->type = ATTRIBUTE_TYPE_MODULEPACKAGES;
	attr->info = (void *)amp;
	return true;
}

bool java_attribute_set_modulemainclass(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length == 2);
	AttributeModuleMainClass *ammc = RZ_NEW0(AttributeModuleMainClass);
	if (!ammc) {
		rz_warn_if_reached();
		return false;
	}
	ammc->main_class_index = rz_buf_read_be16(buf);
	attr->type = ATTRIBUTE_TYPE_MODULEMAINCLASS;
	attr->info = (void *)ammc;
	return true;
}

bool java_attribute_resolve(ConstPool **pool, ut32 poolsize, Attribute *attr, RzBuffer *buf, bool is_oak) {
	char *name = resolve_const_pool_index(pool, poolsize, attr->attribute_name_index);
	if (!name) {
		return false;
	}

	bool result = false;
	if (!strcmp(name, "ConstantValue")) {
		result = java_attribute_set_constantvalue(attr, buf);
	} else if (!strcmp(name, "Code")) {
		result = java_attribute_set_code(pool, poolsize, attr, buf, is_oak);
	} else if (!strcmp(name, "SourceFile")) {
		result = java_attribute_set_sourcefile(attr, buf);
	} else if (!strcmp(name, "SourceDebugExtension")) {
		result = java_attribute_set_sourcedebugextension(attr, buf);
	} else if (!strcmp(name, "LineNumberTable")) {
		result = java_attribute_set_linenumbertable(attr, buf);
	} else if (!strcmp(name, "LocalVariableTable")) {
		result = java_attribute_set_localvariabletable(attr, buf);
	} else if (!strcmp(name, "LocalVariableTypeTable")) {
		result = java_attribute_set_localvariabletypetable(attr, buf);
	} else if (!strcmp(name, "Module")) {
		result = java_attribute_set_module(attr, buf);
	} else if (!strcmp(name, "ModulePackages")) {
		result = java_attribute_set_modulepackages(attr, buf);
	} else if (!strcmp(name, "ModuleMainClass")) {
		result = java_attribute_set_modulemainclass(attr, buf);
	}

	if (!result) {
		result = java_attribute_set_unknown(attr, buf);
	}
	free(name);
	return result;
}

Attribute *java_attribute_new(RzBuffer *buf, ut64 offset) {
	Attribute *attr = RZ_NEW0(Attribute);
	rz_return_val_if_fail(attr, NULL);

	attr->offset = offset;
	attr->attribute_name_index = rz_buf_read_be16(buf);
	ut32 attribute_length = 0;
	attribute_length = rz_buf_read_be32(buf);
	if (attribute_length == UT32_MAX) {
		free(attr);
		rz_warn_if_reached();
		return NULL;
	}
	attr->attribute_length = attribute_length;
	return attr;
}

void java_attribute_free(Attribute *attr) {
	if (!attr || !attr->info) {
		free(attr);
		return;
	}
	if (attr->type == ATTRIBUTE_TYPE_CODE) {
		AttributeCode *ac = (AttributeCode *)attr->info;
		free(ac->code);
		free(ac->exceptions);
		if (ac->attributes) {
			for (ut32 i = 0; i < ac->attributes_count; ++i) {
				java_attribute_free(ac->attributes[i]);
			}
			free(ac->attributes);
		}
	} else if (attr->type == ATTRIBUTE_TYPE_LINENUMBERTABLE) {
		AttributeLineNumberTable *alnt = (AttributeLineNumberTable *)attr->info;
		free(alnt->table);
	} else if (attr->type == ATTRIBUTE_TYPE_LOCALVARIABLETABLE) {
		AttributeLocalVariableTable *alvt = (AttributeLocalVariableTable *)attr->info;
		free(alvt->table);
	} else if (attr->type == ATTRIBUTE_TYPE_MODULE) {
		AttributeModule *am = (AttributeModule *)attr->info;
		for (ut32 i = 0; i < am->exports_count; ++i) {
			free(am->exports[i].to_indices);
		}
		for (ut32 i = 0; i < am->opens_count; ++i) {
			free(am->opens[i].to_indices);
		}
		for (ut32 i = 0; i < am->provides_count; ++i) {
			free(am->provides[i].with_indices);
		}
		free(am->uses_index);
		free(am->exports);
		free(am->requires);
	} else if (attr->type == ATTRIBUTE_TYPE_MODULEPACKAGES) {
		AttributeModulePackages *amp = (AttributeModulePackages *)attr->info;
		free(amp->package_index);
	}
	free(attr->info);
	free(attr);
}
