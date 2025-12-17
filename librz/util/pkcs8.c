// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdlib.h>
#include <string.h>
#include <rz_util.h>

static bool pkcs8_private_key_algorithm_parse(const RzASN1Object *object, RzPKCS8PrivateKeyAlgorithm *pka) {
	// first child object must be an OBJECT IDENTIFIER with size > 1 (i.e. algorithm)
	if (object->list.length < 1 ||
		!object->list.objects[0] ||
		object->list.objects[0]->tag != RZ_ASN1_TAG_OID ||
		object->list.objects[0]->length < 1) {
		RZ_LOG_INFO("pkcs8: expected pka.tag=oid but wasn't\n");
		return false;
	}

	pka->algorithm = rz_asn1_stringify_oid(object->list.objects[0]->sector, object->list.objects[0]->length);
	if (!pka->algorithm) {
		RZ_LOG_INFO("pkcs8: failed to decode algorithm oid\n");
		return false;
	}

	if (object->list.length > 1 && object->list.objects[1] && object->list.objects[0]->length > 1) {
		// the parameters value is optional and can be anything; it should be parsed based on the algorithm OID data.
		pka->parameters = rz_asn1_binary_parse(object->list.objects[1]->sector, object->list.objects[1]->length);
		if (!pka->parameters) {
			RZ_LOG_INFO("pkcs8: failed to alloc parameters bin\n");
			return false;
		}
	}

	return true;
}

/**
 * \brief      Parses a PKCS#8 PrivateKeyInfo structure from a given buffer
 *
 * \param[in]  buffer  The buffer to parse from
 * \param[in]  length  The length of the buffer
 *
 * \return     On success returns a valid pointer to a RzPrivateKeyInfo structure, otherwise NULL.
 */
RZ_API RZ_OWN RzPrivateKeyInfo *rz_pkcs8_private_key_info_parse(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	RzPrivateKeyInfo *pki = NULL;
	RzASN1Object *object = NULL;
	if (!buffer || !length || !(pki = RZ_NEW0(RzPrivateKeyInfo))) {
		return NULL;
	}

	object = rz_asn1_object_parse(buffer, length);
	if (!object ||
		object->klass != RZ_ASN1_CLASS_UNIVERSAL ||
		object->form != RZ_ASN1_FORM_CONSTRUCTED ||
		object->list.length < 3 ||
		!object->list.objects[0] ||
		!object->list.objects[1] ||
		!object->list.objects[2]) {
		RZ_LOG_INFO("pkcs8: invalid asn1 object\n");
		RZ_FREE(pki);
		goto fail;
	}

	// first child object must be an integer with size 1 (i.e. version)
	if (!object->list.objects[0] ||
		object->list.objects[0]->tag != RZ_ASN1_TAG_INTEGER ||
		object->list.objects[0]->length != 1) {
		RZ_LOG_INFO("pkcs8: expected pki[0].tag=integer but wasn't\n");
		RZ_FREE_CUSTOM(pki, rz_pkcs8_private_key_info_free);
		goto fail;
	}

	// second child object must be an sequence with at least 1 sub-object (i.e. algo id)
	if (!object->list.objects[1] ||
		object->list.objects[1]->tag != RZ_ASN1_TAG_SEQUENCE ||
		object->list.objects[1]->list.length < 1) {
		RZ_LOG_INFO("pkcs8: expected pki[1].tag=sequence but wasn't\n");
		RZ_FREE_CUSTOM(pki, rz_pkcs8_private_key_info_free);
		goto fail;
	}

	// third child object must be an octet string with a size > 1
	if (!object->list.objects[2] ||
		object->list.objects[2]->tag != RZ_ASN1_TAG_OCTETSTRING ||
		object->list.objects[2]->length < 1) {
		RZ_LOG_INFO("pkcs8: expected pki[2].tag=octet_string but wasn't\n");
		RZ_FREE_CUSTOM(pki, rz_pkcs8_private_key_info_free);
		goto fail;
	}

	pki->version = (ut32)object->list.objects[0]->sector[0];
	if (!pkcs8_private_key_algorithm_parse(object->list.objects[1], &pki->private_key_algorithm)) {
		RZ_LOG_INFO("pkcs8: expected valid pka but wasn't\n");
		RZ_FREE_CUSTOM(pki, rz_pkcs8_private_key_info_free);
		goto fail;
	}

	pki->private_key = rz_asn1_binary_parse(object->list.objects[2]->sector, object->list.objects[2]->length);
	if (!pki->private_key) {
		RZ_LOG_INFO("pkcs8: failed to alloc private key bin\n");
		RZ_FREE_CUSTOM(pki, rz_pkcs8_private_key_info_free);
		goto fail;
	}

	if (pki->version == RZ_PKCS8_VERSION_2 && object->list.length > 3) {
		// when V2 there can be the public key embedded in the structure
		// this structure is available after the attributes field (the 4th field) and is always the last one.
		const RzASN1Object *last = object->list.objects[object->list.length - 1];
		if (last && last->tag == RZ_ASN1_TAG_BITSTRING && last->length > 0) {
			// we use bytes instead of bits for convinience.
			pki->public_key = rz_asn1_binary_parse(last->sector, last->length);
			if (!pki->public_key) {
				RZ_LOG_INFO("pkcs8: failed to alloc public key bin\n");
				RZ_FREE_CUSTOM(pki, rz_pkcs8_private_key_info_free);
				goto fail;
			}
		}
	}

fail:
	rz_asn1_object_free(object);
	return pki;
}

/**
 * \brief      Frees a RzPrivateKeyInfo structure
 *
 * \param      pki   The pki to be freed
 */
RZ_API void rz_pkcs8_private_key_info_free(RZ_NULLABLE RzPrivateKeyInfo *pki) {
	if (!pki) {
		return;
	}

	rz_asn1_string_free(pki->private_key_algorithm.algorithm);
	rz_asn1_binary_free(pki->private_key_algorithm.parameters);
	rz_asn1_binary_free(pki->private_key);
	rz_asn1_binary_free(pki->public_key);
	free(pki);
}

static RZ_OWN char *asn1_oid_copy_name(const RzASN1String *asn1str) {
	if (!asn1str) {
		return NULL;
	}

	const char *first_whitespace = rz_str_trim_head_wp(asn1str->string);
	if (!first_whitespace) {
		// length counts also the `\0`
		return rz_str_ndup(asn1str->string, asn1str->length - 1);
	}

	size_t size = first_whitespace - asn1str->string;
	return rz_str_ndup(asn1str->string, size);
}

/**
 * \brief      Returns the algorithm name of a given PrivateKeyInfo
 *
 * \param[in]  pki   The PrivateKeyInfo to use
 *
 * \return     On success returns a valid pointer to a C string, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_pkcs8_private_key_algorithm(RZ_NONNULL const RzPrivateKeyInfo *pki) {
	rz_return_val_if_fail(pki && pki->private_key_algorithm.algorithm, NULL);

	const RzPKCS8PrivateKeyAlgorithm *pka = &pki->private_key_algorithm;
	if (rz_str_startswith(pka->algorithm->string, "ecPublicKey")) {
		// when ecPublicKey is found, params is an oid
		char *copy = NULL;
		RzASN1String *oid = rz_asn1_stringify_oid(pka->parameters->binary, pka->parameters->length);
		if (oid) {
			copy = asn1_oid_copy_name(oid);
			rz_asn1_string_free(oid);
			return copy;
		}
	}

	return asn1_oid_copy_name(pka->algorithm);
}

static void pkcs8_private_key_algorithm_to_structure(const RzPKCS8PrivateKeyAlgorithm *pka, RzStructuredData *pkey_algo) {
	if (!pka->algorithm) {
		return;
	}

	const char *algorithm = pka->algorithm->string;
	const RzASN1Binary *parameters = pka->parameters;
	rz_structured_data_map_add_string(pkey_algo, "algorithm", algorithm);
	if (!parameters) {
		return;
	}

	if (rz_str_startswith(algorithm, "ecPublicKey")) {
		// when ecPublicKey is found, params is an oid
		RzASN1String *oid = rz_asn1_stringify_oid(parameters->binary, parameters->length);
		if (oid) {
			rz_structured_data_map_add_string(pkey_algo, "parameters", oid->string);
			rz_asn1_string_free(oid);
		}
		return;
	}

	// generic fallback to just hexdump the data, since we do not know the structure.
	RzASN1String *bytes = rz_asn1_stringify_bytes(parameters->binary, parameters->length);
	if (bytes) {
		rz_str_trim_tail((char *)bytes->string);
		rz_structured_data_map_add_string(pkey_algo, "parameters", bytes->string);
		rz_asn1_string_free(bytes);
	}
}

/**
 * \brief      Returns the PrivateKeyInfo as RzStructuredData
 *
 * \param      pki   The pki to convert into RzStructuredData
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzStructuredData *rz_pkcs8_private_key_info_to_structure(RZ_NULLABLE const RzPrivateKeyInfo *pki) {
	if (!pki) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *sd_pki = rz_structured_data_map_add_map(root, "PrivateKeyInfo");
	RzStructuredData *pkey_algo = rz_structured_data_map_add_map(sd_pki, "privateKeyAlgorithm");

	pkcs8_private_key_algorithm_to_structure(&pki->private_key_algorithm, pkey_algo);

	if (pki->private_key) {
		RzASN1String *bytes = rz_asn1_stringify_bytes(pki->private_key->binary, pki->private_key->length);
		if (bytes) {
			rz_str_trim_tail((char *)bytes->string);
			rz_structured_data_map_add_string(sd_pki, "privateKey", bytes->string);
			rz_asn1_string_free(bytes);
		}
	}

	if (pki->public_key) {
		RzASN1String *bytes = rz_asn1_stringify_bytes(pki->public_key->binary, pki->public_key->length);
		if (bytes) {
			rz_str_trim_tail((char *)bytes->string);
			rz_structured_data_map_add_string(sd_pki, "publicKey", bytes->string);
			rz_asn1_string_free(bytes);
		}
	}

	return root;
}
