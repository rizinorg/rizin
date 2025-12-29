// SPDX-FileCopyrightText: 2017-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdlib.h>
#include <string.h>
#include <rz_util.h>
#include "./x509.h"

static bool pkcs7_attributes_parse(RzPKCS7Attributes *attribute, RzASN1Object *object);

static bool pkcs7_contentinfo_parse(RzPKCS7ContentInfo *ci, RzASN1Object *object) {
	if (!ci || !object || object->list.length < 1 || !object->list.objects[0]) {
		return false;
	}
	ci->contentType = rz_asn1_stringify_oid(object->list.objects[0]->sector, object->list.objects[0]->length);
	if (object->list.length > 1) {
		RzASN1Object *obj1 = object->list.objects[1];
		if (obj1) {
			ci->content = rz_asn1_binary_parse(obj1->sector, obj1->length);
		}
	}
	return true;
}

static bool pkcs7_certificaterevocationlists_parse(RzPKCS7CertificateRevocationLists *crls, RzASN1Object *object) {
	if (!crls || !object) {
		return false;
	}
	if (object->list.length > 0) {
		crls->elements = (RzX509CertificateRevocationList **)calloc(object->list.length, sizeof(RzX509CertificateRevocationList *));
		if (!crls->elements) {
			return false;
		}
		crls->length = object->list.length;
		for (ut32 i = 0; i < crls->length; i++) {
			crls->elements[i] = rz_x509_crl_parse(object->list.objects[i]);
		}
	}
	return true;
}

static void pkcs7_certificaterevocationlists_fini(RzPKCS7CertificateRevocationLists *crls) {
	if (!crls) {
		return;
	}
	for (ut32 i = 0; i < crls->length; i++) {
		rz_x509_crl_free(crls->elements[i]);
		crls->elements[i] = NULL;
	}
	RZ_FREE(crls->elements);
	// Used internally pkcs #7, so it shouldn't free crls.
}

static bool pkcs7_extendedcertificatesandcertificates_parse(RzPKCS7ExtendedCertificatesAndCertificates *ecac, RzASN1Object *object) {
	if (!ecac || !object) {
		return false;
	}
	if (object->list.length > 0) {
		ecac->elements = (RzX509Certificate **)calloc(object->list.length, sizeof(RzX509Certificate *));
		if (!ecac->elements) {
			return false;
		}
		ecac->length = object->list.length;
		for (ut32 i = 0; i < ecac->length; i++) {
			ecac->elements[i] = rz_x509_certificate_parse(object->list.objects[i]);
			object->list.objects[i] = NULL;
		}
	}
	return true;
}

static void pkcs7_extendedcertificatesandcertificates_fini(RzPKCS7ExtendedCertificatesAndCertificates *ecac) {
	if (!ecac) {
		return;
	}
	for (ut32 i = 0; i < ecac->length; i++) {
		rz_x509_certificate_free(ecac->elements[i]);
		ecac->elements[i] = NULL;
	}
	RZ_FREE(ecac->elements);
	// Used internally pkcs #7, so it shouldn't free ecac.
}

static bool pkcs7_digestalgorithmidentifier_parse(RzPKCS7DigestAlgorithmIdentifiers *dai, RzASN1Object *object) {
	if (!dai || !object) {
		return false;
	}
	if (object->list.length > 0) {
		dai->elements = (RzX509AlgorithmIdentifier **)calloc(object->list.length, sizeof(RzX509AlgorithmIdentifier *));
		if (!dai->elements) {
			return false;
		}
		dai->length = object->list.length;
		for (ut32 i = 0; i < dai->length; i++) {
			// rz_x509_algorithmidentifier_parse returns bool,
			// so i have to allocate before calling the function
			dai->elements[i] = (RzX509AlgorithmIdentifier *)malloc(sizeof(RzX509AlgorithmIdentifier));
			// should i handle invalid memory? the function checks the pointer
			// or it should return if dai->elements[i] == NULL ?
			if (dai->elements[i]) {
				// Memset is needed to initialize to 0 the structure and avoid garbage.
				memset(dai->elements[i], 0, sizeof(RzX509AlgorithmIdentifier));
				rz_x509_algorithmidentifier_parse(dai->elements[i], object->list.objects[i]);
			}
		}
	}
	return true;
}

static void pkcs7_digestalgorithmidentifier_fini(RzPKCS7DigestAlgorithmIdentifiers *dai) {
	if (!dai) {
		return;
	}
	for (ut32 i = 0; i < dai->length; i++) {
		if (dai->elements[i]) {
			rz_x509_algorithmidentifier_fini(dai->elements[i]);
			// rz_x509_algorithmidentifier_fini doesn't free the pointer
			// because on x509 the original use was internal.
			RZ_FREE(dai->elements[i]);
		}
	}
	RZ_FREE(dai->elements);
	// Used internally pkcs #7, so it shouldn't free dai.
}

static void pkcs7_contentinfo_fini(RzPKCS7ContentInfo *ci) {
	if (!ci) {
		return;
	}
	rz_asn1_binary_free(ci->content);
	rz_asn1_string_free(ci->contentType);
	// Used internally pkcs #7, so it shouldn't free ci.
}

static bool pkcs7_issuerandserialnumber_parse(RzPKCS7IssuerAndSerialNumber *iasu, RzASN1Object *object) {
	if (!iasu || !object || object->list.length != 2) {
		return false;
	}
	rz_x509_name_parse(&iasu->issuer, object->list.objects[0]);
	RzASN1Object *obj1 = object->list.objects[1];
	if (obj1) {
		iasu->serialNumber = rz_asn1_binary_parse(obj1->sector, obj1->length);
	}
	return true;
}

static void pkcs7_issuerandserialnumber_fini(RzPKCS7IssuerAndSerialNumber *iasu) {
	if (!iasu) {
		return;
	}
	rz_x509_name_fini(&iasu->issuer);
	rz_asn1_binary_free(iasu->serialNumber);
	// Used internally pkcs #7, so it shouldn't free iasu.
}

static bool pkcs7_signerinfo_parse(RzPKCS7SignerInfo *si, RzASN1Object *object) {
	RzASN1Object **elems;
	ut32 shift = 3;
	if (!si || !object || object->list.length < 5) {
		return false;
	}
	elems = object->list.objects;
	// Following RFC
	si->version = (ut32)elems[0]->sector[0];
	pkcs7_issuerandserialnumber_parse(&si->issuerAndSerialNumber, elems[1]);
	rz_x509_algorithmidentifier_parse(&si->digestAlgorithm, elems[2]);
	if (shift < object->list.length && elems[shift]->klass == RZ_ASN1_CLASS_CONTEXT && elems[shift]->tag == 0) {
		pkcs7_attributes_parse(&si->authenticatedAttributes, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		rz_x509_algorithmidentifier_parse(&si->digestEncryptionAlgorithm, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		RzASN1Object *obj1 = object->list.objects[shift];
		if (obj1) {
			si->encryptedDigest = rz_asn1_binary_parse(obj1->sector, obj1->length);
			shift++;
		}
	}
	if (shift < object->list.length) {
		RzASN1Object *elem = elems[shift];
		if (elem && elem->klass == RZ_ASN1_CLASS_CONTEXT && elem->tag == 1) {
			pkcs7_attributes_parse(&si->unauthenticatedAttributes, elems[shift]);
		}
	}
	return true;
}

static void pkcs7_attribute_free(RzPKCS7Attribute *attribute) {
	if (!attribute) {
		return;
	}
	rz_asn1_binary_free(attribute->data);
	rz_asn1_string_free(attribute->oid);
	free(attribute);
}

static void pkcs7_attributes_fini(RzPKCS7Attributes *attributes) {
	if (!attributes) {
		return;
	}
	for (ut32 i = 0; i < attributes->length; i++) {
		pkcs7_attribute_free(attributes->elements[i]);
	}
	RZ_FREE(attributes->elements);
	// Used internally pkcs #7, so it shouldn't free attributes.
}

static void pkcs7_signerinfo_free(RzPKCS7SignerInfo *si) {
	if (!si) {
		return;
	}
	pkcs7_issuerandserialnumber_fini(&si->issuerAndSerialNumber);
	rz_x509_algorithmidentifier_fini(&si->digestAlgorithm);
	pkcs7_attributes_fini(&si->authenticatedAttributes);
	rz_x509_algorithmidentifier_fini(&si->digestEncryptionAlgorithm);
	rz_asn1_binary_free(si->encryptedDigest);
	pkcs7_attributes_fini(&si->unauthenticatedAttributes);
	free(si);
}

static bool pkcs7_signerinfos_parse(RzPKCS7SignerInfos *ss, RzASN1Object *object) {
	if (!ss || !object) {
		return false;
	}
	if (object->list.length > 0) {
		ss->elements = (RzPKCS7SignerInfo **)calloc(object->list.length, sizeof(RzPKCS7SignerInfo *));
		if (!ss->elements) {
			return false;
		}
		ss->length = object->list.length;
		for (ut32 i = 0; i < ss->length; i++) {
			// pkcs7_signerinfo_parse returns bool,
			// so i have to allocate before calling the function
			ss->elements[i] = RZ_NEW0(RzPKCS7SignerInfo);
			// should i handle invalid memory? the function checks the pointer
			// or it should return if si->elements[i] == NULL ?
			pkcs7_signerinfo_parse(ss->elements[i], object->list.objects[i]);
		}
	}
	return true;
}

static void pkcs7_signerinfos_fini(RzPKCS7SignerInfos *ss) {
	if (!ss) {
		return;
	}
	for (ut32 i = 0; i < ss->length; i++) {
		pkcs7_signerinfo_free(ss->elements[i]);
		ss->elements[i] = NULL;
	}
	RZ_FREE(ss->elements);
	// Used internally pkcs #7, so it shouldn't free ss.
}

static bool pkcs7_signeddata_parse(RzPKCS7SignedData *sd, RzASN1Object *object) {
	ut32 shift = 3;
	if (!sd || !object || object->list.length < 4) {
		return false;
	}
	memset(sd, 0, sizeof(RzPKCS7SignedData));
	RzASN1Object **elems = object->list.objects;
	// Following RFC
	sd->version = (ut32)elems[0]->sector[0];
	pkcs7_digestalgorithmidentifier_parse(&sd->digestAlgorithms, elems[1]);
	pkcs7_contentinfo_parse(&sd->contentInfo, elems[2]);
	// Optional
	if (object->list.length > 3 && shift < object->list.length && elems[shift] &&
		elems[shift]->klass == RZ_ASN1_CLASS_CONTEXT && elems[shift]->tag == 0) {
		pkcs7_extendedcertificatesandcertificates_parse(&sd->certificates, elems[shift]);
		shift++;
	}
	// Optional
	if (object->list.length > 3 && shift < object->list.length && elems[shift] &&
		elems[shift]->klass == RZ_ASN1_CLASS_CONTEXT && elems[shift]->tag == 1) {
		pkcs7_certificaterevocationlists_parse(&sd->crls, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		pkcs7_signerinfos_parse(&sd->signerinfos, elems[shift]);
	}
	return true;
}

static void pkcs7_signeddata_fini(RzPKCS7SignedData *sd) {
	if (!sd) {
		return;
	}
	pkcs7_digestalgorithmidentifier_fini(&sd->digestAlgorithms);
	pkcs7_contentinfo_fini(&sd->contentInfo);
	pkcs7_extendedcertificatesandcertificates_fini(&sd->certificates);
	pkcs7_certificaterevocationlists_fini(&sd->crls);
	pkcs7_signerinfos_fini(&sd->signerinfos);
	// Used internally pkcs #7, so it shouldn't free sd.
}

/**
 * \brief      Parses a Cryptographic Message Syntax (or CMS) from a buffer
 *
 * \param[in]  buffer  The buffer to use to parse
 * \param[in]  length  The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzCMS *rz_pkcs7_cms_parse(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	RzASN1Object *object;
	RzCMS *container;
	if (!buffer || !length) {
		return NULL;
	}
	container = RZ_NEW0(RzCMS);
	if (!container) {
		return NULL;
	}
	object = rz_asn1_object_parse(buffer, length);
	if (!object || object->list.length < 2 || !object->list.objects ||
		!object->list.objects[0] || !object->list.objects[1] ||
		object->list.objects[1]->list.length < 1) {
		rz_asn1_object_free(object);
		free(container);
		return NULL;
	}
	if (object->list.objects[0]) {
		container->contentType = rz_asn1_stringify_oid(object->list.objects[0]->sector, object->list.objects[0]->length);
		if (!container->contentType) {
			rz_asn1_object_free(object);
			free(container);
			return NULL;
		}
	}
	if (object->list.objects[1]) {
		pkcs7_signeddata_parse(&container->signedData, object->list.objects[1]->list.objects[0]);
	}
	rz_asn1_object_free(object);
	return container;
}

/**
 * \brief      Frees a Cryptographic Message Syntax (or CMS) pointer
 *
 * \param      container  The container to free
 */
RZ_API void rz_pkcs7_cms_free(RZ_NULLABLE RzCMS *container) {
	if (!container) {
		return;
	}

	rz_asn1_string_free(container->contentType);
	pkcs7_signeddata_fini(&container->signedData);
	free(container);
}

static RzPKCS7Attribute *pkcs7_attribute_parse(RzASN1Object *object) {
	RzPKCS7Attribute *attribute;
	if (!object || object->list.length < 1) {
		return NULL;
	}
	attribute = RZ_NEW0(RzPKCS7Attribute);
	if (!attribute) {
		return NULL;
	}
	if (object->list.objects[0]) {
		attribute->oid = rz_asn1_stringify_oid(object->list.objects[0]->sector, object->list.objects[0]->length);
	}
	if (object->list.length == 2) {
		RzASN1Object *obj1 = object->list.objects[1];
		if (obj1) {
			attribute->data = rz_asn1_binary_parse(obj1->sector, obj1->length);
		}
	}
	return attribute;
}

static bool pkcs7_attributes_parse(RzPKCS7Attributes *attributes, RzASN1Object *object) {
	if (!attributes || !object || !object->list.length) {
		return false;
	}

	attributes->length = object->list.length;
	if (attributes->length > 0) {
		attributes->elements = RZ_NEWS0(RzPKCS7Attribute *, attributes->length);
		if (!attributes->elements) {
			attributes->length = 0;
			return false;
		}
		for (ut32 i = 0; i < object->list.length; i++) {
			attributes->elements[i] = pkcs7_attribute_parse(object->list.objects[i]);
		}
	}
	return true;
}

static void pkcs7_attributes_to_structure(RzStructuredData *array, RzPKCS7Attribute *attribute) {
	if (!attribute || !attribute->oid) {
		return;
	}
	RzStructuredData *attr = rz_structured_data_array_add_map(array);
	if (!attribute->data) {
		rz_structured_data_map_add_string(attr, attribute->oid->string, "");
		return;
	}

	RzASN1String *bytes = rz_asn1_stringify_bytes(attribute->data->binary, attribute->data->length);
	if (bytes) {
		rz_structured_data_map_add_string(attr, attribute->oid->string, bytes->string);
	}
	rz_asn1_string_free(bytes);
}

static RzStructuredData *pkcs7_signedinfo_to_structure(RzPKCS7SignerInfo *si) {
	if (!si) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	rz_structured_data_map_add_signed(root, "version", si->version + 1);

	RzStructuredData *issuer = rz_structured_data_map_add_array(root, "issuer");
	rz_x509_name_to_structure(issuer, &si->issuerAndSerialNumber.issuer);

	if (si->issuerAndSerialNumber.serialNumber) {
		RzASN1Binary *o = si->issuerAndSerialNumber.serialNumber;
		RzASN1String *serial = rz_asn1_stringify_integer(o->binary, o->length);
		rz_structured_data_map_add_string(root, "serialNumber", serial ? serial->string : "");
		rz_asn1_string_free(serial);
	}

	RzStructuredData *digest_algorithm = rz_structured_data_map_add_map(root, "digestAlgorithm");
	rz_x509_algorithmidentifier_to_structure(digest_algorithm, &si->digestAlgorithm);

	if (si->authenticatedAttributes.length) {
		RzStructuredData *authAttrbs = rz_structured_data_map_add_array(root, "authenticatedAttributes");
		for (ut32 i = 0; i < si->authenticatedAttributes.length; i++) {
			pkcs7_attributes_to_structure(authAttrbs, si->authenticatedAttributes.elements[i]);
		}
	}

	RzStructuredData *digest_enc_algo = rz_structured_data_map_add_map(root, "digestEncryptionAlgorithm");
	rz_x509_algorithmidentifier_to_structure(digest_enc_algo, &si->digestEncryptionAlgorithm);

	if (si->encryptedDigest) {
		RzASN1String *bytes = rz_asn1_stringify_bytes(si->encryptedDigest->binary, si->encryptedDigest->length);
		rz_structured_data_map_add_string(root, "encryptedDigest", bytes->string);
		rz_asn1_string_free(bytes);
	}

	if (si->unauthenticatedAttributes.length) {
		RzStructuredData *unauthAttrbs = rz_structured_data_map_add_array(root, "unauthenticatedAttributes");
		for (ut32 i = 0; i < si->unauthenticatedAttributes.length; i++) {
			pkcs7_attributes_to_structure(unauthAttrbs, si->unauthenticatedAttributes.elements[i]);
		}
	}

	return root;
}

/**
 * \brief      Returns the Cryptographic Message Syntax (or CMS) as RzStructuredData
 *
 * \param      container  The container to be converted to RzStructuredData
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzStructuredData *rz_pkcs7_cms_to_structure(RZ_NULLABLE RzCMS *container) {
	if (!container) {
		return NULL;
	}
	RzPKCS7SignedData *sd = &container->signedData;
	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *signed_data = rz_structured_data_map_add_map(root, "signedData");
	rz_structured_data_map_add_signed(signed_data, "version", sd->version);

	if (container->signedData.digestAlgorithms.elements) {
		RzStructuredData *digest_algos = rz_structured_data_map_add_array(signed_data, "digestAlgorithms");
		for (ut32 i = 0; i < container->signedData.digestAlgorithms.length; i++) {
			if (!container->signedData.digestAlgorithms.elements[i]) {
				continue;
			}
			RzStructuredData *digest = rz_structured_data_array_add_map(digest_algos);
			rz_x509_algorithmidentifier_to_structure(digest, container->signedData.digestAlgorithms.elements[i]);
		}
	}

	if (container->signedData.certificates.length) {
		RzStructuredData *certificates = rz_structured_data_map_add_array(signed_data, "certificates");
		for (ut32 i = 0; i < container->signedData.certificates.length; i++) {
			RzStructuredData *cert = rz_x509_certificate_to_structure(container->signedData.certificates.elements[i]);
			if (!cert) {
				continue;
			}
			rz_structured_data_array_add(certificates, cert);
		}
	}

	if (container->signedData.crls.length) {
		RzStructuredData *crls = rz_structured_data_map_add_array(signed_data, "crls");
		for (ut32 i = 0; i < container->signedData.crls.length; i++) {
			RzStructuredData *crl = rz_x509_crl_to_structure(container->signedData.crls.elements[i]);
			if (!crl) {
				continue;
			}
			rz_structured_data_array_add(crls, crl);
		}
	}

	if (container->signedData.signerinfos.elements) {
		RzStructuredData *sig_infos = rz_structured_data_map_add_array(signed_data, "signerInfos");
		for (ut32 i = 0; i < container->signedData.signerinfos.length; i++) {
			RzStructuredData *sig_info = pkcs7_signedinfo_to_structure(container->signedData.signerinfos.elements[i]);
			if (!sig_info) {
				continue;
			}
			rz_structured_data_array_add(sig_infos, sig_info);
		}
	}

	return root;
}

static bool pkcs7_spcdata_parse(RzSpcAttributeTypeAndOptionalValue *data, RzASN1Object *object) {
	if (!data || !object || object->list.length < 1 ||
		!object->list.objects[0]) {
		return false;
	}
	data->type = rz_asn1_stringify_oid(object->list.objects[0]->sector, object->list.objects[0]->length);
	if (!data->type) {
		return false;
	} else if (object->list.length < 2) {
		return true;
	}
	RzASN1Object *obj1 = object->list.objects[1];
	if (obj1) {
		data->data = rz_asn1_binary_parse(obj1->sector, obj1->length);
	}
	return true;
}

static bool pkcs7_spcmessagedigest_parse(RzSpcDigestInfo *messageDigest, RzASN1Object *object) {
	if (!messageDigest || !object || object->list.length < 2 ||
		!object->list.objects[0] || !object->list.objects[1]) {
		return false;
	}
	if (!rz_x509_algorithmidentifier_parse(&messageDigest->digestAlgorithm, object->list.objects[0])) {
		return false;
	}
	RzASN1Object *obj1 = object->list.objects[1];
	messageDigest->digest = rz_asn1_binary_parse(obj1->sector, obj1->length);
	return true;
}

/**
 * \brief      Extracts the SPC structure from a Cryptographic Message Syntax (or CMS)
 *
 * \param      cms   The CMS structure to use
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSpcIndirectDataContent *rz_pkcs7_spcinfo_parse(RZ_NONNULL RzCMS *cms) {
	rz_return_val_if_fail(cms, NULL);

	RzASN1String *type = cms->signedData.contentInfo.contentType;
	if (type && !rz_str_startswith(type->string, "spcIndirectDataContext")) {
		return NULL;
	}

	RzSpcIndirectDataContent *spcinfo = RZ_NEW0(RzSpcIndirectDataContent);
	if (!spcinfo) {
		return NULL;
	}

	RzASN1Binary *content = cms->signedData.contentInfo.content;
	if (!content) {
		free(spcinfo);
		return NULL;
	}
	RzASN1Object *object = rz_asn1_object_parse(content->binary, content->length);
	if (!object || object->list.length < 2 || !object->list.objects ||
		!object->list.objects[0] || !object->list.objects[1]) {
		RZ_FREE_CUSTOM(spcinfo, rz_pkcs7_spcinfo_free);
		goto beach;
	}
	if (object->list.objects[0]) {
		if (!pkcs7_spcdata_parse(&spcinfo->data, object->list.objects[0])) {
			RZ_FREE_CUSTOM(spcinfo, rz_pkcs7_spcinfo_free);
			goto beach;
		}
	}
	if (object->list.objects[1]) {
		if (!pkcs7_spcmessagedigest_parse(&spcinfo->messageDigest, object->list.objects[1])) {
			RZ_FREE_CUSTOM(spcinfo, rz_pkcs7_spcinfo_free);
			goto beach;
		}
	}
beach:
	rz_asn1_object_free(object);
	return spcinfo;
}

static void pkcs7_spcdata_fini(RzSpcAttributeTypeAndOptionalValue *data) {
	if (!data) {
		return;
	}
	rz_asn1_string_free(data->type);
	rz_asn1_binary_free(data->data);
}

static void pkcs7_spcmessagedigest_fini(RzSpcDigestInfo *messageDigest) {
	if (!messageDigest) {
		return;
	}
	rz_asn1_binary_free(messageDigest->digest);
	rz_x509_algorithmidentifier_fini(&messageDigest->digestAlgorithm);
}

/**
 * \brief      Frees a RzSpcIndirectDataContent pointer
 *
 * \param      spcinfo  The spcinfo to free
 */
RZ_API void rz_pkcs7_spcinfo_free(RZ_NULLABLE RzSpcIndirectDataContent *spcinfo) {
	if (!spcinfo) {
		return;
	}
	pkcs7_spcdata_fini(&spcinfo->data);
	pkcs7_spcmessagedigest_fini(&spcinfo->messageDigest);
	free(spcinfo);
}

/**
 * \brief      Returns the SPC structure as RzStructuredData
 *
 * \param      container  The container to be converted to RzStructuredData
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzStructuredData *rz_pkcs7_spcinfo_to_structure(RZ_NULLABLE RzSpcIndirectDataContent *spcinfo) {
	if (!spcinfo) {
		return NULL;
	}
	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *spc_attribute = rz_structured_data_map_add_map(root, "spcAttribute");
	if (spcinfo->data.type) {
		rz_structured_data_map_add_string(spc_attribute, "type", spcinfo->data.type->string);
	}
	if (spcinfo->data.data) {
		RzASN1Binary *opt = spcinfo->data.data;
		RzASN1String *asn1str = NULL;
		if (rz_str_is_printable_limited((const char *)opt->binary, opt->length)) {
			asn1str = rz_asn1_stringify_string(opt->binary, opt->length);
		} else {
			asn1str = rz_asn1_stringify_bytes(opt->binary, opt->length);
		}
		if (asn1str) {
			rz_structured_data_map_add_string(spc_attribute, "data", asn1str->string);
			rz_asn1_string_free(asn1str);
		}
	}

	RzStructuredData *message_digest = rz_structured_data_map_add_map(root, "messageDigest");
	RzStructuredData *digest_algorithm = rz_structured_data_map_add_map(message_digest, "digestAlgorithm");

	rz_x509_algorithmidentifier_to_structure(digest_algorithm, &spcinfo->messageDigest.digestAlgorithm);

	if (spcinfo->messageDigest.digest) {
		RzASN1Binary *opt = spcinfo->messageDigest.digest;
		RzASN1String *asn1str = rz_asn1_stringify_bytes(opt->binary, opt->length);
		if (asn1str) {
			rz_structured_data_map_add_string(message_digest, "digest", asn1str->string);
			rz_asn1_string_free(asn1str);
		}
	}

	return root;
}
