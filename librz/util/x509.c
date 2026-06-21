// SPDX-FileCopyrightText: 2017-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_cons.h>
#include <stdlib.h>
#include <string.h>
#include "./x509.h"

static bool rz_x509_validity_parse(RzX509Validity *validity, RzASN1Object *object) {
	RzASN1Object *o;
	if (!validity || !object || object->list.length != 2) {
		return false;
	}
	if (object->klass == RZ_ASN1_CLASS_UNIVERSAL &&
		object->tag == RZ_ASN1_TAG_SEQUENCE &&
		object->form == RZ_ASN1_FORM_CONSTRUCTED) {
		o = object->list.objects[0];
		if (o && o->klass == RZ_ASN1_CLASS_UNIVERSAL && o->form == RZ_ASN1_FORM_PRIMITIVE) {
			if (o->tag == RZ_ASN1_TAG_UTCTIME) {
				validity->notBefore = rz_asn1_stringify_utctime(o->sector, o->length);
			} else if (o->tag == RZ_ASN1_TAG_GENERALIZEDTIME) {
				validity->notBefore = rz_asn1_stringify_time(o->sector, o->length);
			}
		}
		o = object->list.objects[1];
		if (o && o->klass == RZ_ASN1_CLASS_UNIVERSAL && o->form == RZ_ASN1_FORM_PRIMITIVE) {
			if (o->tag == RZ_ASN1_TAG_UTCTIME) {
				validity->notAfter = rz_asn1_stringify_utctime(o->sector, o->length);
			} else if (o->tag == RZ_ASN1_TAG_GENERALIZEDTIME) {
				validity->notAfter = rz_asn1_stringify_time(o->sector, o->length);
			}
		}
	}
	return true;
}

static inline bool is_oid_object(RzASN1Object *object) {
	return object->list.objects[0] &&
		object->list.objects[0]->klass == RZ_ASN1_CLASS_UNIVERSAL &&
		object->list.objects[0]->tag == RZ_ASN1_TAG_OID;
}

RZ_IPI bool rz_x509_algorithmidentifier_parse(RZ_NONNULL RzX509AlgorithmIdentifier *ai, RZ_NONNULL RzASN1Object *object) {
	rz_return_val_if_fail(ai && object, false);

	if (object->list.length < 1 || !object->list.objects || !is_oid_object(object)) {
		return false;
	}

	ai->algorithm = rz_asn1_stringify_oid(object->list.objects[0]->sector, object->list.objects[0]->length);
	if (object->list.length < 2 || !object->list.objects[1]) {
		return true;
	}

	ai->parameters = rz_asn1_binary_parse(object->list.objects[1]->sector, object->list.objects[1]->length);
	return true;
}

static bool x509_subjectpublickeyinfo_parse(RzX509SubjectPublicKeyInfo *spki, RzASN1Object *object) {
	RzASN1Object *o;
	if (!spki || !object || object->list.length != 2) {
		return false;
	}
	rz_x509_algorithmidentifier_parse(&spki->algorithm, object->list.objects[0]);
	if (object->list.objects[1]) {
		o = object->list.objects[1];
		spki->subjectPublicKey = rz_asn1_binary_parse(o->sector, o->length);
		if (o->list.length == 1 && o->list.objects[0] && o->list.objects[0]->list.length == 2) {
			o = o->list.objects[0];
			if (o->list.objects[0]) {
				spki->subjectPublicKeyExponent = rz_asn1_binary_parse(o->list.objects[0]->sector, o->list.objects[0]->length);
			}
			if (o->list.objects[1]) {
				spki->subjectPublicKeyModule = rz_asn1_binary_parse(o->list.objects[1]->sector, o->list.objects[1]->length);
			}
		}
	}
	return true;
}

RZ_IPI bool rz_x509_name_parse(RZ_NULLABLE RzX509Name *name, RZ_NULLABLE RzASN1Object *object) {
	if (!name || !object || !object->list.length) {
		return false;
	}
	if (object->klass == RZ_ASN1_CLASS_UNIVERSAL && object->tag == RZ_ASN1_TAG_SEQUENCE) {
		name->length = object->list.length;
		name->names = (RzASN1String **)calloc(name->length, sizeof(RzASN1String *));
		if (!name->names) {
			name->length = 0;
			return false;
		}
		name->oids = (RzASN1String **)calloc(name->length, sizeof(RzASN1String *));
		if (!name->oids) {
			name->length = 0;
			RZ_FREE(name->names);
			return false;
		}
		for (ut32 i = 0; i < object->list.length; i++) {
			RzASN1Object *o = object->list.objects[i];
			if (o && o->klass == RZ_ASN1_CLASS_UNIVERSAL &&
				o->tag == RZ_ASN1_TAG_SET &&
				o->form == RZ_ASN1_FORM_CONSTRUCTED &&
				o->list.length == 1) {
				o = o->list.objects[0];
				if (o && o->list.length > 1 &&
					o->klass == RZ_ASN1_CLASS_UNIVERSAL &&
					o->tag == RZ_ASN1_TAG_SEQUENCE) {
					if (o->list.objects[0]->klass == RZ_ASN1_CLASS_UNIVERSAL &&
						o->list.objects[0]->tag == RZ_ASN1_TAG_OID) {
						name->oids[i] = rz_asn1_stringify_oid(o->list.objects[0]->sector, o->list.objects[0]->length);
					}
					RzASN1Object *obj1 = o->list.objects[1];
					if (obj1 && obj1->klass == RZ_ASN1_CLASS_UNIVERSAL) {
						name->names[i] = rz_asn1_stringify_string(obj1->sector, obj1->length);
					}
				}
			}
		}
	}
	return true;
}

static bool x509_extension_parse(RzX509Extension *ext, RzASN1Object *object) {
	RzASN1Object *o;
	if (!ext || !object || object->list.length < 2) {
		return false;
	}
	o = object->list.objects[0];
	if (o && o->tag == RZ_ASN1_TAG_OID) {
		ext->extnID = rz_asn1_stringify_oid(o->sector, o->length);
		o = object->list.objects[1];
		if (o && o->tag == RZ_ASN1_TAG_BOOLEAN && object->list.length > 2) {
			// This field is optional (so len must be 3)
			ext->critical = o->sector[0] != 0;
			o = object->list.objects[2];
		}
		if (o && o->tag == RZ_ASN1_TAG_OCTETSTRING) {
			ext->extnValue = rz_asn1_binary_parse(o->sector, o->length);
		}
	}
	return true;
}

static void x509_extension_free(RzX509Extension *ex) {
	if (!ex) {
		return;
	}
	rz_asn1_string_free(ex->extnID);
	rz_asn1_binary_free(ex->extnValue);
	// this is allocated dynamically so, i'll free
	free(ex);
}

static bool x509_extensions_parse(RzX509Extensions *ext, RzASN1Object *object) {
	if (!ext || !object || object->list.length != 1 || !object->list.objects[0]->length) {
		return false;
	}
	object = object->list.objects[0];
	ext->extensions = (RzX509Extension **)calloc(object->list.length, sizeof(RzX509Extension *));
	if (!ext->extensions) {
		return false;
	}
	ext->length = object->list.length;
	for (ut32 i = 0; i < object->list.length; i++) {
		ext->extensions[i] = RZ_NEW0(RzX509Extension);
		if (!x509_extension_parse(ext->extensions[i], object->list.objects[i])) {
			x509_extension_free(ext->extensions[i]);
			ext->extensions[i] = NULL;
		}
	}
	return true;
}

static bool x509_tbscertificate_parse(RzX509TBSCertificate *tbsc, RzASN1Object *object) {
	RzASN1Object **elems;
	ut32 shift = 0;
	if (!tbsc || !object || object->list.length < 6) {
		return false;
	}
	elems = object->list.objects;
	// Following RFC
	if (elems[0] &&
		elems[0]->list.length == 1 &&
		elems[0]->klass == RZ_ASN1_CLASS_CONTEXT &&
		elems[0]->form == RZ_ASN1_FORM_CONSTRUCTED &&
		elems[0]->list.objects[0] &&
		elems[0]->list.objects[0]->tag == RZ_ASN1_TAG_INTEGER &&
		elems[0]->list.objects[0]->length == 1) {
		if (object->list.length < 7) {
			// Always expect at least 7 elements for non-v1 certificates.
			return false;
		}
		// Integer inside a RZ_ASN1_CLASS_CONTEXT
		tbsc->version = (ut32)elems[0]->list.objects[0]->sector[0];
		shift = 1;
	} else {
		tbsc->version = 0;
	}
	if (elems[shift] && elems[shift]->klass == RZ_ASN1_CLASS_UNIVERSAL && elems[shift]->tag == RZ_ASN1_TAG_INTEGER) {
		tbsc->serialNumber = rz_asn1_stringify_integer(elems[shift]->sector, elems[shift]->length);
	}
	rz_x509_algorithmidentifier_parse(&tbsc->signature, elems[shift + 1]);
	rz_x509_name_parse(&tbsc->issuer, elems[shift + 2]);
	rz_x509_validity_parse(&tbsc->validity, elems[shift + 3]);
	rz_x509_name_parse(&tbsc->subject, elems[shift + 4]);
	x509_subjectpublickeyinfo_parse(&tbsc->subjectPublicKeyInfo, elems[shift + 5]);

	if (tbsc->version < 1) {
		return true;
	}

	for (ut32 i = shift + 6; i < object->list.length; i++) {
		if (!elems[i] || elems[i]->klass != RZ_ASN1_CLASS_CONTEXT) {
			continue;
		}
		if (elems[i]->tag == 1) {
			tbsc->issuerUniqueID = rz_asn1_binary_parse(elems[i]->sector, elems[i]->length);
		}
		if (elems[i]->tag == 2) {
			tbsc->subjectUniqueID = rz_asn1_binary_parse(elems[i]->sector, elems[i]->length);
		}
		if (tbsc->version == 2 && elems[i]->tag == 3 && elems[i]->form == RZ_ASN1_FORM_CONSTRUCTED) {
			x509_extensions_parse(&tbsc->extensions, elems[i]);
		}
	}
	return true;
}

/**
 * \brief      Parse a x509 certificate DER encoded from an ASN1 object
 *
 * \param[in]  buffer  The buffer to use
 * \param[in]  length  The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzX509Certificate *rz_x509_certificate_parse(RZ_NULLABLE RzASN1Object *object) {
	if (!object) {
		return NULL;
	}
	RzX509Certificate *cert = RZ_NEW0(RzX509Certificate);
	if (!cert) {
		goto fail;
	}
	if (object->klass != RZ_ASN1_CLASS_UNIVERSAL ||
		object->form != RZ_ASN1_FORM_CONSTRUCTED ||
		object->list.length != 3 ||
		!object->list.objects[0] ||
		!object->list.objects[1] ||
		!object->list.objects[2]) {
		RZ_FREE(cert);
		goto fail;
	}
	RzASN1Object *tmp = object->list.objects[2];
	if (!tmp) {
		RZ_FREE(cert);
		goto fail;
	}
	if (tmp->klass != RZ_ASN1_CLASS_UNIVERSAL || tmp->form != RZ_ASN1_FORM_PRIMITIVE || tmp->tag != RZ_ASN1_TAG_BITSTRING) {
		RZ_FREE(cert);
		goto fail;
	}
	cert->signature = rz_asn1_binary_parse(object->list.objects[2]->sector, object->list.objects[2]->length);
	x509_tbscertificate_parse(&cert->tbsCertificate, object->list.objects[0]);

	if (!rz_x509_algorithmidentifier_parse(&cert->algorithmIdentifier, object->list.objects[1])) {
		RZ_FREE(cert);
	}
fail:
	rz_asn1_object_free(object);
	return cert;
}

/**
 * \brief      Parse a x509 certificate DER encoded
 *
 * \param[in]  buffer  The buffer to use
 * \param[in]  length  The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzX509Certificate *rz_x509_certificate_parse2(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	RzX509Certificate *certificate;
	RzASN1Object *object;
	if (!buffer || !length) {
		return NULL;
	}
	object = rz_asn1_object_parse(buffer, length);
	certificate = rz_x509_certificate_parse(object);
	// object freed by rz_x509_certificate_parse
	return certificate;
}

static RzX509CRLEntry *x509_crlentry_parse(RzASN1Object *object) {
	RzX509CRLEntry *entry;
	if (!object ||
		object->list.length != 2 ||
		!object->list.objects[1] ||
		!object->list.objects[0]) {
		return NULL;
	}
	entry = RZ_NEW0(RzX509CRLEntry);
	if (!entry) {
		return NULL;
	}
	entry->userCertificate = rz_asn1_binary_parse(object->list.objects[0]->sector, object->list.objects[0]->length);
	entry->revocationDate = rz_asn1_stringify_utctime(object->list.objects[1]->sector, object->list.objects[1]->length);
	return entry;
}

/**
 * \brief      Parse a certificate revocation list (or CRL) from an RzASN1Object object
 *
 * \param      object  The object to use to parse the CRL
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzX509CertificateRevocationList *rz_x509_crl_parse(RZ_NULLABLE RzASN1Object *object) {
	RzX509CertificateRevocationList *crl;
	RzASN1Object **elems;
	if (!object || object->list.length < 4) {
		return NULL;
	}
	crl = RZ_NEW0(RzX509CertificateRevocationList);
	if (!crl) {
		return NULL;
	}
	elems = object->list.objects;
	if (!elems || !elems[0] || !elems[1] || !elems[2] || !elems[3]) {
		free(crl);
		return NULL;
	}
	rz_x509_algorithmidentifier_parse(&crl->signature, elems[0]);
	rz_x509_name_parse(&crl->issuer, elems[1]);
	crl->lastUpdate = rz_asn1_stringify_utctime(elems[2]->sector, elems[2]->length);
	crl->nextUpdate = rz_asn1_stringify_utctime(elems[3]->sector, elems[3]->length);
	if (object->list.length > 4 && object->list.objects[4]) {
		crl->revokedCertificates = calloc(object->list.objects[4]->list.length, sizeof(RzX509CRLEntry *));
		if (!crl->revokedCertificates) {
			free(crl);
			return NULL;
		}
		crl->length = object->list.objects[4]->list.length;
		for (ut32 i = 0; i < object->list.objects[4]->list.length; i++) {
			crl->revokedCertificates[i] = x509_crlentry_parse(object->list.objects[4]->list.objects[i]);
		}
	}
	return crl;
}

RZ_IPI void rz_x509_algorithmidentifier_fini(RZ_NULLABLE RzX509AlgorithmIdentifier *ai) {
	if (!ai) {
		return;
	}
	// no need to free ai, since this functions is used internally
	rz_asn1_string_free(ai->algorithm);
	rz_asn1_binary_free(ai->parameters);
}

static void x509_validity_fini(RzX509Validity *validity) {
	if (!validity) {
		return;
	}
	// not freeing validity since it's not allocated dynamically
	rz_asn1_string_free(validity->notAfter);
	rz_asn1_string_free(validity->notBefore);
}

RZ_IPI void rz_x509_name_fini(RZ_NULLABLE RzX509Name *name) {
	// not freeing name since it's not allocated dynamically
	if (!name || !name->names) {
		return;
	}

	for (ut32 i = 0; i < name->length; i++) {
		rz_asn1_string_free(name->oids[i]);
		rz_asn1_string_free(name->names[i]);
	}
	RZ_FREE(name->names);
	RZ_FREE(name->oids);
}

static void x509_extensions_fini(RzX509Extensions *ex) {
	if (!ex) {
		return;
	}
	if (ex->extensions) {
		for (ut32 i = 0; i < ex->length; i++) {
			x509_extension_free(ex->extensions[i]);
		}
		free(ex->extensions);
	}
	// no need to free ex, since this functions is used internally
}

static void x509_subjectpublickeyinfo_fini(RzX509SubjectPublicKeyInfo *spki) {
	if (!spki) {
		return;
	}
	rz_x509_algorithmidentifier_fini(&spki->algorithm);
	rz_asn1_binary_free(spki->subjectPublicKey);
	rz_asn1_binary_free(spki->subjectPublicKeyExponent);
	rz_asn1_binary_free(spki->subjectPublicKeyModule);
	// No need to free spki, since it's a static variable.
}

static void x509_tbscertificate_fini(RzX509TBSCertificate *tbsc) {
	if (!tbsc) {
		return;
	}
	//  version is ut32
	rz_asn1_string_free(tbsc->serialNumber);
	rz_x509_algorithmidentifier_fini(&tbsc->signature);
	rz_x509_name_fini(&tbsc->issuer);
	x509_validity_fini(&tbsc->validity);
	rz_x509_name_fini(&tbsc->subject);
	x509_subjectpublickeyinfo_fini(&tbsc->subjectPublicKeyInfo);
	rz_asn1_binary_free(tbsc->subjectUniqueID);
	rz_asn1_binary_free(tbsc->issuerUniqueID);
	x509_extensions_fini(&tbsc->extensions);
	// no need to free tbsc, since this functions is used internally
}

/**
 * \brief      Frees an RzX509Certificate certificate
 *
 * \param      certificate  The object to use to parse the CRL
 */
RZ_API void rz_x509_certificate_free(RZ_NULLABLE RzX509Certificate *certificate) {
	if (!certificate) {
		return;
	}
	rz_asn1_binary_free(certificate->signature);
	rz_x509_algorithmidentifier_fini(&certificate->algorithmIdentifier);
	x509_tbscertificate_fini(&certificate->tbsCertificate);
	free(certificate);
}

static void x509_crlentry_free(RzX509CRLEntry *entry) {
	if (!entry) {
		return;
	}
	rz_asn1_binary_free(entry->userCertificate);
	rz_asn1_string_free(entry->revocationDate);
	free(entry);
}

RZ_IPI void rz_x509_crl_free(RZ_NULLABLE RzX509CertificateRevocationList *crl) {
	if (!crl) {
		return;
	}
	rz_x509_algorithmidentifier_fini(&crl->signature);
	rz_x509_name_fini(&crl->issuer);
	rz_asn1_string_free(crl->nextUpdate);
	rz_asn1_string_free(crl->lastUpdate);
	if (crl->revokedCertificates) {
		for (ut32 i = 0; i < crl->length; i++) {
			x509_crlentry_free(crl->revokedCertificates[i]);
			crl->revokedCertificates[i] = NULL;
		}
		RZ_FREE(crl->revokedCertificates);
	}
	free(crl);
}

static void x509_crlentry_to_structure(RzStructuredData *parent, RzX509CRLEntry *crle) {
	RzASN1String *m = NULL;
	if (!crle) {
		return;
	}

	if (crle->userCertificate) {
		m = rz_asn1_stringify_integer(crle->userCertificate->binary, crle->userCertificate->length);
		if (m) {
			rz_structured_data_map_add_string(parent, "userCertificate", m->string);
		}
		rz_asn1_string_free(m);
	}

	if (crle->revocationDate) {
		rz_structured_data_map_add_string(parent, "revocationDate", crle->revocationDate->string);
	}
}

RZ_IPI void rz_x509_algorithmidentifier_to_structure(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const RzX509AlgorithmIdentifier *ai) {
	rz_return_if_fail(parent && ai);

	if (ai->algorithm) {
		rz_structured_data_map_add_string(parent, "algorithm", ai->algorithm->string);
	}

	if (!ai->parameters) {
		return;
	}
	RzASN1Object *object = rz_asn1_object_parse(ai->parameters->binary, ai->parameters->length);
	if (object) {
		RzStructuredData *params = rz_asn1_to_structure(object, true);
		rz_asn1_object_free(object);
		rz_structured_data_map_add(parent, "parameters", params);
		return;
	}

	RzASN1String *params = NULL;
	if (rz_str_is_printable_limited((const char *)ai->parameters->binary, ai->parameters->length)) {
		params = rz_asn1_stringify_string(ai->parameters->binary, ai->parameters->length);
	} else {
		params = rz_asn1_stringify_bytes(ai->parameters->binary, ai->parameters->length);
	}

	rz_structured_data_map_add_string(parent, "parameters", params->string);
	rz_asn1_string_free(params);
}

/**
 * \brief      Converts a certificate revocation list (or CRL) into RzStructuredData
 *
 * \param      crl   The crl to convert to a RzStructuredData
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzStructuredData *rz_x509_crl_to_structure(RZ_NULLABLE RzX509CertificateRevocationList *crl) {
	if (!crl) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzASN1String *lastUpdate = crl->lastUpdate;
	RzASN1String *nextUpdate = crl->nextUpdate;

	RzStructuredData *signature = rz_structured_data_map_add_map(root, "signature");
	rz_x509_algorithmidentifier_to_structure(signature, &crl->signature);

	RzStructuredData *issuer = rz_structured_data_map_add_array(root, "issuer");
	rz_x509_name_to_structure(issuer, &crl->issuer);

	if (lastUpdate) {
		rz_structured_data_map_add_string(root, "lastUpdate", lastUpdate->string);
	}
	if (nextUpdate) {
		rz_structured_data_map_add_string(root, "nextUpdate", nextUpdate->string);
	}

	RzStructuredData *revokedCerts = rz_structured_data_map_add_array(root, "revokedCertificates");
	for (ut32 i = 0; i < crl->length; i++) {
		RzStructuredData *revoked = rz_structured_data_array_add_map(revokedCerts);
		x509_crlentry_to_structure(revoked, crl->revokedCertificates[i]);
	}

	return root;
}

static void x509_validity_to_structure(RzStructuredData *parent, RzX509Validity *validity) {
	if (!validity) {
		return;
	}
	if (validity->notBefore) {
		rz_structured_data_map_add_string(parent, "notBefore", validity->notBefore->string);
	}
	if (validity->notAfter) {
		rz_structured_data_map_add_string(parent, "notAfter", validity->notAfter->string);
	}
}

RZ_IPI void rz_x509_name_to_structure(RZ_NULLABLE RzStructuredData *array, RZ_NULLABLE RzX509Name *name) {
	if (!array || !name) {
		return;
	}

	for (ut32 i = 0; i < name->length; i++) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		RzStructuredData *entry = rz_structured_data_array_add_map(array);
		rz_structured_data_map_add_string(entry, "oid", name->oids[i]->string);
		rz_structured_data_map_add_string(entry, "value", name->names[i]->string);
	}
}

static void x509_subjectpublickeyinfo_to_structure(RzStructuredData *parent, RzX509SubjectPublicKeyInfo *spki) {
	RzASN1String *m = NULL;
	if (!spki) {
		return;
	}
	if (spki->algorithm.algorithm) {
		rz_structured_data_map_add_string(parent, "algorithm", spki->algorithm.algorithm->string);
	}

	if (spki->subjectPublicKeyModule && spki->subjectPublicKeyExponent) {
		RzStructuredData *subjectPublicKey = rz_structured_data_map_add_map(parent, "subjectPublicKey");
		m = rz_asn1_stringify_bytes(spki->subjectPublicKeyExponent->binary, spki->subjectPublicKeyExponent->length);
		if (m) {
			rz_structured_data_map_add_string(subjectPublicKey, "exponent", m->string);
		}
		rz_asn1_string_free(m);

		m = rz_asn1_stringify_integer(spki->subjectPublicKeyModule->binary, spki->subjectPublicKeyModule->length);
		if (m) {
			rz_structured_data_map_add_string(subjectPublicKey, "module", m->string);
		}
		rz_asn1_string_free(m);
	} else if (spki->subjectPublicKey) {
		m = rz_asn1_stringify_bytes(spki->subjectPublicKey->binary, spki->subjectPublicKey->length);
		if (m) {
			rz_structured_data_map_add_string(parent, "subjectPublicKey", m->string);
		}
		rz_asn1_string_free(m);
	}
}

static void x509_extensions_to_structure(RzStructuredData *parent, RzX509Extensions *exts) {
	if (!exts) {
		return;
	}

	RzStructuredData *extensions = rz_structured_data_map_add_array(parent, "extensions");
	for (ut32 i = 0; i < exts->length; i++) {
		RzX509Extension *e = exts->extensions[i];
		if (!e) {
			continue;
		}

		RzStructuredData *extension = rz_structured_data_array_add_map(extensions);
		if (e->extnID) {
			rz_structured_data_map_add_string(extension, "extnID", e->extnID->string);
		}
		if (e->critical) {
			rz_structured_data_map_add_boolean(extension, "critical", e->critical);
		}
		if (!e->extnValue) {
			continue;
		}

		RzASN1String *m = NULL;
		const RzASN1Binary *val = e->extnValue;

		if (rz_str_is_printable_limited((const char *)val->binary, val->length)) {
			m = rz_asn1_stringify_string(val->binary, val->length);
		} else if (val->length > 3) {
			RzASN1Object *obj = rz_asn1_object_parse(val->binary, val->length);
			if (obj) {
				RzStructuredData *sd = rz_asn1_to_structure(obj, true);
				rz_asn1_object_free(obj);
				rz_structured_data_map_add(extension, "extnValue", sd);
				continue;
			}
		}

		if (!m && val->length < 20) {
			m = rz_asn1_stringify_integer(val->binary, val->length);
		} else if (!m) {
			m = rz_asn1_stringify_bytes(val->binary, val->length);
		}
		if (m) {
			rz_structured_data_map_add_string(extension, "extnValue", m->string);
		}
		rz_asn1_string_free(m);
	}
}

static void x509_tbscertificate_to_structure(RzStructuredData *parent, RzX509TBSCertificate *tbsc) {
	if (!tbsc) {
		return;
	}

	RzStructuredData *tbs_cert = rz_structured_data_map_add_map(parent, "tbsCertificate");
	if (!tbs_cert) {
		return;
	}

	rz_structured_data_map_add_signed(tbs_cert, "version", tbsc->version + 1);
	if (tbsc->serialNumber) {
		rz_structured_data_map_add_string(tbs_cert, "serialNumber", tbsc->serialNumber->string);
	}

	RzStructuredData *signature = rz_structured_data_map_add_map(tbs_cert, "signature");
	rz_x509_algorithmidentifier_to_structure(signature, &tbsc->signature);
	RzStructuredData *issuer = rz_structured_data_map_add_array(tbs_cert, "issuer");
	rz_x509_name_to_structure(issuer, &tbsc->issuer);
	RzStructuredData *validity = rz_structured_data_map_add_map(tbs_cert, "validity");
	x509_validity_to_structure(validity, &tbsc->validity);
	RzStructuredData *subject = rz_structured_data_map_add_array(tbs_cert, "subject");
	rz_x509_name_to_structure(subject, &tbsc->subject);
	RzStructuredData *subjectPki = rz_structured_data_map_add_map(tbs_cert, "subjectPublicKeyInfo");
	x509_subjectpublickeyinfo_to_structure(subjectPki, &tbsc->subjectPublicKeyInfo);

	if (tbsc->issuerUniqueID) {
		RzASN1String *m = rz_asn1_stringify_integer(tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
		if (m) {
			rz_structured_data_map_add_string(tbs_cert, "issuerUniqueID", m->string);
		}
		rz_asn1_string_free(m);
	}

	if (tbsc->subjectUniqueID) {
		RzASN1String *m = rz_asn1_stringify_integer(tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
		if (m) {
			rz_structured_data_map_add_string(tbs_cert, "subjectUniqueID", m->string);
		}
		rz_asn1_string_free(m);
	}
	x509_extensions_to_structure(tbs_cert, &tbsc->extensions);
}

/**
 * \brief      Converts a certificate to a RzStructuredData
 *
 * \param      certificate  The certificate to convert to RzStructuredData
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzStructuredData *rz_x509_certificate_to_structure(RZ_NULLABLE RzX509Certificate *certificate) {
	if (!certificate) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzASN1String *m = NULL;
	x509_tbscertificate_to_structure(root, &certificate->tbsCertificate);

	RzStructuredData *algorithm_identifier = rz_structured_data_map_add_map(root, "algorithmIdentifier");
	rz_x509_algorithmidentifier_to_structure(algorithm_identifier, &certificate->algorithmIdentifier);

	if (certificate->signature) {
		m = rz_asn1_stringify_bytes(certificate->signature->binary, certificate->signature->length);
		if (m) {
			rz_structured_data_map_add_string(root, "signature", m->string);
		}
		rz_asn1_string_free(m);
	}

	return root;
}
