// SPDX-FileCopyrightText: 2017-2018 deroad <wargio@libero.it>
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

RZ_IPI bool rz_x509_algorithmidentifier_parse(RzX509AlgorithmIdentifier *ai, RzASN1Object *object) {
	rz_return_val_if_fail(ai && object, false);

	if (object->list.length < 1 || !object->list.objects || !is_oid_object(object)) {
		return false;
	}

	ai->algorithm = rz_asn1_stringify_oid(object->list.objects[0]->sector, object->list.objects[0]->length);
	ai->parameters = NULL; // TODO
	// ai->parameters = asn1_stringify_sector (object->list.objects[1]);
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

RZ_IPI bool rz_x509_name_parse(RzX509Name *name, RzASN1Object *object) {
	ut32 i;
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
		for (i = 0; i < object->list.length; i++) {
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
	// this is allocated dinamically so, i'll free
	free(ex);
}

static bool x509_extensions_parse(RzX509Extensions *ext, RzASN1Object *object) {
	ut32 i;
	if (!ext || !object || object->list.length != 1 || !object->list.objects[0]->length) {
		return false;
	}
	object = object->list.objects[0];
	ext->extensions = (RzX509Extension **)calloc(object->list.length, sizeof(RzX509Extension *));
	if (!ext->extensions) {
		return false;
	}
	ext->length = object->list.length;
	for (i = 0; i < object->list.length; i++) {
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
	ut32 i;
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
	if (tbsc->version > 0) {
		for (i = shift + 6; i < object->list.length; i++) {
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
		ut32 i;
		crl->revokedCertificates = calloc(object->list.objects[4]->list.length, sizeof(RzX509CRLEntry *));
		if (!crl->revokedCertificates) {
			free(crl);
			return NULL;
		}
		crl->length = object->list.objects[4]->list.length;
		for (i = 0; i < object->list.objects[4]->list.length; i++) {
			crl->revokedCertificates[i] = x509_crlentry_parse(object->list.objects[4]->list.objects[i]);
		}
	}
	return crl;
}

RZ_IPI void rz_x509_algorithmidentifier_fini(RzX509AlgorithmIdentifier *ai) {
	if (ai) {
		// no need to free ai, since this functions is used internally
		rz_asn1_string_free(ai->algorithm);
		rz_asn1_string_free(ai->parameters);
	}
}

static void x509_validity_fini(RzX509Validity *validity) {
	if (!validity) {
		return;
	}
	// not freeing validity since it's not allocated dinamically
	rz_asn1_string_free(validity->notAfter);
	rz_asn1_string_free(validity->notBefore);
}

RZ_IPI void rz_x509_name_fini(RzX509Name *name) {
	ut32 i;
	if (!name) {
		return;
	}
	if (name->names) {
		for (i = 0; i < name->length; i++) {
			rz_asn1_string_free(name->oids[i]);
			rz_asn1_string_free(name->names[i]);
		}
		RZ_FREE(name->names);
		RZ_FREE(name->oids);
	}
	// not freeing name since it's not allocated dinamically
}

static void x509_extensions_fini(RzX509Extensions *ex) {
	ut32 i;
	if (!ex) {
		return;
	}
	if (ex->extensions) {
		for (i = 0; i < ex->length; i++) {
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

RZ_IPI void rz_x509_crl_free(RzX509CertificateRevocationList *crl) {
	ut32 i;
	if (!crl) {
		return;
	}
	rz_x509_algorithmidentifier_fini(&crl->signature);
	rz_x509_name_fini(&crl->issuer);
	rz_asn1_string_free(crl->nextUpdate);
	rz_asn1_string_free(crl->lastUpdate);
	if (crl->revokedCertificates) {
		for (i = 0; i < crl->length; i++) {
			x509_crlentry_free(crl->revokedCertificates[i]);
			crl->revokedCertificates[i] = NULL;
		}
		RZ_FREE(crl->revokedCertificates);
	}
	free(crl);
}

static void x509_validity_dump(RzX509Validity *validity, const char *pad, RzStrBuf *sb) {
	if (!validity) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	const char *b = validity->notBefore ? validity->notBefore->string : "Missing";
	const char *a = validity->notAfter ? validity->notAfter->string : "Missing";
	rz_strbuf_appendf(sb, "%sNot Before: %s\n%sNot After: %s\n", pad, b, pad, a);
}

RZ_IPI void rz_x509_name_dump(RzX509Name *name, const char *pad, RzStrBuf *sb) {
	ut32 i;
	if (!name) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	for (i = 0; i < name->length; i++) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		rz_strbuf_appendf(sb, "%s%s: %s\n", pad, name->oids[i]->string, name->names[i]->string);
	}
}

static void x509_subjectpublickeyinfo_dump(RzX509SubjectPublicKeyInfo *spki, const char *pad, RzStrBuf *sb) {
	const char *a;
	if (!spki) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	a = spki->algorithm.algorithm ? spki->algorithm.algorithm->string : "Missing";
	RzASN1String *m = NULL;
	if (spki->subjectPublicKeyModule) {
		m = rz_asn1_stringify_integer(spki->subjectPublicKeyModule->binary, spki->subjectPublicKeyModule->length);
	}
	//	RzASN1String* e = rz_asn1_stringify_bytes (spki->subjectPublicKeyExponent->sector, spki->subjectPublicKeyExponent->length);
	//	r = snprintf (buffer, length, "%sAlgorithm: %s\n%sModule: %s\n%sExponent: %u bytes\n%s\n", pad, a, pad, m->string,
	//				pad, spki->subjectPublicKeyExponent->length - 1, e->string);
	rz_strbuf_appendf(sb, "%sAlgorithm: %s\n%sModule: %s\n%sExponent: %u bytes\n", pad, a, pad, m ? m->string : "Missing",
		pad, spki->subjectPublicKeyExponent ? spki->subjectPublicKeyExponent->length - 1 : 0);
	rz_asn1_string_free(m);
	//	rz_asn1_string_free (e);
}

static void x509_extensions_dump(RzX509Extensions *exts, const char *pad, RzStrBuf *sb) {
	ut32 i;
	if (!exts) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	for (i = 0; i < exts->length; i++) {
		RzX509Extension *e = exts->extensions[i];
		if (!e) {
			continue;
		}
		// TODO handle extensions..
		// s = rz_asn1_stringify_bytes (e->extnValue->sector, e->extnValue->length);
		rz_strbuf_appendf(sb, "%s%s: %s\n%s%u bytes\n", pad,
			e->extnID ? e->extnID->string : "Missing",
			e->critical ? "critical" : "",
			pad, e->extnValue ? e->extnValue->length : 0);
		// rz_asn1_string_free (s);
	}
}

static void x509_tbscertificate_dump(RzX509TBSCertificate *tbsc, const char *pad, RzStrBuf *sb) {
	RzASN1String *sid = NULL, *iid = NULL;
	if (!tbsc) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	char *pad2 = rz_str_newf("%s  ", pad);
	if (!pad2) {
		return;
	}
	rz_strbuf_appendf(sb, "%sVersion: v%u\n"
			      "%sSerial Number:\n%s  %s\n"
			      "%sSignature Algorithm:\n%s  %s\n"
			      "%sIssuer:\n",
		pad, tbsc->version + 1,
		pad, pad, tbsc->serialNumber ? tbsc->serialNumber->string : "Missing",
		pad, pad, tbsc->signature.algorithm ? tbsc->signature.algorithm->string : "Missing",
		pad);
	rz_x509_name_dump(&tbsc->issuer, pad2, sb);

	rz_strbuf_appendf(sb, "%sValidity:\n", pad);
	x509_validity_dump(&tbsc->validity, pad2, sb);

	rz_strbuf_appendf(sb, "%sSubject:\n", pad);
	rz_x509_name_dump(&tbsc->subject, pad2, sb);

	rz_strbuf_appendf(sb, "%sSubject Public Key Info:\n", pad);
	x509_subjectpublickeyinfo_dump(&tbsc->subjectPublicKeyInfo, pad2, sb);

	if (tbsc->issuerUniqueID) {
		iid = rz_asn1_stringify_integer(tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
		if (iid) {
			rz_strbuf_appendf(sb, "%sIssuer Unique ID:\n%s  %s", pad, pad, iid->string);
			rz_asn1_string_free(iid);
		}
	}
	if (tbsc->subjectUniqueID) {
		sid = rz_asn1_stringify_integer(tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
		if (sid) {
			rz_strbuf_appendf(sb, "%sSubject Unique ID:\n%s  %s", pad, pad, sid->string);
			rz_asn1_string_free(sid);
		}
	}

	rz_strbuf_appendf(sb, "%sExtensions:\n", pad);
	x509_extensions_dump(&tbsc->extensions, pad2, sb);
	free(pad2);
}

/**
 * \brief      Converts a certificate into a human readable string
 *
 * \param      cert  The certificate to convert
 * \param[in]  pad   The padding to use for the string
 * \param      sb    The RzStrBuf to write to
 */
RZ_API void rz_x509_certificate_dump(RZ_NULLABLE RzX509Certificate *cert, RZ_NULLABLE const char *pad, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(sb);
	RzASN1String *algo = NULL;
	char *pad2;
	if (!cert) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	pad2 = rz_str_newf("%s  ", pad);
	if (!pad2) {
		return;
	}
	rz_strbuf_appendf(sb, "%sTBSCertificate:\n", pad);
	x509_tbscertificate_dump(&cert->tbsCertificate, pad2, sb);

	algo = cert->algorithmIdentifier.algorithm;
	rz_strbuf_appendf(sb, "%sAlgorithm:\n%s%s\n%sSignature: %u bytes\n",
		pad, pad2, algo ? algo->string : "", pad, cert->signature->length);
	free(pad2);
}

static void x509_crlentry_dump(RzX509CRLEntry *crle, const char *pad, RzStrBuf *sb) {
	RzASN1String *id = NULL, *utc = NULL;
	if (!crle) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	utc = crle->revocationDate;
	if (crle->userCertificate) {
		id = rz_asn1_stringify_integer(crle->userCertificate->binary, crle->userCertificate->length);
	}
	rz_strbuf_appendf(sb, "%sUser Certificate:\n%s  %s\n"
			      "%sRevocation Date:\n%s  %s\n",
		pad, pad, id ? id->string : "Missing",
		pad, pad, utc ? utc->string : "Missing");
	rz_asn1_string_free(id);
}

/**
 * \brief      Converts a certificate revocation list (or CRL) into human readable string
 *
 * \param      crl   The crl to convert to a string
 * \param[in]  pad   The padding to use for the spacing
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN char *rz_x509_crl_to_string(RZ_NULLABLE RzX509CertificateRevocationList *crl, RZ_NULLABLE const char *pad) {
	RzASN1String *algo = NULL, *last = NULL, *next = NULL;
	ut32 i;
	char *pad2, *pad3;
	if (!crl) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	pad3 = rz_str_newf("%s    ", pad);
	if (!pad3) {
		return NULL;
	}
	pad2 = pad3 + 2;
	algo = crl->signature.algorithm;
	last = crl->lastUpdate;
	next = crl->nextUpdate;
	RzStrBuf *sb = rz_strbuf_new("");
	rz_strbuf_appendf(sb, "%sCRL:\n%sSignature:\n%s%s\n%sIssuer\n", pad, pad2, pad3,
		algo ? algo->string : "", pad2);
	rz_x509_name_dump(&crl->issuer, pad3, sb);

	rz_strbuf_appendf(sb, "%sLast Update: %s\n%sNext Update: %s\n%sRevoked Certificates:\n",
		pad2, last ? last->string : "Missing",
		pad2, next ? next->string : "Missing", pad2);

	for (i = 0; i < crl->length; i++) {
		x509_crlentry_dump(crl->revokedCertificates[i], pad3, sb);
	}

	free(pad3);
	return rz_strbuf_drain(sb);
}

static void x509_validity_json(PJ *pj, RzX509Validity *validity) {
	if (!validity) {
		return;
	}
	if (validity->notBefore) {
		pj_ks(pj, "NotBefore", validity->notBefore->string);
	}
	if (validity->notAfter) {
		pj_ks(pj, "NotAfter", validity->notAfter->string);
	}
}

RZ_IPI void rz_x509_name_json(PJ *pj, RzX509Name *name) {
	ut32 i;
	for (i = 0; i < name->length; i++) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		pj_ks(pj, name->oids[i]->string, name->names[i]->string);
	}
}

static void x509_subjectpublickeyinfo_json(PJ *pj, RzX509SubjectPublicKeyInfo *spki) {
	RzASN1String *m = NULL;
	if (!spki) {
		return;
	}
	if (spki->algorithm.algorithm) {
		pj_ks(pj, "Algorithm", spki->algorithm.algorithm->string);
	}
	if (spki->subjectPublicKeyModule) {
		m = rz_asn1_stringify_integer(spki->subjectPublicKeyModule->binary, spki->subjectPublicKeyModule->length);
		if (m) {
			pj_ks(pj, "Module", m->string);
		}
		rz_asn1_string_free(m);
	}
	if (spki->subjectPublicKeyExponent) {
		m = rz_asn1_stringify_integer(spki->subjectPublicKeyExponent->binary, spki->subjectPublicKeyExponent->length);
		if (m) {
			pj_ks(pj, "Exponent", m->string);
		}
		rz_asn1_string_free(m);
	}
}

static void x509_extensions_json(PJ *pj, RzX509Extensions *exts) {
	if (!exts) {
		return;
	}

	RzASN1String *m = NULL;
	ut32 i;
	pj_a(pj);
	for (i = 0; i < exts->length; i++) {
		RzX509Extension *e = exts->extensions[i];
		if (!e) {
			continue;
		}
		pj_o(pj);
		if (e->extnID) {
			pj_ks(pj, "OID", e->extnID->string);
		}
		if (e->critical) {
			pj_kb(pj, "Critical", e->critical);
		}
		// TODO handle extensions correctly..
		if (e->extnValue) {
			m = rz_asn1_stringify_integer(e->extnValue->binary, e->extnValue->length);
			if (m) {
				pj_ks(pj, "Value", m->string);
			}
			rz_asn1_string_free(m);
		}
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);
}

static void x509_crlentry_json(PJ *pj, RzX509CRLEntry *crle) {
	RzASN1String *m = NULL;
	if (!crle) {
		return;
	}

	if (crle->userCertificate) {
		m = rz_asn1_stringify_integer(crle->userCertificate->binary, crle->userCertificate->length);
		if (m) {
			pj_ks(pj, "UserCertificate", m->string);
		}
		rz_asn1_string_free(m);
	}
	if (crle->revocationDate) {
		pj_ks(pj, "RevocationDate", crle->revocationDate->string);
	}
}

/**
 * \brief      Converts a certificate revocation list (or CRL) into a json structure
 *
 * \param      pj    The PJ pointer to write to
 * \param      crl   The crl to convert to json
 */
RZ_API void rz_x509_crl_json(RZ_NONNULL PJ *pj, RZ_NULLABLE RzX509CertificateRevocationList *crl) {
	rz_return_if_fail(pj);
	ut32 i;
	if (!crl) {
		return;
	}

	if (crl->signature.algorithm) {
		pj_ks(pj, "Signature", crl->signature.algorithm->string);
	}
	pj_k(pj, "Issuer");
	pj_o(pj);
	rz_x509_name_json(pj, &crl->issuer);
	pj_end(pj);
	if (crl->lastUpdate) {
		pj_ks(pj, "LastUpdate", crl->lastUpdate->string);
	}
	if (crl->nextUpdate) {
		pj_ks(pj, "NextUpdate", crl->nextUpdate->string);
	}
	pj_k(pj, "RevokedCertificates");
	pj_a(pj);
	for (i = 0; i < crl->length; i++) {
		x509_crlentry_json(pj, crl->revokedCertificates[i]);
	}
	pj_end(pj);
}

static void x509_tbscertificate_json(PJ *pj, RzX509TBSCertificate *tbsc) {
	pj_o(pj);
	RzASN1String *m = NULL;
	if (!tbsc) {
		return;
	}

	pj_ki(pj, "Version", tbsc->version + 1);
	if (tbsc->serialNumber) {
		pj_ks(pj, "SerialNumber", tbsc->serialNumber->string);
	}
	if (tbsc->signature.algorithm) {
		pj_ks(pj, "SignatureAlgorithm", tbsc->signature.algorithm->string);
	}
	pj_k(pj, "Issuer");
	pj_o(pj);
	rz_x509_name_json(pj, &tbsc->issuer);
	pj_end(pj);
	pj_k(pj, "Validity");
	pj_o(pj);
	x509_validity_json(pj, &tbsc->validity);
	pj_end(pj);
	pj_k(pj, "Subject");
	pj_o(pj);
	rz_x509_name_json(pj, &tbsc->subject);
	pj_end(pj);
	pj_k(pj, "SubjectPublicKeyInfo");
	pj_o(pj);
	x509_subjectpublickeyinfo_json(pj, &tbsc->subjectPublicKeyInfo);
	pj_end(pj);
	if (tbsc->issuerUniqueID) {
		m = rz_asn1_stringify_integer(tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
		if (m) {
			pj_ks(pj, "IssuerUniqueID", m->string);
		}
		rz_asn1_string_free(m);
	}
	if (tbsc->subjectUniqueID) {
		m = rz_asn1_stringify_integer(tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
		if (m) {
			pj_ks(pj, "SubjectUniqueID", m->string);
		}
		rz_asn1_string_free(m);
	}
	pj_k(pj, "Extensions");
	x509_extensions_json(pj, &tbsc->extensions);
}

/**
 * \brief      Converts a certificate into a json structure
 *
 * \param      pj           The PJ pointer to write to
 * \param      certificate  The certificate to convert to json
 */
RZ_API void rz_x509_certificate_json(RZ_NONNULL PJ *pj, RZ_NULLABLE RzX509Certificate *certificate) {
	rz_return_if_fail(pj);
	if (!certificate) {
		return;
	}
	RzASN1String *m = NULL;
	pj_o(pj);
	pj_k(pj, "TBSCertificate");
	x509_tbscertificate_json(pj, &certificate->tbsCertificate);
	if (certificate->algorithmIdentifier.algorithm) {
		pj_ks(pj, "Algorithm", certificate->algorithmIdentifier.algorithm->string);
	}
	if (certificate->signature) {
		m = rz_asn1_stringify_integer(certificate->signature->binary, certificate->signature->length);
		if (m) {
			pj_ks(pj, "Signature", m->string);
		}
		rz_asn1_string_free(m);
	}
	pj_end(pj);
}
