#ifndef RZ_PKCS7_H
#define RZ_PKCS7_H

#include <rz_util/rz_x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_pkcs7_certificaterevocationlists_t {
	ut32 length;
	RzX509CertificateRevocationList **elements;
} RPKCS7CertificateRevocationLists;

typedef struct rz_pkcs7_extendedcertificatesandcertificates_t {
	ut32 length;
	RzX509Certificate **elements;
} RPKCS7ExtendedCertificatesAndCertificates;

typedef struct rz_pkcs7_digestalgorithmidentifiers_t {
	ut32 length;
	RzX509AlgorithmIdentifier **elements;
} RPKCS7DigestAlgorithmIdentifiers;

typedef struct rz_pkcs7_contentinfo_t {
	RASN1String *contentType; // OID
	RASN1Binary *content; // optional. oid structure definition
} RPKCS7ContentInfo;

typedef struct rz_pkcs7_issuerandserialnumber_t {
	RzX509Name issuer;
	RASN1Binary *serialNumber;
} RPKCS7IssuerAndSerialNumber;

typedef struct rz_pkcs7_attribute_t {
	RASN1String *oid; // OID
	RASN1Binary *data; // optional. oid structure definition
} RPKCS7Attribute;

typedef struct rz_pkcs7_attributes_t {
	ut32 length;
	RPKCS7Attribute **elements;
} RPKCS7Attributes;

typedef struct rz_pkcs7_signerinfo_t {
	ut32 version;
	RPKCS7IssuerAndSerialNumber issuerAndSerialNumber;
	RzX509AlgorithmIdentifier digestAlgorithm;
	RPKCS7Attributes authenticatedAttributes; // Optional
	RzX509AlgorithmIdentifier digestEncryptionAlgorithm;
	RASN1Binary *encryptedDigest;
	RPKCS7Attributes unauthenticatedAttributes; // Optional
} RPKCS7SignerInfo;

typedef struct rz_pkcs7_signerinfos_t {
	ut32 length;
	RPKCS7SignerInfo **elements;
} RPKCS7SignerInfos;

typedef struct rz_pkcs7_signeddata_t {
	ut32 version;
	RPKCS7DigestAlgorithmIdentifiers digestAlgorithms;
	RPKCS7ContentInfo contentInfo;
	RPKCS7ExtendedCertificatesAndCertificates certificates; // Optional
	RPKCS7CertificateRevocationLists crls; // Optional
	RPKCS7SignerInfos signerinfos;
} RPKCS7SignedData;

typedef struct rz_pkcs7_container_t {
	RASN1String *contentType;
	RPKCS7SignedData signedData;
} RCMS;

typedef struct {
	RASN1String *type; // OID
	RASN1Binary *data; // optional.
} SpcAttributeTypeAndOptionalValue;

typedef struct {
	RzX509AlgorithmIdentifier digestAlgorithm;
	RASN1Binary *digest;
} SpcDigestInfo;

typedef struct {
	SpcAttributeTypeAndOptionalValue data;
	SpcDigestInfo messageDigest;
} SpcIndirectDataContent;

RZ_API RZ_OWN RCMS *rz_pkcs7_cms_parse(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API void rz_pkcs7_cms_free(RZ_NULLABLE RCMS *container);
RZ_API RZ_OWN char *rz_pkcs7_cms_to_string(RZ_NULLABLE RCMS *container);
RZ_API RZ_OWN PJ *rz_pkcs7_cms_json(RZ_NULLABLE RCMS *container);
RZ_API RZ_OWN SpcIndirectDataContent *rz_pkcs7_spcinfo_parse(RZ_NONNULL RCMS *cms);
RZ_API void rz_pkcs7_spcinfo_free(RZ_NULLABLE SpcIndirectDataContent *spcinfo);

#ifdef __cplusplus
}
#endif

#endif /* RZ_PKCS7_H */
