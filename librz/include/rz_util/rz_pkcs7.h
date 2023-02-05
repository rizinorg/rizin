#ifndef RZ_PKCS7_H
#define RZ_PKCS7_H

#include <rz_util/rz_x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_pkcs7_certificaterevocationlists_t {
	ut32 length;
	RzX509CertificateRevocationList **elements;
} RzPKCS7CertificateRevocationLists;

typedef struct rz_pkcs7_extendedcertificatesandcertificates_t {
	ut32 length;
	RzX509Certificate **elements;
} RzPKCS7ExtendedCertificatesAndCertificates;

typedef struct rz_pkcs7_digestalgorithmidentifiers_t {
	ut32 length;
	RzX509AlgorithmIdentifier **elements;
} RzPKCS7DigestAlgorithmIdentifiers;

typedef struct rz_pkcs7_contentinfo_t {
	RzASN1String *contentType; // OID
	RzASN1Binary *content; // optional. oid structure definition
} RzPKCS7ContentInfo;

typedef struct rz_pkcs7_issuerandserialnumber_t {
	RzX509Name issuer;
	RzASN1Binary *serialNumber;
} RzPKCS7IssuerAndSerialNumber;

typedef struct rz_pkcs7_attribute_t {
	RzASN1String *oid; // OID
	RzASN1Binary *data; // optional. oid structure definition
} RzPKCS7Attribute;

typedef struct rz_pkcs7_attributes_t {
	ut32 length;
	RzPKCS7Attribute **elements;
} RzPKCS7Attributes;

typedef struct rz_pkcs7_signerinfo_t {
	ut32 version;
	RzPKCS7IssuerAndSerialNumber issuerAndSerialNumber;
	RzX509AlgorithmIdentifier digestAlgorithm;
	RzPKCS7Attributes authenticatedAttributes; // Optional
	RzX509AlgorithmIdentifier digestEncryptionAlgorithm;
	RzASN1Binary *encryptedDigest;
	RzPKCS7Attributes unauthenticatedAttributes; // Optional
} RzPKCS7SignerInfo;

typedef struct rz_pkcs7_signerinfos_t {
	ut32 length;
	RzPKCS7SignerInfo **elements;
} RzPKCS7SignerInfos;

typedef struct rz_pkcs7_signeddata_t {
	ut32 version;
	RzPKCS7DigestAlgorithmIdentifiers digestAlgorithms;
	RzPKCS7ContentInfo contentInfo;
	RzPKCS7ExtendedCertificatesAndCertificates certificates; // Optional
	RzPKCS7CertificateRevocationLists crls; // Optional
	RzPKCS7SignerInfos signerinfos;
} RzPKCS7SignedData;

typedef struct rz_pkcs7_container_t {
	RzASN1String *contentType;
	RzPKCS7SignedData signedData;
} RzCMS;

typedef struct rz_cms_attribute_type_optional_value_t {
	RzASN1String *type; // OID
	RzASN1Binary *data; // optional.
} RzSpcAttributeTypeAndOptionalValue;

typedef struct rz_cms_digest_info_t {
	RzX509AlgorithmIdentifier digestAlgorithm;
	RzASN1Binary *digest;
} RzSpcDigestInfo;

typedef struct rz_cms_indirect_data_content_t {
	RzSpcAttributeTypeAndOptionalValue data;
	RzSpcDigestInfo messageDigest;
} RzSpcIndirectDataContent;

RZ_API RZ_OWN RzCMS *rz_pkcs7_cms_parse(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API void rz_pkcs7_cms_free(RZ_NULLABLE RzCMS *container);
RZ_API RZ_OWN char *rz_pkcs7_cms_to_string(RZ_NULLABLE RzCMS *container);
RZ_API void rz_pkcs7_cms_json(RZ_NULLABLE RzCMS *container, RZ_NONNULL PJ *pj);
RZ_API RZ_OWN RzSpcIndirectDataContent *rz_pkcs7_spcinfo_parse(RZ_NONNULL RzCMS *cms);
RZ_API void rz_pkcs7_spcinfo_free(RZ_NULLABLE RzSpcIndirectDataContent *spcinfo);

#ifdef __cplusplus
}
#endif

#endif /* RZ_PKCS7_H */
