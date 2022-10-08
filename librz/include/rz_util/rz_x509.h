#ifndef RZ_X509_H
#define RZ_X509_H

#include <rz_util/rz_asn1.h>
#include <rz_util/rz_pj.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Following RFC 5280
 */

typedef struct rz_x509_validity_t {
	RzASN1String *notBefore;
	RzASN1String *notAfter;
} RzX509Validity;

typedef struct rz_x509_name_t {
	ut32 length;
	RzASN1String **oids;
	RzASN1String **names;
} RzX509Name;

typedef struct rz_x509_algorithmidentifier_t {
	RzASN1String *algorithm; // OBJECT IDENTIFIER
	RzASN1String *parameters; // OPTIONAL
} RzX509AlgorithmIdentifier;

typedef struct rz_x509_authoritykeyidentifier_t {
	RzASN1Binary *keyIdentifier;
	RzX509Name authorityCertIssuer;
	RzASN1Binary *authorityCertSerialNumber;
} RzX509AuthorityKeyIdentifier;

typedef struct rz_x509_subjectpublickeyinfo_t {
	RzX509AlgorithmIdentifier algorithm;
	// This is a bit string, but it encapsulate mod + pubkey
	RzASN1Binary *subjectPublicKey; // BIT STRING
	// Extracted module and exponent from pubkey
	RzASN1Binary *subjectPublicKeyExponent;
	RzASN1Binary *subjectPublicKeyModule;
} RzX509SubjectPublicKeyInfo;

typedef struct rz_x509_extension_t {
	RzASN1String *extnID; // OBJECT IDENTIFIER
	bool critical;
	RzASN1Binary *extnValue; // OCTET STRING
} RzX509Extension;

typedef struct rz_x509_extensions_t {
	ut32 length;
	RzX509Extension **extensions;
} RzX509Extensions;

typedef struct rz_x509_tbscertificate_t {
	ut32 version; // INTEGER
	RzASN1String *serialNumber; // INTEGER
	RzX509AlgorithmIdentifier signature;
	RzX509Name issuer;
	RzX509Validity validity;
	RzX509Name subject;
	RzX509SubjectPublicKeyInfo subjectPublicKeyInfo;
	RzASN1Binary *issuerUniqueID; // BIT STRING
	RzASN1Binary *subjectUniqueID; // BIT STRING
	RzX509Extensions extensions;
} RzX509TBSCertificate;

typedef struct rz_x509_certificate_t {
	RzX509TBSCertificate tbsCertificate;
	RzX509AlgorithmIdentifier algorithmIdentifier;
	RzASN1Binary *signature; // BIT STRING
} RzX509Certificate;

// RFC 1422

typedef struct rz_x509_crlentry {
	RzASN1Binary *userCertificate; // INTEGER ?
	RzASN1String *revocationDate; // UTCTime
} RzX509CRLEntry;

typedef struct rz_x509_certificaterevocationlist {
	RzX509AlgorithmIdentifier signature;
	RzX509Name issuer;
	RzASN1String *lastUpdate; // UTCTime
	RzASN1String *nextUpdate; // UTCTime
	ut32 length;
	RzX509CRLEntry **revokedCertificates;
} RzX509CertificateRevocationList;

RZ_API RZ_OWN RzX509CertificateRevocationList *rz_x509_crl_parse(RZ_NULLABLE RzASN1Object *object);
RZ_API RZ_OWN char *rz_x509_crl_to_string(RZ_NULLABLE RzX509CertificateRevocationList *crl, RZ_NULLABLE const char *pad);
RZ_API void rz_x509_crl_json(RZ_NONNULL PJ *pj, RZ_NULLABLE RzX509CertificateRevocationList *crl);

RZ_API RZ_OWN RzX509Certificate *rz_x509_certificate_parse(RZ_NULLABLE RzASN1Object *object);
RZ_API RZ_OWN RzX509Certificate *rz_x509_certificate_parse2(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API void rz_x509_certificate_free(RZ_NULLABLE RzX509Certificate *certificate);
RZ_API void rz_x509_certificate_json(RZ_NONNULL PJ *pj, RZ_NULLABLE RzX509Certificate *certificate);
RZ_API void rz_x509_certificate_dump(RZ_NULLABLE RzX509Certificate *cert, RZ_NULLABLE const char *pad, RZ_NONNULL RzStrBuf *sb);

#ifdef __cplusplus
}
#endif

#endif /* RZ_X509_H */
