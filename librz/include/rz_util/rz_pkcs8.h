#ifndef RZ_PKCS8_H
#define RZ_PKCS8_H

#include <rz_util/rz_asn1.h>
#include <rz_util/rz_structured_data.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_PKCS8_VERSION_1 0
#define RZ_PKCS8_VERSION_2 1

typedef struct pkcs8_private_key_algorithm_t {
	RzASN1String *algorithm; ///< OBJECT IDENTIFIER
	RzASN1Binary *parameters; ///< ANY
} RzPKCS8PrivateKeyAlgorithm;

typedef struct private_key_info_t {
	ut32 version;
	RzPKCS8PrivateKeyAlgorithm private_key_algorithm; ///< OBJECT IDENTIFIER
	RzASN1Binary *private_key; ///< OCTET STRING
	RzASN1Binary *public_key; ///< BIT STRING
} RzPrivateKeyInfo;

RZ_API RZ_OWN RzPrivateKeyInfo *rz_pkcs8_private_key_info_parse(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API void rz_pkcs8_private_key_info_free(RZ_NULLABLE RzPrivateKeyInfo *pki);
RZ_API RZ_OWN char *rz_pkcs8_private_key_algorithm(RZ_NONNULL const RzPrivateKeyInfo *pki);
RZ_API RZ_OWN RzStructuredData *rz_pkcs8_private_key_info_to_structure(RZ_NULLABLE const RzPrivateKeyInfo *pki);

#ifdef __cplusplus
}
#endif

#endif /* RZ_PKCS8_H */
