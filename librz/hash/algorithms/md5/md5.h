#ifndef RZ_HASH_MD5_H
#define RZ_HASH_MD5_H

#include <rz_types.h>

#define RZ_HASH_MD5_DIGEST_SIZE  0x10
#define RZ_HASH_MD5_BLOCK_LENGTH 0x40

typedef struct {
	ut32 state[4];
	ut32 count[2];
	ut8 buffer[RZ_HASH_MD5_BLOCK_LENGTH];
} MD5_CTX;

void MD5_Init(MD5_CTX *context);
void MD5_Update(MD5_CTX *context, const ut8 *data, unsigned int length);
void MD5_Final(ut8 *digest, MD5_CTX *context);

#endif /* RZ_HASH_MD5_H */
