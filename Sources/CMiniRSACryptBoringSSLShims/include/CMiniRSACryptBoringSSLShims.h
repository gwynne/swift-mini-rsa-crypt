#ifndef C_MINI_RSA_CRYPT_BORINGSSL_SHIMS_H
#define C_MINI_RSA_CRYPT_BORINGSSL_SHIMS_H

#include <CMiniRSACryptBoringSSL.h>

BIGNUM *CMiniRSACryptBoringSSLShims_BN_bin2bn(const void *in, size_t len, BIGNUM *ret);
size_t CMiniRSACryptBoringSSLShims_BN_bn2bin(const BIGNUM *in, void *out);
int CMiniRSACryptBoringSSLShims_RSA_public_encrypt(int flen, const void *from, void *to, RSA *rsa, int padding);
int CMiniRSACryptBoringSSLShims_RSA_private_decrypt(int flen, const void *from, void *to, RSA *rsa, int padding);

#endif  // C_MINI_RSA_CRYPT_BORINGSSL_SHIMS_H
