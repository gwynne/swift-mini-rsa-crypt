#include <CMiniRSACryptBoringSSLShims.h>

BIGNUM *CMiniRSACryptBoringSSLShims_BN_bin2bn(const void *in, size_t len, BIGNUM *ret) {
    return CMiniRSACryptBoringSSL_BN_bin2bn(in, len, ret);
}

size_t CMiniRSACryptBoringSSLShims_BN_bn2bin(const BIGNUM *in, void *out) {
    return CMiniRSACryptBoringSSL_BN_bn2bin(in, out);
}

int CMiniRSACryptBoringSSLShims_RSA_public_encrypt(int flen, const void *from, void *to,
                                             RSA *rsa, int padding) {
    return CMiniRSACryptBoringSSL_RSA_public_encrypt(flen, from, to, rsa, padding);
}

int CMiniRSACryptBoringSSLShims_RSA_private_decrypt(int flen, const void *from, void *to,
                                              RSA *rsa, int padding) {
    return CMiniRSACryptBoringSSL_RSA_private_decrypt(flen, from, to, rsa, padding);
}
