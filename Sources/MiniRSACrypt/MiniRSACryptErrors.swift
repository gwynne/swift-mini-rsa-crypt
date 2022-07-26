#if !canImport(Security)
@_implementationOnly import CMiniRSACryptBoringSSL
#endif

public enum MiniRSACryptError: Error {
    case incorrectParameterSize
    case underlyingCryptoError(error: Int32)

#if !canImport(Security)
    @usableFromInline
    static var boringSSLError: MiniRSACryptError {
        .underlyingCryptoError(error: Int32(bitPattern: CMiniRSACryptBoringSSL_ERR_get_error()))
    }
#endif
}
