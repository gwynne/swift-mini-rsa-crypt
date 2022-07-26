#if !canImport(Security)
@_implementationOnly import CMiniRSACryptBoringSSL
#endif

public enum MiniRSACryptError: Error {
    case incorrectParameterSize
    case underlyingCoreCryptoError(error: Int32)

#if !canImport(Security)
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    static func internalBoringSSLError() -> MiniRSACryptError {
        return .underlyingCoreCryptoError(error: Int32(bitPattern: CMiniRSACryptBoringSSL_ERR_get_error()))
    }
#endif
}
