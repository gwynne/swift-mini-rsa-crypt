#if !canImport(Security)
@_implementationOnly import CMiniRSACryptBoringSSL
import Foundation

internal enum BIOHelper {
    static func withReadOnlyMemoryBIO<R>(wrapping pointer: UnsafeRawBufferPointer, _ block: (UnsafeMutablePointer<BIO>) throws -> R) rethrows -> R {
        let bio = CMiniRSACryptBoringSSL_BIO_new_mem_buf(pointer.baseAddress, ossl_ssize_t(pointer.count))!
        defer { CMiniRSACryptBoringSSL_BIO_free(bio) }
        return try block(bio)
    }

    static func withReadOnlyMemoryBIO<R>(wrapping pointer: UnsafeBufferPointer<UInt8>, _ block: (UnsafeMutablePointer<BIO>) throws -> R) rethrows -> R {
        let bio = CMiniRSACryptBoringSSL_BIO_new_mem_buf(pointer.baseAddress, ossl_ssize_t(pointer.count))!
        defer { CMiniRSACryptBoringSSL_BIO_free(bio) }
        return try block(bio)
    }

    static func withWritableMemoryBIO<R>(_ block: (UnsafeMutablePointer<BIO>) throws -> R) rethrows -> R {
        let bio = CMiniRSACryptBoringSSL_BIO_new(CMiniRSACryptBoringSSL_BIO_s_mem())!
        defer { CMiniRSACryptBoringSSL_BIO_free(bio) }
        return try block(bio)
    }
}

extension Data {
    init(copyingMemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil, innerLength = 0
        guard CMiniRSACryptBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) == 1 else {
            throw MiniRSACryptError.internalBoringSSLError()
        }
        self = Data(UnsafeBufferPointer(start: innerPointer, count: innerLength))
    }
}

extension String {
    init(copyingUTF8MemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil, innerLength = 0
        guard CMiniRSACryptBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) == 1 else {
            throw MiniRSACryptError.internalBoringSSLError()
        }
        self = String(decoding: UnsafeBufferPointer(start: innerPointer, count: innerLength), as: UTF8.self)
    }
}

extension FixedWidthInteger {
    func withBignumPointer<R>(_ block: (UnsafeMutablePointer<BIGNUM>) throws -> R) rethrows -> R {
        precondition(self.bitWidth <= UInt.bitWidth)
        var bn = BIGNUM()
        CMiniRSACryptBoringSSL_BN_init(&bn)
        defer { CMiniRSACryptBoringSSL_BN_clear(&bn) }
        CMiniRSACryptBoringSSL_BN_set_word(&bn, .init(self))
        return try block(&bn)
    }
}
#endif
