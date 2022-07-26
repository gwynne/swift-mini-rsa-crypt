#if !canImport(Security)
@_implementationOnly import CMiniRSACryptBoringSSL
import Foundation

internal enum BIOHelper {
    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeRawBufferPointer, _ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CMiniRSACryptBoringSSL_BIO_new_mem_buf(pointer.baseAddress, CInt(pointer.count))!
        defer {
            CMiniRSACryptBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeBufferPointer<UInt8>, _ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CMiniRSACryptBoringSSL_BIO_new_mem_buf(pointer.baseAddress, CInt(pointer.count))!
        defer {
            CMiniRSACryptBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withWritableMemoryBIO<ReturnValue>(_ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue) rethrows -> ReturnValue {
        let bio = CMiniRSACryptBoringSSL_BIO_new(CMiniRSACryptBoringSSL_BIO_s_mem())!
        defer {
            CMiniRSACryptBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }
}

extension Data {
    init(copyingMemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CMiniRSACryptBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw MiniRSACryptError.internalBoringSSLError()
        }

        self = Data(UnsafeBufferPointer(start: innerPointer, count: innerLength))
    }
}

extension String {
    init(copyingUTF8MemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CMiniRSACryptBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw MiniRSACryptError.internalBoringSSLError()
        }

        self = String(decoding: UnsafeBufferPointer(start: innerPointer, count: innerLength), as: UTF8.self)
    }
}

extension FixedWidthInteger {
    func withBignumPointer<ReturnType>(_ block: (UnsafeMutablePointer<BIGNUM>) throws -> ReturnType) rethrows -> ReturnType {
        precondition(self.bitWidth <= UInt.bitWidth)

        var bn = BIGNUM()
        CMiniRSACryptBoringSSL_BN_init(&bn)
        defer {
            CMiniRSACryptBoringSSL_BN_clear(&bn)
        }

        CMiniRSACryptBoringSSL_BN_set_word(&bn, .init(self))

        return try block(&bn)
    }
}
#endif
