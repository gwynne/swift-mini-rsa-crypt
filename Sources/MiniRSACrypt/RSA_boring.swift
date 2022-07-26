import Foundation

#if !canImport(Security)
@_implementationOnly import CMiniRSACryptBoringSSL
@_implementationOnly import CMiniRSACryptBoringSSLShims

extension _RSA.Encryption.Padding {
    fileprivate var rawBoringSSLPadding: CInt {
        switch self.backing {
        case .pkcs1v1_5: return RSA_PKCS1_PADDING
        case .pkcs1_oaep: return RSA_PKCS1_OAEP_PADDING
        }
    }
}

internal struct BoringSSLRSAPublicKey {
    private var backing: Backing

    init(pemRepresentation: String) throws { self.backing = try Backing(pemRepresentation: pemRepresentation) }
    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws { self.backing = try Backing(derRepresentation: derRepresentation) }
    var derRepresentation: Data { self.backing.derRepresentation }
    var pemRepresentation: String { self.backing.pemRepresentation }
    var keySizeInBits: Int { self.backing.keySizeInBits }
    fileprivate init(_ backing: Backing) { self.backing = backing }
}

internal struct BoringSSLRSAPrivateKey {
    private var backing: Backing

    init(pemRepresentation: String) throws { self.backing = try Backing(pemRepresentation: pemRepresentation) }
    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws { self.backing = try Backing(derRepresentation: derRepresentation) }
    init(keySize: _RSA.Encryption.KeySize) throws { self.backing = try Backing(keySize: keySize) }
    var derRepresentation: Data { self.backing.derRepresentation }
    var pemRepresentation: String { self.backing.pemRepresentation }
    var keySizeInBits: Int { self.backing.keySizeInBits }
    var publicKey: BoringSSLRSAPublicKey { self.backing.publicKey }
}

extension BoringSSLRSAPrivateKey {
    internal func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSADecryptedData {
        try self.backing.decrypt(data, padding: padding)
    }
 }

extension BoringSSLRSAPublicKey {
    internal func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSAEncryptedData {
        try self.backing.encrypt(data, padding: padding)
    }
}

extension BoringSSLRSAPublicKey {
    fileprivate final class Backing {
        private let pointer: UnsafeMutablePointer<RSA>

        fileprivate init(takingOwnershipOf pointer: UnsafeMutablePointer<RSA>) {
            self.pointer = pointer
        }

        fileprivate init(copying other: Backing) {
            self.pointer = CMiniRSACryptBoringSSL_RSAPublicKey_dup(other.pointer)
        }

        fileprivate init(pemRepresentation: String) throws {
            var pemRepresentation = pemRepresentation
            self.pointer = try pemRepresentation.withUTF8 { utf8Ptr in
                try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                    guard let key = CMiniRSACryptBoringSSL_PEM_read_bio_RSA_PUBKEY(bio, nil, nil, nil) else {
                        throw MiniRSACryptError.boringSSLError
                    }
                    return key
                }
            }
        }

        fileprivate convenience init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            if derRepresentation.regions.count == 1 {
                try self.init(contiguousDerRepresentation: derRepresentation.regions.first!)
            } else {
                try self.init(contiguousDerRepresentation: Array(derRepresentation))
            }
        }

        private init<Bytes: ContiguousBytes>(contiguousDerRepresentation: Bytes) throws {
            self.pointer = try contiguousDerRepresentation.withUnsafeBytes { derPtr in
                try BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                    guard let key = CMiniRSACryptBoringSSL_d2i_RSA_PUBKEY_bio(bio, nil) else {
                        throw MiniRSACryptError.boringSSLError
                    }
                    return key
                }
            }
        }

        fileprivate var derRepresentation: Data {
            BIOHelper.withWritableMemoryBIO { bio in
                let rc = CMiniRSACryptBoringSSL_i2d_RSA_PUBKEY_bio(bio, self.pointer)
                precondition(rc == 1)
                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            BIOHelper.withWritableMemoryBIO { bio in
                let rc = CMiniRSACryptBoringSSL_PEM_write_bio_RSA_PUBKEY(bio, self.pointer)
                precondition(rc == 1)
                return try! String(copyingUTF8MemoryBIO: bio)
            }
        }

        fileprivate var keySizeInBits: Int {
            Int(CMiniRSACryptBoringSSL_RSA_size(self.pointer)) * 8
        }

        fileprivate func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSAEncryptedData {
            let outputSize = Int(CMiniRSACryptBoringSSL_RSA_size(self.pointer))
            let output = try Array<UInt8>(unsafeUninitializedCapacity: outputSize) { bufferPtr, length in
                let contiguousData: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                let rc: CInt = contiguousData.withUnsafeBytes { dataPtr in
                    CMiniRSACryptBoringSSLShims_RSA_public_encrypt(
                        CInt(dataPtr.count),
                        dataPtr.baseAddress,
                        bufferPtr.baseAddress,
                        self.pointer,
                        padding.rawBoringSSLPadding
                    )
                }
                guard rc != -1 else { throw MiniRSACryptError.boringSSLError }
                length = Int(rc)
            }
            return _RSA.Encryption.RSAEncryptedData(rawRepresentation: Data(output))
        }

        deinit {
            CMiniRSACryptBoringSSL_RSA_free(self.pointer)
        }
    }
}

extension BoringSSLRSAPrivateKey {
    fileprivate final class Backing {
        private let pointer: UnsafeMutablePointer<RSA>

        fileprivate init(copying other: Backing) {
            self.pointer = CMiniRSACryptBoringSSL_RSAPrivateKey_dup(other.pointer)
        }

        fileprivate init(pemRepresentation: String) throws {
            var pemRepresentation = pemRepresentation
            self.pointer = try pemRepresentation.withUTF8 { utf8Ptr in
                try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                    guard let key = CMiniRSACryptBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil) else {
                        throw MiniRSACryptError.boringSSLError
                    }
                    return key
                }
            }
        }

        fileprivate convenience init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            if derRepresentation.regions.count == 1 {
                try self.init(contiguousDerRepresentation: derRepresentation.regions.first!)
            } else {
                try self.init(contiguousDerRepresentation: Array(derRepresentation))
            }
        }

        private init<Bytes: ContiguousBytes>(contiguousDerRepresentation: Bytes) throws {
            if let pointer = Backing.pkcs8DERPrivateKey(contiguousDerRepresentation) {
                self.pointer = pointer
            } else if let pointer = Backing.pkcs1DERPrivateKey(contiguousDerRepresentation) {
                self.pointer = pointer
            } else {
                throw MiniRSACryptError.boringSSLError
            }
        }

        private static func pkcs8DERPrivateKey<Bytes: ContiguousBytes>(_ derRepresentation: Bytes) -> UnsafeMutablePointer<RSA>? {
            derRepresentation.withUnsafeBytes { derPtr in
                BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                    guard let p8 = CMiniRSACryptBoringSSL_d2i_PKCS8_PRIV_KEY_INFO_bio(bio, nil) else { return nil }
                    defer { CMiniRSACryptBoringSSL_PKCS8_PRIV_KEY_INFO_free(p8) }
                    guard let pkey = CMiniRSACryptBoringSSL_EVP_PKCS82PKEY(p8) else { return nil }
                    defer { CMiniRSACryptBoringSSL_EVP_PKEY_free(pkey) }
                    return CMiniRSACryptBoringSSL_EVP_PKEY_get1_RSA(pkey)
                }
            }
        }

        private static func pkcs1DERPrivateKey<Bytes: ContiguousBytes>(_ derRepresentation: Bytes) -> UnsafeMutablePointer<RSA>? {
            derRepresentation.withUnsafeBytes { derPtr in
                BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { CMiniRSACryptBoringSSL_d2i_RSAPrivateKey_bio($0, nil) }
            }
        }

        fileprivate init(keySize: _RSA.Encryption.KeySize) throws {
            let ptr = CMiniRSACryptBoringSSL_RSA_new()!
            do {
                guard RSA_F4.withBignumPointer({ CMiniRSACryptBoringSSL_RSA_generate_key_ex(ptr, CInt(keySize.bitCount), $0, nil) }) == 1 else {
                    throw MiniRSACryptError.boringSSLError
                }
                self.pointer = ptr
            } catch {
                CMiniRSACryptBoringSSL_RSA_free(ptr)
                throw error
            }
        }

        fileprivate var derRepresentation: Data {
            BIOHelper.withWritableMemoryBIO { bio in
                let rc = CMiniRSACryptBoringSSL_i2d_RSAPrivateKey_bio(bio, self.pointer)
                precondition(rc == 1)
                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            BIOHelper.withWritableMemoryBIO { bio in
                let rc = CMiniRSACryptBoringSSL_PEM_write_bio_RSAPrivateKey(bio, self.pointer, nil, nil, 0, nil, nil)
                precondition(rc == 1)
                return try! String(copyingUTF8MemoryBIO: bio)
            }
        }

        fileprivate var keySizeInBits: Int {
            Int(CMiniRSACryptBoringSSL_RSA_size(self.pointer)) * 8
        }

        fileprivate var publicKey: BoringSSLRSAPublicKey {
            .init(.init(takingOwnershipOf: CMiniRSACryptBoringSSL_RSAPublicKey_dup(self.pointer)))
        }

        fileprivate func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSADecryptedData {
            let outputSize = Int(CMiniRSACryptBoringSSL_RSA_size(self.pointer))
            let output = try Array<UInt8>(unsafeUninitializedCapacity: outputSize) { bufferPtr, length in
                let contiguousData: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                let rc: CInt = contiguousData.withUnsafeBytes { dataPtr in
                    CMiniRSACryptBoringSSLShims_RSA_private_decrypt(
                        CInt(dataPtr.count),
                        dataPtr.baseAddress,
                        bufferPtr.baseAddress,
                        self.pointer,
                        padding.rawBoringSSLPadding
                    )
                }
                guard rc != -1 else { throw MiniRSACryptError.boringSSLError }
                length = Int(rc)
            }
            return _RSA.Encryption.RSADecryptedData(rawRepresentation: Data(output))
        }

        deinit {
            CMiniRSACryptBoringSSL_RSA_free(self.pointer)
        }
    }
}
#endif
