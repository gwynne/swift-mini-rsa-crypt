import Foundation

#if canImport(Security)
fileprivate typealias BackingPublicKey = SecurityRSAPublicKey
fileprivate typealias BackingPrivateKey = SecurityRSAPrivateKey
#else
fileprivate typealias BackingPublicKey = BoringSSLRSAPublicKey
fileprivate typealias BackingPrivateKey = BoringSSLRSAPrivateKey
#endif

/// support is provided for interoperability with legacy systems.
public enum _RSA {
    public enum Encryption {
        public struct PublicKey {
            private var backing: BackingPublicKey

            public init(pemRepresentation: String) throws {
                self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)
                if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 { throw MiniRSACryptError.incorrectParameterSize }
            }

            public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
                self.backing = try BackingPublicKey(derRepresentation: derRepresentation)
                if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 { throw MiniRSACryptError.incorrectParameterSize }
            }

            public func encrypt<D: DataProtocol>(_ data: D, padding: Padding) throws -> RSAEncryptedData {
                try self.backing.encrypt(data, padding: padding)
            }

            public var derRepresentation: Data { self.backing.derRepresentation }
            public var pemRepresentation: String { self.backing.pemRepresentation }
            public var keySizeInBits: Int { self.backing.keySizeInBits }
            fileprivate init(_ backing: BackingPublicKey) { self.backing = backing }
        }

        public struct PrivateKey {
            private var backing: BackingPrivateKey

            public init(pemRepresentation: String) throws {
                self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)
                if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 { throw MiniRSACryptError.incorrectParameterSize }
            }

            public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
                self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)
                if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 { throw MiniRSACryptError.incorrectParameterSize }
            }

            public init(keySize: KeySize) throws {
                guard keySize.bitCount >= 1024 else { throw MiniRSACryptError.incorrectParameterSize }
                self.backing = try BackingPrivateKey(keySize: keySize)
            }

            public func decrypt<D: DataProtocol>(_ data: D, padding: Padding) throws -> RSADecryptedData {
                try self.backing.decrypt(data, padding: padding)
            }

            public var derRepresentation: Data { self.backing.derRepresentation }
            public var pemRepresentation: String { self.backing.pemRepresentation }
            public var keySizeInBits: Int { self.backing.keySizeInBits }
            public var publicKey: PublicKey { PublicKey(self.backing.publicKey) }
        }

        public struct KeySize {
            public let bitCount: Int

            public static let bits2048 = Self(bitCount: 2048)
            public static let bits3072 = Self(bitCount: 3072)
            public static let bits4096 = Self(bitCount: 4096)

            public init(bitCount: Int) {
                precondition(bitCount % 8 == 0 && bitCount > 0)
                self.bitCount = bitCount
            }
        }

        public struct RSAEncryptedData: ContiguousBytes {
            public var rawRepresentation: Data
            
            public init<D: DataProtocol>(rawRepresentation: D) { self.rawRepresentation = Data(rawRepresentation) }
            public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try self.rawRepresentation.withUnsafeBytes(body) }
        }
        
        public struct RSADecryptedData: ContiguousBytes {
            public var rawRepresentation: Data
            
            public init<D: DataProtocol>(rawRepresentation: D) { self.rawRepresentation = Data(rawRepresentation) }
            public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try self.rawRepresentation.withUnsafeBytes(body) }
        }

        public struct Padding {
            internal enum Backing { case pkcs1v1_5, pkcs1_oaep }
            internal var backing: Backing
            private init(_ backing: Backing) { self.backing = backing }
            
            public static let insecurePKCS1v1_5 = Self(.pkcs1v1_5)
            public static let PKCS1_OAEP = Self(.pkcs1_oaep)
        }
    }
}
