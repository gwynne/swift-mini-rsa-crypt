import Foundation

#if canImport(Security)
fileprivate typealias BackingPublicKey = SecurityRSAPublicKey
fileprivate typealias BackingPrivateKey = SecurityRSAPrivateKey
#else
fileprivate typealias BackingPublicKey = BoringSSLRSAPublicKey
fileprivate typealias BackingPrivateKey = BoringSSLRSAPrivateKey
#endif

/// support is provided for interoperability with legacy systems.
#if swift(>=5.8)
@_documentation(visibility: public)
public enum _RSA { public enum Encryption {} }
#else
public enum _RSA { public enum Encryption {} }
#endif

extension _RSA.Encryption {
    public struct PublicKey {
        private var backing: BackingPublicKey
        
        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw MiniRSACryptError.incorrectParameterSize }
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw MiniRSACryptError.incorrectParameterSize }
        }

        public var derRepresentation: Data { self.backing.derRepresentation }
        public var pemRepresentation: String { self.backing.pemRepresentation }
        public var keySizeInBits: Int { self.backing.keySizeInBits }
        fileprivate init(_ backing: BackingPublicKey) { self.backing = backing }
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

    /// Identical to ``_RSA/Signing/PrivateKey``.
    public struct PrivateKey {
        private var backing: BackingPrivateKey

        /// Construct an RSA private key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw MiniRSACryptError.incorrectParameterSize }
        }

        /// Construct an RSA private key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw MiniRSACryptError.incorrectParameterSize }
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 1024 bits. Callers that want to enforce minimum
        /// key size requirements should validate `keySize` before use.
        public init(keySize: _RSA.Encryption.KeySize) throws {
            guard keySize.bitCount >= 1024 else { throw MiniRSACryptError.incorrectParameterSize }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }
        
        public var derRepresentation: Data { self.backing.derRepresentation }
        public var pemRepresentation: String { self.backing.pemRepresentation }
        public var keySizeInBits: Int { self.backing.keySizeInBits }
        public var publicKey: _RSA.Encryption.PublicKey { .init(self.backing.publicKey) }
    }
}

extension _RSA.Encryption {
    public struct Padding {
        internal enum Backing {
            case pkcs1_oaep
        }
        
        internal var backing: Backing
        
        private init(_ backing: Backing) {
            self.backing = backing
        }
        
        /// PKCS#1 OAEP padding
        ///
        /// As defined by [RFC 8017 § 7.1](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
        public static let PKCS1_OAEP = Self(.pkcs1_oaep)
    }
}

extension _RSA.Encryption.PrivateKey {
    /// Decrypt a message encrypted with this key's public key and using the specified padding mode.
    ///
    /// > Important: The size of the data to decrypt must be equal to the block size of the key (e.g.
    ///   `keySizeInBits / 8`). Attempting to decrypt data of the wrong size will fail.
    public func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.decrypt(data, padding: padding)
    }
}

extension _RSA.Encryption.PublicKey {
    /// Return the maximum amount of data in bytes this key can encrypt in a single operation when using
    /// the specified padding mode.
    ///
    /// ## Common values:
    ///
    /// Key size|Padding|Max length
    /// -|-|-
    /// 2048|PKCS-OAEP|214 bytes
    /// 3072|PKCS-OAEP|342 bytes
    /// 4096|PKCS-OAEP|470 bytes
    public func maximumEncryptSize(with padding: _RSA.Encryption.Padding) -> Int {
        switch padding.backing {
        case .pkcs1_oaep:
            return (self.keySizeInBits / 8) - 42
        }
    }
    
    /// Encrypt a message with this key, using the specified padding mode.
    ///
    /// > Important: The size of the data to encrypt _must_ not exceed the modulus of the key (e.g.
    ///   `keySizeInBits / 8`), minus any additional space required by the padding mode. Attempting to
    ///   encrypt data larger than this will fail. Use ``maximumEncryptSize(with:)`` to determine
    ///   exactly how many bytes can be encrypted by the key.
    public func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.encrypt(data, padding: padding)
    }
}
