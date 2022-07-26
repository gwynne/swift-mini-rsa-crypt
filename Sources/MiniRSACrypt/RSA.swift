import Foundation

#if canImport(Security)
fileprivate typealias BackingPublicKey = SecurityRSAPublicKey
fileprivate typealias BackingPrivateKey = SecurityRSAPrivateKey
#else
fileprivate typealias BackingPublicKey = BoringSSLRSAPublicKey
fileprivate typealias BackingPrivateKey = BoringSSLRSAPrivateKey
#endif

/// Types associated with the RSA algorithm
///
/// RSA is an asymmetric algorithm. In comparison to elliptic-curve equivalents, RSA requires relatively larger
/// key sizes to achieve equivalent security guarantees. These keys are inefficient to transmit and are often slow to
/// compute with, meaning that RSA-based cryptosystems perform poorly in comparison to elliptic-curve based systems.
/// Additionally, several common operating modes of RSA are insecure and unsafe to use.
///
/// When rolling out new cryptosystems, users should avoid RSA and use ECDSA or edDSA instead. RSA
/// support is provided for interoperability with legacy systems.
public enum _RSA { }

extension _RSA {
    public enum Encryption { }
}

extension _RSA.Encryption {
    public struct PublicKey {
        private var backing: BackingPublicKey

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)

            if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 {
                throw MiniRSACryptError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)

            if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 {
                throw MiniRSACryptError.incorrectParameterSize
            }
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public var keySizeInBits: Int {
            self.backing.keySizeInBits
        }

        fileprivate init(_ backing: BackingPublicKey) {
            self.backing = backing
        }
    }
}

extension _RSA.Encryption {
    public struct PrivateKey {
        private var backing: BackingPrivateKey

        /// Construct an RSA private key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)

            if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 {
                throw MiniRSACryptError.incorrectParameterSize
            }
        }

        /// Construct an RSA private key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)

            if self.keySizeInBits < 1024 || self.keySizeInBits % 8 != 0 {
                throw MiniRSACryptError.incorrectParameterSize
            }
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 1024 bits. Callers that want to enforce minimum
        /// key size requirements should validate `keySize` before use.
        public init(keySize: _RSA.Encryption.KeySize) throws {
            guard keySize.bitCount >= 1024 else {
                throw MiniRSACryptError.incorrectParameterSize
            }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public var keySizeInBits: Int {
            self.backing.keySizeInBits
        }

        public var publicKey: _RSA.Encryption.PublicKey {
            _RSA.Encryption.PublicKey(self.backing.publicKey)
        }
    }
}

extension _RSA.Encryption {
    public struct KeySize {
        public let bitCount: Int

        /// RSA key size of 2048 bits
        public static let bits2048 = _RSA.Encryption.KeySize(bitCount: 2048)

        /// RSA key size of 3072 bits
        public static let bits3072 = _RSA.Encryption.KeySize(bitCount: 3072)

        /// RSA key size of 4096 bits
        public static let bits4096 = _RSA.Encryption.KeySize(bitCount: 4096)

        /// RSA key size with a custom number of bits.
        ///
        /// Params:
        ///     - bitsCount: Positive integer that is a multiple of 8.
        public init(bitCount: Int) {
            precondition(bitCount % 8 == 0 && bitCount > 0)
            self.bitCount = bitCount
        }
    }
}

extension _RSA.Encryption {
    public struct RSAEncryptedData: ContiguousBytes {
        public var rawRepresentation: Data
        
        public init<D: DataProtocol>(rawRepresentation: D) {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }
    }
    
    public struct RSADecryptedData: ContiguousBytes {
        public var rawRepresentation: Data
        
        public init<D: DataProtocol>(rawRepresentation: D) {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }
    }
}

extension _RSA.Encryption {
    public struct Padding {
        internal enum Backing {
            case pkcs1v1_5
            case pkcs1_oaep
        }
        
        internal var backing: Backing
        
        private init(_ backing: Backing) {
            self.backing = backing
        }
        
        public static let insecurePKCS1v1_5 = Self(.pkcs1v1_5)
        public static let PKCS1_OAEP = Self(.pkcs1_oaep)
    }
}

extension _RSA.Encryption.PrivateKey {
    public func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSADecryptedData {
        return try self.backing.decrypt(data, padding: padding)
    }
}

extension _RSA.Encryption.PublicKey {
    public func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSAEncryptedData {
        return try self.backing.encrypt(data, padding: padding)
    }
}
