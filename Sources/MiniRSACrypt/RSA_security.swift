import Foundation

#if canImport(Security)
@_implementationOnly import Security

internal struct SecurityRSAPublicKey {
    private var backing: SecKey

    init(pemRepresentation: String) throws {
        let document = try PEMDocument(pemString: pemRepresentation)
        self = try .init(derRepresentation: document.derBytes)
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        let keyAttributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        let data = Data(derRepresentation)
        var error: Unmanaged<CFError>? = nil
        let key = SecKeyCreateWithData(data as CFData, keyAttributes as CFDictionary, &error)

        guard let unwrappedKey = key else {
            // If this returns nil, error must be set.
            throw error!.takeRetainedValue() as Error
        }

        self.backing = unwrappedKey
    }

    var derRepresentation: Data {
        var error: Unmanaged<CFError>? = nil
        let representation = SecKeyCopyExternalRepresentation(self.backing, &error)
        return representation! as Data
    }

    var pemRepresentation: String {
        return PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation).pemString
    }

    var keySizeInBits: Int {
        let attributes = SecKeyCopyAttributes(self.backing)! as NSDictionary
        return (attributes[kSecAttrKeySizeInBits]! as! NSNumber).intValue
    }

    fileprivate init(_ backing: SecKey) {
        self.backing = backing
    }
}


internal struct SecurityRSAPrivateKey {
    private var backing: SecKey

    static let PKCS1KeyType = "RSA PRIVATE KEY"

    static let PKCS8KeyType = "PRIVATE KEY"

    init(pemRepresentation: String) throws {
        let document = try PEMDocument(pemString: pemRepresentation)

        switch document.type {
        case SecurityRSAPrivateKey.PKCS1KeyType:
            // This is what is expected by Security.framework
            self = try .init(derRepresentation: document.derBytes)
        case SecurityRSAPrivateKey.PKCS8KeyType:
            guard let pkcs8Bytes = document.derBytes.pkcs8RSAKeyBytes else {
                throw PEMDocumentError.invalidPEMDocument
            }
            self = try .init(derRepresentation: pkcs8Bytes)
        default:
            throw PEMDocumentError.invalidPEMDocument
        }

    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        let keyAttributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        let data = Data(derRepresentation)
        var error: Unmanaged<CFError>? = nil

        // We can't know in DER if this is PKCS8 or PKCS1 without just trying to decode it.
        let keyData: Data
        if let pkcs8Data = data.pkcs8RSAKeyBytes {
            keyData = pkcs8Data
        } else {
            keyData = data
        }

        let key = SecKeyCreateWithData(keyData as CFData, keyAttributes as CFDictionary, &error)

        guard let unwrappedKey = key else {
            // If this returns nil, error must be set.
            throw error!.takeRetainedValue() as Error
        }

        self.backing = unwrappedKey
    }

    init(keySize: _RSA.Encryption.KeySize) throws {
        let keyAttributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: keySize.bitCount
        ]
        var error: Unmanaged<CFError>? = nil
        let key = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error)

        guard let unwrappedKey = key else {
            // If this returns nil, error must be set.
            throw error!.takeRetainedValue() as Error
        }

        self.backing = unwrappedKey
    }

    var derRepresentation: Data {
        var error: Unmanaged<CFError>? = nil
        let representation = SecKeyCopyExternalRepresentation(self.backing, &error)
        return representation! as Data
    }

    var pemRepresentation: String {
        return PEMDocument(type: SecurityRSAPrivateKey.PKCS1KeyType, derBytes: self.derRepresentation).pemString
    }

    var keySizeInBits: Int {
        let attributes = SecKeyCopyAttributes(self.backing)! as NSDictionary
        return (attributes[kSecAttrKeySizeInBits]! as! NSNumber).intValue
    }

    var publicKey: SecurityRSAPublicKey {
        SecurityRSAPublicKey(SecKeyCopyPublicKey(self.backing)!)
    }
}

extension SecurityRSAPrivateKey {
    internal func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSADecryptedData {
        let algorithm = try SecKeyAlgorithm(padding: padding)
        let dataToDecrypt = Data(data)
        var error: Unmanaged<CFError>? = nil
        let dec = SecKeyCreateDecryptedData(self.backing, algorithm, dataToDecrypt as CFData, &error)
        
        guard let decrypted = dec else {
            throw error!.takeRetainedValue() as Error
        }
        
        return _RSA.Encryption.RSADecryptedData(rawRepresentation: decrypted as Data)
    }
}

extension SecurityRSAPublicKey {
    internal func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> _RSA.Encryption.RSAEncryptedData {
        let algorithm = try SecKeyAlgorithm(padding: padding)
        let dataToEncrypt = Data(data)
        var error: Unmanaged<CFError>? = nil
        let enc = SecKeyCreateEncryptedData(self.backing, algorithm, dataToEncrypt as CFData, &error)
        
        guard let encrypted = enc else {
            throw error!.takeRetainedValue() as Error
        }
        
        return _RSA.Encryption.RSAEncryptedData(rawRepresentation: encrypted as Data)
    }
}

extension SecKeyAlgorithm {
    fileprivate init(padding: _RSA.Encryption.Padding) throws {
        switch padding.backing {
        case .pkcs1v1_5:
            self = .rsaEncryptionPKCS1
        case .pkcs1_oaep:
            self = .rsaEncryptionOAEPSHA1
        }
    }
}

extension Data {
    /// A partial PKCS8 DER prefix. This specifically is the version and private key algorithm identifier.
    private static let partialPKCS8Prefix = Data(
        [
            0x02, 0x01, 0x00,  // Version, INTEGER 0
            0x30, 0x0d,        // SEQUENCE, length 13
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,  // rsaEncryption OID
            0x05, 0x00         // NULL
        ]
    )

    var pkcs8RSAKeyBytes: Data? {
        // This is PKCS8. A bit awkward now. Rather than bring over the fully-fledged ASN.1 code from
        // the main module and all its dependencies, we have a little hand-rolled verifier. To be a proper
        // PKCS8 key, this should match:
        //
        // PrivateKeyInfo ::= SEQUENCE {
        //   version                   Version,
        //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        //   privateKey                PrivateKey,
        //   attributes           [0]  IMPLICIT Attributes OPTIONAL }
        //
        // Version ::= INTEGER
        //
        // PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
        //
        // PrivateKey ::= OCTET STRING
        //
        // Attributes ::= SET OF Attribute
        //
        // We know the version and algorithm identifier, so we can just strip the bytes we'd expect to see here. We do validate
        // them though.
        precondition(self.startIndex == 0)

        guard self.count >= 4 + Data.partialPKCS8Prefix.count + 4 else {
            return nil
        }

        // First byte will be the tag for sequence, 0x30.
        guard self[0] == 0x30 else {
            return nil
        }

        // The next few bytes will be a length. We'll expect it to be 3 bytes long, with the first byte telling us
        // that it's 3 bytes long.
        let lengthLength = Int(self[1])
        guard lengthLength == 0x82 else {
            return nil
        }

        let length = Int(self[2]) << 8 | Int(self[3])
        guard length == self.count - 4 else {
            return nil
        }

        // Now we can check the version through the algorithm identifier against the hardcoded values.
        guard self.dropFirst(4).prefix(Data.partialPKCS8Prefix.count) == Data.partialPKCS8Prefix else {
            return nil
        }

        // Ok, the last check are the next 4 bytes, which should now be the tag for OCTET STRING followed by another length.
        guard self[4 + Data.partialPKCS8Prefix.count] == 0x04,
        self[4 + Data.partialPKCS8Prefix.count + 1] == 0x82 else {
            return nil
        }

        let octetStringLength = Int(self[4 + Data.partialPKCS8Prefix.count + 2]) << 8 |
                                Int(self[4 + Data.partialPKCS8Prefix.count + 3])
        guard octetStringLength == self.count - 4 - Data.partialPKCS8Prefix.count - 4 else {
            return nil
        }

        return self.dropFirst(4 + Data.partialPKCS8Prefix.count + 4)
    }
}

#endif
