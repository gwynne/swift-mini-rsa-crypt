import Foundation

#if canImport(Security)
@_implementationOnly import Security

internal struct SecurityRSAPublicKey {
    private var backing: SecKey

    init(pemRepresentation: String) throws {
        self = try .init(derRepresentation: PEMDocument(pemString: pemRepresentation).derBytes)
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        var error: Unmanaged<CFError>? = nil
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic], data = Data(derRepresentation)
        let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error)
        guard let unwrappedKey = key else { throw error!.takeRetainedValue() as Error }
        self.backing = unwrappedKey
    }

    var derRepresentation: Data {
        var error: Unmanaged<CFError>? = nil
        return SecKeyCopyExternalRepresentation(self.backing, &error)! as Data
    }
    var pemRepresentation: String { PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation).pemString }
    var keySizeInBits: Int { ((SecKeyCopyAttributes(self.backing)! as NSDictionary)[kSecAttrKeySizeInBits]! as! NSNumber).intValue }
    fileprivate init(_ backing: SecKey) { self.backing = backing }
}


internal struct SecurityRSAPrivateKey {
    private var backing: SecKey

    static let PKCS1KeyType = "RSA PRIVATE KEY"
    static let PKCS8KeyType = "PRIVATE KEY"

    init(pemRepresentation: String) throws {
        let document = try PEMDocument(pemString: pemRepresentation)
        switch document.type {
        case SecurityRSAPrivateKey.PKCS1KeyType: self = try .init(derRepresentation: document.derBytes)
        case SecurityRSAPrivateKey.PKCS8KeyType:
            guard let pkcs8Bytes = document.derBytes.pkcs8RSAKeyBytes else { throw PEMDocumentError.invalidPEMDocument }
            self = try .init(derRepresentation: pkcs8Bytes)
        default: throw PEMDocumentError.invalidPEMDocument
        }
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        var error: Unmanaged<CFError>? = nil
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        let data = Data(derRepresentation), keyData = data.pkcs8RSAKeyBytes ?? data
        let key = SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &error)
        guard let unwrappedKey = key else { throw error!.takeRetainedValue() as Error }
        self.backing = unwrappedKey
    }

    init(keySize: _RSA.Encryption.KeySize) throws {
        var error: Unmanaged<CFError>? = nil
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: keySize.bitCount]
        let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error)
        guard let unwrappedKey = key else { throw error!.takeRetainedValue() as Error }
        self.backing = unwrappedKey
    }

    var derRepresentation: Data {
        var error: Unmanaged<CFError>? = nil
        return SecKeyCopyExternalRepresentation(self.backing, &error)! as Data
    }
    var pemRepresentation: String { PEMDocument(type: SecurityRSAPrivateKey.PKCS1KeyType, derBytes: self.derRepresentation).pemString }
    var keySizeInBits: Int { ((SecKeyCopyAttributes(self.backing)! as NSDictionary)[kSecAttrKeySizeInBits]! as! NSNumber).intValue }
    var publicKey: SecurityRSAPublicKey { SecurityRSAPublicKey(SecKeyCopyPublicKey(self.backing)!) }
}

extension SecurityRSAPrivateKey {
    internal func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        let algorithm = try SecKeyAlgorithm(padding: padding)
        let dataToDecrypt = Data(data)
        var error: Unmanaged<CFError>? = nil
        let dec = SecKeyCreateDecryptedData(self.backing, algorithm, dataToDecrypt as CFData, &error)
        
        guard let decrypted = dec else {
            throw error!.takeRetainedValue() as Error
        }
        
        return decrypted as Data
    }
}

extension SecurityRSAPublicKey {
    internal func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        let algorithm = try SecKeyAlgorithm(padding: padding)
        let dataToEncrypt = Data(data)
        var error: Unmanaged<CFError>? = nil
        let enc = SecKeyCreateEncryptedData(self.backing, algorithm, dataToEncrypt as CFData, &error)
        
        guard let encrypted = enc else {
            throw error!.takeRetainedValue() as Error
        }
        
        return encrypted as Data
    }
}

extension SecKeyAlgorithm {
    fileprivate init(padding: _RSA.Encryption.Padding) throws {
        switch padding.backing {
        case .pkcs1_oaep: self = .rsaEncryptionOAEPSHA1
        }
    }
}

extension Data {
    var pkcs8RSAKeyBytes: Data? {
        precondition(self.startIndex == 0)
        // Version, INTEGER 0; SEQUENCE, length 13; rsaEncryption OID; NULL
        let pkcs8Start = Data([0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
        guard
            self.count >= 8 + pkcs8Start.count, self[0] == 0x30,
            Int(self[1]) == 0x82, (Int(self[2]) << 8 | Int(self[3])) == self.count - 4,
            self.dropFirst(4).prefix(pkcs8Start.count) == pkcs8Start,
            self[4 + pkcs8Start.count] == 0x04, self[5 + pkcs8Start.count] == 0x82,
            Int(self[6 + pkcs8Start.count]) << 8 | Int(self[7 + pkcs8Start.count]) == self.count - 4 - pkcs8Start.count - 4
        else { return nil }
        return self.dropFirst(8 + pkcs8Start.count)
    }
}

#endif
