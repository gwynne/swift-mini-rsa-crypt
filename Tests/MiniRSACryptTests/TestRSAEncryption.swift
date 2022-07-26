import Foundation
import XCTest
import MiniRSACrypt

final class TestRSAEncryption: XCTestCase {
    func test_wycheproofPKCS1Vectors() throws {
        try wycheproofTest(jsonName: "rsa_pkcs1_2048_test", testFunction: self.testPKCS1Group)
        try wycheproofTest(jsonName: "rsa_pkcs1_3072_test", testFunction: self.testPKCS1Group)
        try wycheproofTest(jsonName: "rsa_pkcs1_4096_test", testFunction: self.testPKCS1Group)
    }
    
    func test_wycheproofOAEPVectors() throws {
        try wycheproofTest(jsonName: "rsa_oaep_2048_sha1_mgf1sha1_test", testFunction: self.testOAEPGroup)
        try wycheproofTest(jsonName: "rsa_oaep_misc_test",               testFunction: self.testOAEPGroup)
    }
    
    private func getTestKeys(
        der: Data, pem: String, file: StaticString = #filePath, line: UInt = #line
    ) throws -> (_RSA.Encryption.PrivateKey, _RSA.Encryption.PublicKey) {
        let derKey = try _RSA.Encryption.PrivateKey(derRepresentation: der), pemKey = try _RSA.Encryption.PrivateKey(pemRepresentation: pem)
        XCTAssertEqual(derKey.derRepresentation, pemKey.derRepresentation, file: file, line: line)
        XCTAssertEqual(derKey.pemRepresentation, pemKey.pemRepresentation, file: file, line: line)
        return (derKey, derKey.publicKey)
    }
    
    private func testPKCS1Group(_ group: RSAEncryptionPKCS1TestGroup, file: StaticString, line: UInt) throws {
        let (privKey, pubKey) = try self.getTestKeys(der: group.privateKeyDerBytes, pem: group.privateKeyPem, file: file, line: line)
        for test in group.tests {
            let valid: Bool
            do {
                let decryptResult = try privKey.decrypt(test.ciphertextBytes, padding: .insecurePKCS1v1_5)
                let encryptResult = try pubKey.encrypt(test.messageBytes, padding: .insecurePKCS1v1_5)
                let decryptResult2 = try privKey.decrypt(encryptResult.rawRepresentation, padding: .insecurePKCS1v1_5)
                valid = (test.messageBytes == decryptResult.rawRepresentation && decryptResult2.rawRepresentation == decryptResult.rawRepresentation)
            } catch {
                valid = false
            }
            XCTAssertEqual(valid, test.expectedValidity, "test number \(test.tcId) failed, expected \(test.result) but got \(valid)", file: file, line: line)
        }
    }
    
    private func testOAEPGroup(_ group: RSAEncryptionOAEPTestGroup, file: StaticString, line: UInt) throws {
        let (privKey, pubKey) = try self.getTestKeys(der: group.privateKeyDerBytes, pem: group.privateKeyPem, file: file, line: line)
        guard group.sha == "SHA-1", group.mgfSha == "SHA-1" else { return }
        for test in group.tests {
            guard test.label?.isEmpty ?? true else { continue }
            let valid: Bool
            do {
                let decryptResult = try privKey.decrypt(test.ciphertextBytes, padding: .PKCS1_OAEP)
                let encryptResult = try pubKey.encrypt(test.messageBytes, padding: .PKCS1_OAEP)
                let decryptResult2 = try privKey.decrypt(encryptResult.rawRepresentation, padding: .PKCS1_OAEP)
                valid = (test.messageBytes == decryptResult.rawRepresentation && decryptResult2.rawRepresentation == decryptResult.rawRepresentation)
            } catch {
                valid = false
            }
            XCTAssertEqual(valid, test.expectedValidity, "test number \(test.tcId) failed, expected \(test.result) but got \(valid)", file: file, line: line)
        }
    }
}

struct RSAEncryptionPKCS1TestGroup: Codable {
    var privateKeyPem, privateKeyPkcs8: String
    var tests: [RSAEncryptionTest]
    var privateKeyDerBytes: Data { try! Data(hexString: self.privateKeyPkcs8) }
}

struct RSAEncryptionOAEPTestGroup: Codable {
    var privateKeyPem, privateKeyPkcs8, sha, mgfSha: String
    var tests: [RSAEncryptionTest]
    var privateKeyDerBytes: Data { try! Data(hexString: self.privateKeyPkcs8) }
}

struct RSAEncryptionTest: Codable {
    var tcId: Int
    var comment, msg, ct, result: String
    var flags: [String]
    var label: String?
    var messageBytes: Data { try! Data(hexString: self.msg) }
    var ciphertextBytes: Data { try! Data(hexString: self.ct) }
    var expectedValidity: Bool {
        switch self.result {
        case "valid", "acceptable": return true
        case "invalid": return false
        default: fatalError("Unexpected validity")
        }
    }
}
