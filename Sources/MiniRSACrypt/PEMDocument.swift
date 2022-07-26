import Foundation

enum PEMDocumentError: Error {
    case invalidPEMDocument
}

/// A PEM document is some data, and a discriminator type that is used to advertise the content.
struct PEMDocument {
    private static let lineLength = 64

    var type: String
    var derBytes: Data
    
    init(type: String, derBytes: Data) { (self.type, self.derBytes) = (type, derBytes) }

    init(pemString: String) throws {
        let allLines = pemString.split { $0.isNewline }[...]
        guard let first = allLines.first, let last = allLines.last,
              let discriminator = first.pemStartDiscriminator, discriminator == last.pemEndDiscriminator,
              let lines = Optional.some(allLines.dropFirst().dropLast()), !lines.isEmpty,
              lines.dropLast().allSatisfy({ $0.utf8.count == PEMDocument.lineLength }), lines.last!.utf8.count <= PEMDocument.lineLength,
              let derBytes = Data(base64Encoded: lines.joined())
        else {
            throw PEMDocumentError.invalidPEMDocument
        }

        self.type = discriminator
        self.derBytes = derBytes
    }

    var pemString: String {
        var encoded = self.derBytes.base64EncodedString()[...],  pemLines = [Substring]()
        let pemLineCount = (encoded.utf8.count + PEMDocument.lineLength) / PEMDocument.lineLength
        pemLines.reserveCapacity(pemLineCount + 2)
        pemLines.append("-----BEGIN \(self.type)-----")
        while !encoded.isEmpty {
            let prefixIndex = encoded.index(encoded.startIndex, offsetBy: PEMDocument.lineLength, limitedBy: encoded.endIndex) ?? encoded.endIndex
            pemLines.append(encoded[..<prefixIndex])
            encoded = encoded[prefixIndex...]
        }
        pemLines.append("-----END \(self.type)-----")
        return pemLines.joined(separator: "\n")
    }
}

extension Substring {
    fileprivate var pemStartDiscriminator: String? { self.pemDiscriminator(expectedPrefix: "-----BEGIN ", expectedSuffix: "-----") }
    fileprivate var pemEndDiscriminator: String? { self.pemDiscriminator(expectedPrefix: "-----END ", expectedSuffix: "-----") }

    private func pemDiscriminator(expectedPrefix: String, expectedSuffix: String) -> String? {
        var utf8Bytes = self.utf8[...]
        let prefixSize = expectedPrefix.utf8.count, suffixSize = expectedSuffix.utf8.count
        let prefix = utf8Bytes.prefix(prefixSize)
        utf8Bytes = utf8Bytes.dropFirst(prefixSize)
        let suffix = utf8Bytes.suffix(suffixSize)
        utf8Bytes = utf8Bytes.dropLast(suffixSize)

        guard prefix.elementsEqual(expectedPrefix.utf8), suffix.elementsEqual(expectedSuffix.utf8) else { return nil }
        return String(utf8Bytes)
    }
}
