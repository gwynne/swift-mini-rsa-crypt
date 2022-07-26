import Foundation

enum ByteHexEncodingErrors: Error { case incorrectHexValue }

let charA = UInt8(UnicodeScalar("a").value), char0 = UInt8(UnicodeScalar("0").value)

private func htoi(_ value: UInt8) throws -> UInt8 {
    switch value {
    case char0...char0 + 9: return value - char0
    case charA...charA + 5: return value - charA + 10
    default: throw ByteHexEncodingErrors.incorrectHexValue
    }
}

extension Data {
    init(hexString: String) throws {
        self.init()
        guard !hexString.isEmpty else { return }
        guard hexString.utf8.count % 2 == 0 else { throw ByteHexEncodingErrors.incorrectHexValue }
        let stringBytes = hexString.utf8; var iter = stringBytes.makeIterator()
        while let c1 = iter.next() {
            guard let c2 = iter.next() else { throw ByteHexEncodingErrors.incorrectHexValue }
            try self.append(htoi(c1) << 4 + htoi(c2))
        }
    }
}
