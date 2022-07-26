import XCTest

struct WycheproofTest<T: Codable>: Codable {
    let algorithm: String
    let numberOfTests: UInt32
    let testGroups: [T]
}

extension XCTestCase {
    func wycheproofTest<T: Codable>(
        jsonName: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        testFunction: (T, StaticString, UInt) throws -> Void
    ) throws {
        let testsDirectory = URL(fileURLWithPath: #filePath.description)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("MiniRSACryptTestVectors", isDirectory: true)
        let fileURL = testsDirectory.appendingPathComponent(jsonName, isDirectory: false).appendingPathExtension("json")
        let data = try Data(contentsOf: fileURL), decoder = JSONDecoder(), wpTest = try decoder.decode(WycheproofTest<T>.self, from: data)

        for group in wpTest.testGroups {
            try testFunction(group, file, line)
        }
    }
}
