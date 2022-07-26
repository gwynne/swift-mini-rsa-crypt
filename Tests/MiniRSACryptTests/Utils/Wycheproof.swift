import XCTest

struct WycheproofTest<T: Codable>: Codable {
    let algorithm: String
    let numberOfTests: UInt32
    let testGroups: [T]
}

extension XCTestCase {
    func wycheproofTest<T: Codable>(jsonName: String, file: StaticString = #file, line: UInt = #line, testFunction: (T) throws -> Void) throws {
        let testsDirectory: String = URL(fileURLWithPath: "\(#file)").pathComponents.dropLast(3).joined(separator: "/")
        let fileURL: URL? = URL(fileURLWithPath: "\(testsDirectory)/MiniRSACryptTestVectors/\(jsonName).json")

        let data = try Data(contentsOf: fileURL!)

        let decoder = JSONDecoder()
        let wpTest = try decoder.decode(WycheproofTest<T>.self, from: data)

        for group in wpTest.testGroups {
            try testFunction(group)
        }
    }
}
