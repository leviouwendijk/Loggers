import Foundation
import Loggers
import Testing

private enum StandardLoggerTestingFailure: Error {
    case failed
}

@main
struct StandardLoggerTestingMain {
    static func main() async throws {
        let reporter = PlainTextTestReporter()
        let result = await TestRunner.run(
            StandardLoggerTestSuite.suite,
            sink: reporter
        )
        let rendered = await reporter.rendered()
        if !rendered.isEmpty {
            print(rendered)
        }
        if result.isFailure {
            throw StandardLoggerTestingFailure.failed
        }
    }
}

enum StandardLoggerTestSuite {
    static let suite = TestSuite(
        "standard-logger",
        title: "StandardLogger file writes"
    ) {
        Test("two writers on one file keep every line") {
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("standard-logger-\(UUID().uuidString).log")
            defer { try? FileManager.default.removeItem(at: url) }

            // Two handles on one file, like two services sharing activity logs.
            let first = try StandardLogger(logFileURL: url)
            let second = try StandardLogger(logFileURL: url)

            for index in 0..<50 {
                await first.log("first \(index)")
                await second.log("second \(index)")
            }

            let lines = try String(contentsOf: url, encoding: .utf8)
                .split(separator: "\n")

            try Expect.equal(lines.count, 100, "logger.all-lines-kept")
            try Expect.equal(lines.filter { $0.hasSuffix("first 49") }.count, 1, "logger.first-writer-kept")
            try Expect.equal(lines.filter { $0.hasSuffix("second 49") }.count, 1, "logger.second-writer-kept")
            try Expect.true(lines.allSatisfy { $0.hasPrefix("[") }, "logger.no-torn-lines")
        }

        Test("an external truncate is followed, not padded") {
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("standard-logger-\(UUID().uuidString).log")
            defer { try? FileManager.default.removeItem(at: url) }

            let logger = try StandardLogger(logFileURL: url)
            await logger.log("before rotation")

            // What a rotation job does: copy away, then truncate in place.
            try Data().write(to: url)
            await logger.log("after rotation")

            let text = try String(contentsOf: url, encoding: .utf8)
            try Expect.true(text.hasPrefix("["), "logger.no-null-padding")
            try Expect.equal(text.split(separator: "\n").count, 1, "logger.only-new-line")
        }
    }
}
