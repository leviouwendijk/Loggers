import Testing

private enum LogFormatsTestingFailure: Error {
    case failed
}

@main
struct LogFormatsTestingMain {
    static func main() async throws {
        let reporter = PlainTextTestReporter()
        let result = await TestRunner.run(
            LogFormatsTestSuite.suite,
            sink: reporter
        )
        let rendered = await reporter.rendered()
        if !rendered.isEmpty {
            print(rendered)
        }
        if result.isFailure {
            throw LogFormatsTestingFailure.failed
        }
    }
}

enum LogFormatsTestSuite {
    static let suite = TestSuite(
        "log-formats",
        title: "LogFormats, LogFormatsParsing and LogCollection"
    ) {
        invariantFlow
        priorityFlow
        unifiCEFFlow
        unifiRealFlow
        cefGrammarFlow
        rfc3164Flow
        rfc5424Flow
        keyValueFlow
        robustnessFlow
        collectionFlow
    }
}
