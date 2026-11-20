import Foundation
import LogCollection
import LogFormats
import LogFormatsParsing
import Primitives
import Testing

extension LogFormatsTestSuite {
    static var collectionFlow: TestSuite {
        TestSuite("collection", tags: ["collection", "contract"]) {
            Test("EntriesQuery: defaults and normalization") {
                let query = try EntriesQuery(.init())
                try Expect.equal(query.limit, EntriesQuery.defaultLimit, "query.default-limit")
                try Expect.isNil(query.since, "query.no-since")
                try Expect.isNil(query.match, "query.no-match")

                let filtered = try EntriesQuery(.init(contains: "UDM-SE", field: "UNIFIcategory", value: "Security", limit: 5))
                try Expect.equal(filtered.contains, "udm-se", "query.contains-lowercased")
                try Expect.equal(filtered.match, EntriesQuery.FieldMatch(field: "UNIFIcategory", value: "Security"), "query.match")
                try Expect.equal(filtered.limit, 5, "query.limit")
            }

            Test("EntriesQuery: ISO 8601 with and without fractional seconds; ordered range") {
                let query = try EntriesQuery(.init(since: "2026-11-16T17:00:00Z", until: "2026-11-16T18:00:00.250Z"))
                try Expect.notNil(query.since, "query.since")
                try Expect.notNil(query.until, "query.until-fractional")
                try Expect.equal(
                    violation(try EntriesQuery(.init(since: "2026-11-16T18:00:00Z", until: "2026-11-16T17:00:00Z")))?.0,
                    .custom("log_collection.inverted_range"),
                    "query.inverted"
                )
                let badDate = violation(try EntriesQuery(.init(since: "yesterday")))
                try Expect.equal(badDate?.0, .custom("log_collection.invalid_timestamp"), "query.bad-date")
                try Expect.equal(badDate?.1, [.field("since")], "query.bad-date.path")
            }

            Test("EntriesQuery: limit bounds, pairs and blanks are rejected") {
                try Expect.equal(violation(try EntriesQuery(.init(limit: 0)))?.0, .below_minimum, "query.limit-0")
                try Expect.equal(violation(try EntriesQuery(.init(limit: 2001)))?.0, .above_maximum, "query.limit-2001")
                try Expect.equal(try EntriesQuery(.init(limit: 2000)).limit, 2000, "query.limit-max")
                try Expect.equal(violation(try EntriesQuery(.init(field: "src")))?.1, [.field("value")], "query.field-without-value")
                try Expect.equal(violation(try EntriesQuery(.init(value: "x")))?.1, [.field("field")], "query.value-without-field")
                try Expect.equal(violation(try EntriesQuery(.init(field: " ", value: "x")))?.0, .blank_text, "query.blank-field")
                try Expect.equal(violation(try EntriesQuery(.init(contains: "  ")))?.0, .blank_text, "query.blank-contains")
            }

            Test("EntriesQuery: decoding a request body runs the invariant") {
                let decoded = try JSONDecoder().decode(EntriesQuery.self, from: Data(#"{"field":"UNIFIcategory","value":"System","limit":3}"#.utf8))
                try Expect.equal(decoded.limit, 3, "query.decode")
                try Expect.throwsError("query.decode-invalid") {
                    _ = try JSONDecoder().decode(EntriesQuery.self, from: Data(#"{"limit":9999}"#.utf8))
                }
                try Expect.equal(String(decoding: try JSONEncoder().encode(EntriesQuery(.init(limit: 3))), as: UTF8.self), #"{"limit":3}"#, "query.encode-raw")
            }

            Test("LogEntry: flattens a parsed UniFi CEF line for querying") {
                let raw = Fixture.bsd(Fixture.adminAccessCEF)
                let entry = LogEntry(message: SyslogParser.parse(raw), raw: raw, source: "10.90.30.1", receivedAt: "2026-11-16T17:56:43Z")
                try Expect.equal(entry.format, "rfc3164", "entry.format")
                try Expect.equal(entry.host, "UDM-SE", "entry.host")
                try Expect.isNil(entry.app, "entry.no-app")
                try Expect.equal(entry.severity, "informational", "entry.severity")
                try Expect.equal(entry.payload, "cef", "entry.payload")
                try Expect.equal(entry.fields["cef_name"], "Admin Accessed UniFi Network", "entry.cef-name")
                try Expect.equal(entry.fields["UNIFIcategory"], "System", "entry.category")
                try Expect.equal(entry.fields["UNIFIhost"], "Office UDM Pro", "entry.host-field")
                try Expect.equal(entry.cef?["UNIFIadmin"], "Craig", "entry.cef-typed")
                try Expect.equal(entry.raw, raw, "entry.raw")
            }

            Test("LogEntry and EntriesResponse round-trip through JSON") {
                let raw = Fixture.bsd(Fixture.wifiDisconnectCEF, pri: 13)
                let entry = LogEntry(message: SyslogParser.parse(raw), raw: raw, source: "10.90.30.1", receivedAt: "now")
                let response = EntriesResponse(entries: [entry], truncated: false)
                let decoded = try JSONDecoder().decode(EntriesResponse.self, from: try JSONEncoder().encode(response))
                try Expect.equal(decoded, response, "response.round-trip")
                try Expect.equal(decoded.count, 1, "response.count")
            }

            Test("LogEntry: malformed CEF records the reason") {
                let raw = Fixture.bsd("CEF:0|Ubiquiti|UniFi")
                let entry = LogEntry(message: SyslogParser.parse(raw), raw: raw, source: "s", receivedAt: "t")
                try Expect.equal(entry.payload, "malformed_cef", "entry.malformed")
                try Expect.equal(entry.parse_error, "CEF header needs 7 '|'-separated fields, found 3", "entry.parse-error")
                try Expect.isNil(entry.cef, "entry.no-cef")
            }
        }
    }
}
