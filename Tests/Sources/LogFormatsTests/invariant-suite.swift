import Foundation
import LogFormats
import Primitives
import Testing

extension LogFormatsTestSuite {
    static var invariantFlow: TestSuite {
        TestSuite("invariants", tags: ["invariant"]) {
            Test("KeyValuePair: valid keys construct; raw round-trips") {
                let pair = try kv("UNIFIhost", "Office UDM Pro")
                try Expect.equal(pair.raw, KeyValuePair.Raw(key: "UNIFIhost", value: "Office UDM Pro"), "kv.raw")
                try Expect.equal(try KeyValuePair(pair.raw), pair, "kv.reconstruct")
                try Expect.equal(try kv("k", "").value, "", "kv.empty-value")
            }

            Test("KeyValuePair: blank, too long, and forbidden characters are rejected with paths") {
                let blank = violation(try KeyValuePair("", "v"))
                try Expect.equal(blank?.0, .blank_text, "kv.blank.code")
                try Expect.equal(blank?.1, [.field("key")], "kv.blank.path")

                let long = violation(try KeyValuePair(String(repeating: "k", count: 65), "v"))
                try Expect.equal(long?.0, .length_above_maximum, "kv.long")
                try Expect.isNil(violation(try KeyValuePair(String(repeating: "k", count: 64), "v")), "kv.max-length-ok")

                for bad in ["a b", "a=b", "a\"b", "a]b", "a\tb"] {
                    try Expect.equal(violation(try KeyValuePair(bad, "v"))?.0, .custom("log_formats.invalid_key_character"), "kv.char.\(bad)")
                }
            }

            Test("SyslogPriority: 0...191 only; derived facility and severity") {
                try Expect.equal(try SyslogPriority(0).severity, .emergency, "pri.0")
                try Expect.equal(try SyslogPriority(191).facility, 23, "pri.191")
                try Expect.equal(violation(try SyslogPriority(-1))?.0, .below_minimum, "pri.-1")
                try Expect.equal(violation(try SyslogPriority(192))?.0, .above_maximum, "pri.192")
                try Expect.equal(violation(try SyslogPriority(192))?.1, [.field("priority")], "pri.path")
            }

            Test("SyslogPriority: decodes through its invariant (CodableInvariant)") {
                try Expect.equal(try JSONDecoder().decode(SyslogPriority.self, from: Data("14".utf8)).severity, .informational, "pri.decode")
                try Expect.equal(String(decoding: try JSONEncoder().encode(try SyslogPriority(14)), as: UTF8.self), "14", "pri.encode")
                try Expect.throwsError("pri.decode-invalid") {
                    _ = try JSONDecoder().decode(SyslogPriority.self, from: Data("500".utf8))
                }
            }

            Test("SyslogStructuredDataElement: SD-ID and names follow RFC 5424") {
                let element = try SyslogStructuredDataElement(.init(id: "meta@32473", parameters: [try kv("seq", "7")]))
                try Expect.equal(element.id, "meta@32473", "sd.valid")

                try Expect.equal(violation(try SyslogStructuredDataElement(.init(id: "", parameters: [])))?.0, .blank_text, "sd.blank-id")
                try Expect.equal(
                    violation(try SyslogStructuredDataElement(.init(id: "naïve", parameters: [])))?.0,
                    .custom("log_formats.invalid_structured_data_name"),
                    "sd.non-ascii-id"
                )
                try Expect.equal(
                    violation(try SyslogStructuredDataElement(.init(id: String(repeating: "x", count: 33), parameters: [])))?.0,
                    .length_above_maximum,
                    "sd.long-id"
                )
                let badParameter = violation(try SyslogStructuredDataElement(.init(id: "x", parameters: [try kv("ok", "1"), try kv("ëe", "2")])))
                try Expect.equal(badParameter?.0, .custom("log_formats.invalid_structured_data_name"), "sd.param.code")
                try Expect.equal(badParameter?.1, [.field("parameters"), .index(1), .field("key")], "sd.param.path")
            }

            Test("CEFRecord: version >= 0 and CEF key rules, with indexed paths") {
                func raw(version: Int = 0, keys: [String]) throws(InvarianceFailure) -> CEFRecord.Raw {
                    var extensions: [KeyValuePair] = []
                    for key in keys {
                        extensions.append(try kv(key, "x"))
                    }
                    return .init(
                        version: version, deviceVendor: "V", deviceProduct: "P", deviceVersion: "1",
                        deviceEventClassID: "2", name: "N", severity: "3",
                        extensions: extensions
                    )
                }
                try Expect.equal(try CEFRecord(try raw(keys: ["UNIFIhost", "src", "a.b_c"])).extensions.count, 3, "cef.valid")
                try Expect.equal(violation(try CEFRecord(try raw(version: -1, keys: [])))?.0, .below_minimum, "cef.version")

                let badStart = violation(try CEFRecord(try raw(keys: ["src", "_x"])))
                try Expect.equal(badStart?.0, .custom("log_formats.invalid_key_start"), "cef.key-start")
                try Expect.equal(badStart?.1, [.field("extensions"), .index(1), .field("key")], "cef.key-start.path")

                try Expect.equal(violation(try CEFRecord(try raw(keys: ["a-b"])))?.0, .custom("log_formats.invalid_key_character"), "cef.key-dash")
            }

            Test("CEFRecord: JSON decoding enforces the invariant") {
                let valid = #"{"version":0,"deviceVendor":"V","deviceProduct":"P","deviceVersion":"1","deviceEventClassID":"2","name":"N","severity":"3","extensions":[{"key":"src","value":"1.2.3.4"}]}"#
                try Expect.equal(try JSONDecoder().decode(CEFRecord.self, from: Data(valid.utf8))["src"], "1.2.3.4", "cef.decode")
                let invalid = valid.replacingOccurrences(of: #""key":"src""#, with: #""key":"9src""#)
                try Expect.throwsError("cef.decode-invalid-key") {
                    _ = try JSONDecoder().decode(CEFRecord.self, from: Data(invalid.utf8))
                }
                let record = try JSONDecoder().decode(CEFRecord.self, from: Data(valid.utf8))
                try Expect.equal(try JSONDecoder().decode(CEFRecord.self, from: try JSONEncoder().encode(record)), record, "cef.round-trip")
            }
        }
    }
}
