import LogFormats
import LogFormatsParsing
import Testing

/// Lines as received from a UDM SE on 2026-11-16 (SIEM export to syslogger). They differ from
/// UniFi's documentation: there is no `<PRI>`, UniFi Protect uses the device display name (with
/// spaces) as the hostname, and Protect quotes some extension values.
private enum RealLine {
    static let protect =
        #"Nov 16 19:20:57 Dream Machine Special Edition CEF:0|Ubiquiti|UniFi Protect|7.3.74|2161|smartAudioDetect|7|UNIFIcategory=detection eventId=6afb497b01067a03e405361f eventType=smartAudioDetect category=detection severity=7 timestamp=1794853229187 msg="G6 Turret detected someone speaking.""#

    static let unifiOSTest =
        "Nov 16 17:56:43 Dream-Machine-Special-Edition CEF:0|Ubiquiti|UniFi OS|6.0.17|1|Test Syslog|1|UNIFIhost=Dream Machine Special Edition UNIFIdeviceName=Dream Machine Special Edition UNIFIdeviceModel=UDMPROSE UNIFIdeviceIp=92.66.36.101 UNIFIdeviceMac=28:70:4E:68:A8:C5 UNIFIdeviceVersion=6.0.17"
}

extension LogFormatsTestSuite {
    static var unifiRealFlow: TestSuite {
        TestSuite("unifi-real", tags: ["cef", "unifi", "regression"]) {
            Test("Protect: no PRI, hostname with spaces, quoted msg") {
                let message = SyslogParser.parse(RealLine.protect)
                try Expect.equal(message.format, .rfc3164, "protect.format")
                try Expect.isNil(message.priority, "protect.no-pri")
                try Expect.equal(message.timestamp, "Nov 16 19:20:57", "protect.timestamp")
                try Expect.equal(message.hostname, "Dream Machine Special Edition", "protect.hostname-with-spaces")
                guard case .cef(let record) = message.payload else {
                    throw TestFlowAssertionFailure(label: "protect.payload", message: "expected cef", actual: "\(message.payload)", expected: "cef")
                }
                try Expect.equal(record.deviceProduct, "UniFi Protect", "protect.product")
                try Expect.equal(record.deviceVersion, "7.3.74", "protect.version")
                try Expect.equal(record.name, "smartAudioDetect", "protect.name")
                try Expect.equal(record.severity, "7", "protect.severity")
                try Expect.equal(record["UNIFIcategory"], "detection", "protect.category")
                try Expect.equal(record["eventType"], "smartAudioDetect", "protect.event-type")
                try Expect.equal(record["msg"], "G6 Turret detected someone speaking.", "protect.msg-unquoted")
            }

            Test("UniFi OS: no PRI, hyphenated hostname, values with spaces") {
                let message = SyslogParser.parse(RealLine.unifiOSTest)
                try Expect.equal(message.hostname, "Dream-Machine-Special-Edition", "os.hostname")
                guard case .cef(let record) = message.payload else {
                    throw TestFlowAssertionFailure(label: "os.payload", message: "expected cef", actual: "\(message.payload)", expected: "cef")
                }
                try Expect.equal(record.deviceProduct, "UniFi OS", "os.product")
                try Expect.equal(record.name, "Test Syslog", "os.name")
                try Expect.equal(record["UNIFIhost"], "Dream Machine Special Edition", "os.unifi-host")
                try Expect.equal(record["UNIFIdeviceModel"], "UDMPROSE", "os.model")
                try Expect.equal(record["UNIFIdeviceMac"], "28:70:4E:68:A8:C5", "os.mac")
            }

            Test("a CEF start must be at a word boundary and followed by version and '|'") {
                let embedded = SyslogParser.parse("Nov 16 19:00:00 host app: xCEF:0|V|P|1|2|N|3|a=b")
                try Expect.equal(embedded.appName, "app", "boundary.tag-kept")
                try Expect.equal(embedded.payload, .text, "boundary.not-cef")

                let noVersion = SyslogParser.parse("Nov 16 19:00:00 host app: mentions CEF: in prose")
                try Expect.equal(noVersion.appName, "app", "boundary.prose")
                try Expect.equal(noVersion.payload, .text, "boundary.prose.not-cef")
            }

            Test("only fully quoted extension values lose their quotes") {
                let record = try CEFParser.parse(#"CEF:0|V|P|1|2|N|3|a="quoted value" b="half c=say "hi" d="""#)
                try Expect.equal(record["a"], "quoted value", "quotes.full")
                try Expect.equal(record["b"], #""half"#, "quotes.leading-only")
                try Expect.equal(record["c"], #"say "hi""#, "quotes.inner-kept")
                try Expect.equal(record["d"], "", "quotes.empty")
            }
        }
    }
}
