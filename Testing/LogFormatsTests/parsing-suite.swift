import LogFormats
import LogFormatsParsing
import Testing

extension LogFormatsTestSuite {
    static var priorityFlow: TestSuite {
        TestSuite("priority", tags: ["pri"]) {
            Test("decodes facility and severity") {
                let priority = SyslogParser.parse("<14>hello").priority
                try Expect.equal(priority?.facility, 1, "pri.14.facility")
                try Expect.equal(priority?.severity, .informational, "pri.14.severity")
                try Expect.equal(SyslogParser.parse("<0>x").priority?.severity, .emergency, "pri.0")
                try Expect.equal(SyslogParser.parse("<191>x").priority?.facility, 23, "pri.191.facility")
                try Expect.equal(SyslogParser.parse("<191>x").priority?.severity, .debug, "pri.191.severity")
            }

            Test("out-of-range or malformed PRI is not a priority and stays in the body") {
                let high = SyslogParser.parse("<192>x")
                try Expect.isNil(high.priority, "pri.192")
                try Expect.equal(high.body, "<192>x", "pri.192.body")

                let unterminated = SyslogParser.parse("<14 hello")
                try Expect.isNil(unterminated.priority, "pri.unterminated")
                try Expect.equal(unterminated.body, "<14 hello", "pri.unterminated.body")

                try Expect.isNil(SyslogParser.parse("<>x").priority, "pri.empty")
                try Expect.isNil(SyslogParser.parse("<1234>x").priority, "pri.four-digits")
            }
        }
    }

    static var unifiCEFFlow: TestSuite {
        TestSuite("unifi-cef", tags: ["cef", "unifi"]) {
            Test("UniFi SIEM line: BSD envelope, hostname, then CEF without a tag") {
                let message = SyslogParser.parse(Fixture.bsd(Fixture.adminAccessCEF))
                try Expect.equal(message.format, .rfc3164, "unifi.format")
                try Expect.equal(message.hostname, "UDM-SE", "unifi.hostname")
                try Expect.isNil(message.appName, "unifi.no-tag")
                try Expect.equal(message.timestamp, "Nov 16 18:30:01", "unifi.timestamp")
                try Expect.equal(message.body, Fixture.adminAccessCEF, "unifi.body-intact")
            }

            Test("admin access example: header and extensions") {
                let record = try Fixture.cef(Fixture.bsd(Fixture.adminAccessCEF))
                try Expect.equal(record.version, 0, "admin.version")
                try Expect.equal(record.deviceVendor, "Ubiquiti", "admin.vendor")
                try Expect.equal(record.deviceProduct, "UniFi Network", "admin.product")
                try Expect.equal(record.deviceVersion, "9.3.33", "admin.device-version")
                try Expect.equal(record.deviceEventClassID, "544", "admin.class-id")
                try Expect.equal(record.name, "Admin Accessed UniFi Network", "admin.name")
                try Expect.equal(record.severity, "1", "admin.severity")
                try Expect.equal(
                    record.extensions.map(\.key),
                    ["UNIFIcategory", "UNIFIsubCategory", "UNIFIhost", "UNIFIaccessMethod", "UNIFIadmin", "src", "msg"],
                    "admin.keys-in-order"
                )
                try Expect.equal(record["UNIFIcategory"], "System", "admin.category")
                try Expect.equal(record["UNIFIhost"], "Office UDM Pro", "admin.host-with-spaces")
                try Expect.equal(record["src"], "105.5.138.59", "admin.src")
                try Expect.equal(
                    record["msg"],
                    "Craig accessed UniFi Network using the web. Source IP: 105.5.138.59",
                    "admin.msg-with-spaces-and-colon"
                )
            }

            Test("wifi disconnect example: values with spaces, units, slashes") {
                let record = try Fixture.cef(Fixture.bsd(Fixture.wifiDisconnectCEF, pri: 13))
                try Expect.equal(record.name, "WiFi Client Disconnected", "wifi.name")
                try Expect.equal(record.severity, "2", "wifi.severity")
                try Expect.equal(record["UNIFIlastConnectedToDeviceName"], "Lobby AP", "wifi.device-name")
                try Expect.equal(record["UNIFIclientAlias"], "Apple Watch 0d:87", "wifi.alias")
                try Expect.equal(record["UNIFIduration"], "6m 22s", "wifi.duration")
                try Expect.equal(record["UNIFIusageDown"], "11.78 KB", "wifi.usage")
                try Expect.equal(record["UNIFInetworkSubnet"], "192.168.10.0/24", "wifi.subnet")
                try Expect.equal(record["UNIFInetworkVlan"], "10", "wifi.vlan")
                try Expect.equal(
                    record["msg"],
                    "Apple Watch 0d:87 disconnected from Employee WiFi. Time Connected: 6m 22s. Data Used: 4.46 KB (up) / 11.78 KB (down). Last Connected To: Lobby AP at -77 dBm.",
                    "wifi.msg"
                )
            }

            Test("CEF directly after PRI, without envelope") {
                let message = SyslogParser.parse("<14>" + Fixture.adminAccessCEF)
                try Expect.equal(message.format, .unstructured, "bare.format")
                try Expect.equal(message.priority?.severity, .informational, "bare.pri")
                guard case .cef(let record) = message.payload else {
                    throw TestFlowAssertionFailure(label: "bare.payload", message: "expected cef", actual: "\(message.payload)", expected: "cef")
                }
                try Expect.equal(record["UNIFIadmin"], "Craig", "bare.admin")
            }

            Test("CEF in an RFC 5424 envelope") {
                let message = SyslogParser.parse("<14>1 2026-11-16T18:30:01Z UDM-SE unifi - - - " + Fixture.adminAccessCEF)
                try Expect.equal(message.format, .rfc5424, "5424cef.format")
                try Expect.equal(message.appName, "unifi", "5424cef.app")
                guard case .cef(let record) = message.payload else {
                    throw TestFlowAssertionFailure(label: "5424cef.payload", message: "expected cef", actual: "\(message.payload)", expected: "cef")
                }
                try Expect.equal(record.name, "Admin Accessed UniFi Network", "5424cef.name")
            }
        }
    }

    static var cefGrammarFlow: TestSuite {
        TestSuite("cef-grammar", tags: ["cef"]) {
            Test("escaped pipe and backslash in header fields") {
                let record = try CEFParser.parse(#"CEF:0|Vend\|or|Prod\\uct|1.0|100|Name with \| pipe|5|k=v"#)
                try Expect.equal(record.deviceVendor, "Vend|or", "header.escaped-pipe")
                try Expect.equal(record.deviceProduct, #"Prod\uct"#, "header.escaped-backslash")
                try Expect.equal(record.name, "Name with | pipe", "header.name-pipe")
                try Expect.equal(record["k"], "v", "header.extension")
            }

            Test("extension escapes: \\=, \\\\, \\n, \\r; unknown escapes kept") {
                let record = try CEFParser.parse(#"CEF:0|V|P|1|2|N|3|a=x\=y b=c\\d e=line1\nline2 f=keep\t"#)
                try Expect.equal(record["a"], "x=y", "ext.escaped-equals")
                try Expect.equal(record["b"], #"c\d"#, "ext.escaped-backslash")
                try Expect.equal(record["e"], "line1\nline2", "ext.newline")
                try Expect.equal(record["f"], #"keep\t"#, "ext.unknown-escape")
            }

            Test("escaped equals does not start a new key") {
                let record = try CEFParser.parse(#"CEF:0|V|P|1|2|N|3|msg=a b\=c d=e"#)
                try Expect.equal(record["msg"], "a b=c", "ext.no-false-boundary")
                try Expect.equal(record["d"], "e", "ext.next-key")
            }

            Test("empty extension and empty values") {
                let empty = try CEFParser.parse("CEF:0|V|P|1|2|N|3|")
                try Expect.equal(empty.extensions.count, 0, "ext.empty")
                let blank = try CEFParser.parse("CEF:0|V|P|1|2|N|3|a= b=2")
                try Expect.equal(blank["a"], "", "ext.blank-value")
                try Expect.equal(blank["b"], "2", "ext.after-blank")
            }

            Test("duplicate keys: order kept, lookup returns the last") {
                let record = try CEFParser.parse("CEF:0|V|P|1|2|N|3|k=1 k=2")
                try Expect.equal(record.extensions.count, 2, "dup.count")
                try Expect.equal(record["k"], "2", "dup.last")
            }

            Test("text severity and other versions") {
                let record = try CEFParser.parse("CEF:1|V|P|1|2|N|Very-High|x=y")
                try Expect.equal(record.version, 1, "sev.version")
                try Expect.equal(record.severity, "Very-High", "sev.text")
            }

            Test("typed errors") {
                try Expect.equal(caught("LEEF:1|x"), .missingPrefix, "err.prefix")
                try Expect.equal(caught("CEF:x|V|P|1|2|N|3|"), .invalidVersion("x"), "err.version")
                try Expect.equal(caught("CEF:0|V|P|1"), .incompleteHeader(fieldsFound: 4), "err.header")
            }

            Test("malformed CEF in a syslog line is reported, not dropped") {
                let message = SyslogParser.parse(Fixture.bsd("CEF:0|Ubiquiti|UniFi"))
                try Expect.equal(message.payload, .malformedCEF(.incompleteHeader(fieldsFound: 3)), "malformed.payload")
                try Expect.equal(message.body, "CEF:0|Ubiquiti|UniFi", "malformed.body-kept")
            }
        }
    }

    static var rfc3164Flow: TestSuite {
        TestSuite("rfc3164", tags: ["bsd"]) {
            Test("tag with pid") {
                let message = SyslogParser.parse("<30>Nov 16 18:30:01 udm-se dnsmasq[1234]: query from 10.60.10.147")
                try Expect.equal(message.format, .rfc3164, "bsd.format")
                try Expect.equal(message.hostname, "udm-se", "bsd.host")
                try Expect.equal(message.appName, "dnsmasq", "bsd.tag")
                try Expect.equal(message.processID, "1234", "bsd.pid")
                try Expect.equal(message.body, "query from 10.60.10.147", "bsd.body")
                try Expect.equal(message.payload, .text, "bsd.payload")
            }

            Test("space-padded single-digit day") {
                let message = SyslogParser.parse("<14>Nov  6 08:00:00 host app: hi")
                try Expect.equal(message.timestamp, "Nov  6 08:00:00", "bsd.padded-day")
                try Expect.equal(message.appName, "app", "bsd.padded-day.tag")
                try Expect.equal(message.body, "hi", "bsd.padded-day.body")
            }

            Test("no tag: body starts after the hostname") {
                let message = SyslogParser.parse("<14>Nov 16 18:30:01 host just some words")
                try Expect.isNil(message.appName, "bsd.no-tag")
                try Expect.equal(message.body, "just some words", "bsd.no-tag.body")
            }

            Test("invalid timestamp falls back to unstructured") {
                let message = SyslogParser.parse("<14>Foo 16 18:30:01 host app: hi")
                try Expect.equal(message.format, .unstructured, "bsd.bad-month")
                try Expect.equal(message.body, "Foo 16 18:30:01 host app: hi", "bsd.bad-month.body")
            }
        }
    }

    static var rfc5424Flow: TestSuite {
        TestSuite("rfc5424", tags: ["5424"]) {
            Test("full header with nil values") {
                let message = SyslogParser.parse("<165>1 2026-11-16T18:30:01.003Z mymachine evntslog - ID47 - An application event")
                try Expect.equal(message.format, .rfc5424, "5424.format")
                try Expect.equal(message.priority?.facility, 20, "5424.facility")
                try Expect.equal(message.priority?.severity, .notice, "5424.severity")
                try Expect.equal(message.timestamp, "2026-11-16T18:30:01.003Z", "5424.timestamp")
                try Expect.equal(message.hostname, "mymachine", "5424.host")
                try Expect.equal(message.appName, "evntslog", "5424.app")
                try Expect.isNil(message.processID, "5424.procid-nil")
                try Expect.equal(message.messageID, "ID47", "5424.msgid")
                try Expect.equal(message.structuredData.count, 0, "5424.no-sd")
                try Expect.equal(message.body, "An application event", "5424.body")
            }

            Test("structured data with escapes and multiple elements") {
                let message = SyslogParser.parse(#"<165>1 - host app 1 - [exampleSDID@32473 iut="3" eventSource="App \"x\" \] y"][meta seq="7"] BOM-less body"#)
                try Expect.equal(message.structuredData.map(\.id), ["exampleSDID@32473", "meta"], "5424.sd.ids")
                try Expect.equal(message.structuredData[0].parameters, [try kv("iut", "3"), try kv("eventSource", #"App "x" ] y"#)], "5424.sd.params")
                try Expect.equal(message.structuredData[1].parameters, [try kv("seq", "7")], "5424.sd.second")
                try Expect.equal(message.body, "BOM-less body", "5424.sd.body")
            }

            Test("UTF-8 BOM before the message is removed") {
                let message = SyslogParser.parse("<14>1 - h a - - - \u{FEFF}hello")
                try Expect.equal(message.body, "hello", "5424.bom")
            }

            Test("broken structured data falls back instead of failing") {
                let message = SyslogParser.parse(#"<14>1 - h a - - [broken x="1" rest"#)
                try Expect.notEqual(message.format, .rfc5424, "5424.broken-sd")
            }
        }
    }

    static var keyValueFlow: TestSuite {
        TestSuite("key-values", tags: ["kv"]) {
            Test("iptables-style firewall line") {
                let message = SyslogParser.parse(#"<4>Nov 16 16:01:02 UDM-SE kernel: [FW-A] DESCR="Allow: Default > [DMZ]" IN=br0 OUT=br902 SRC=10.60.0.5 DST=10.90.20.15 PROTO=TCP SPT=51515 DPT=22"#)
                try Expect.equal(message.appName, "kernel", "kv.tag")
                guard case .keyValues(let pairs) = message.payload else {
                    throw TestFlowAssertionFailure(label: "kv.payload", message: "expected key values", actual: "\(message.payload)", expected: "keyValues")
                }
                try Expect.equal(
                    pairs,
                    [
                        try kv("DESCR", "Allow: Default > [DMZ]"),
                        try kv("IN", "br0"),
                        try kv("OUT", "br902"),
                        try kv("SRC", "10.60.0.5"),
                        try kv("DST", "10.90.20.15"),
                        try kv("PROTO", "TCP"),
                        try kv("SPT", "51515"),
                        try kv("DPT", "22"),
                    ],
                    "kv.pairs"
                )
            }

            Test("words without '=' are skipped; plain text has no pairs") {
                try Expect.equal(KeyValueParser.parse("hello a=1 world b=2"), [try kv("a", "1"), try kv("b", "2")], "kv.skip-words")
                try Expect.equal(SyslogParser.parse("<14>just text").payload, .text, "kv.text")
            }
        }
    }

    static var robustnessFlow: TestSuite {
        TestSuite("robustness", tags: ["edge"]) {
            Test("empty and whitespace input") {
                try Expect.equal(SyslogParser.parse("").body, "", "edge.empty")
                try Expect.equal(SyslogParser.parse("\n").body, "", "edge.newline")
                try Expect.equal(SyslogParser.parse("").payload, .text, "edge.empty.payload")
            }

            Test("trailing newline and NUL are trimmed") {
                let message = SyslogParser.parse("<14>Nov 16 18:30:01 h app: hi\r\n\0")
                try Expect.equal(message.body, "hi", "edge.trailing")
            }

            Test("non-ASCII content survives") {
                let message = SyslogParser.parse(Fixture.bsd("CEF:0|Ubiquiti|UniFi Network|9|1|Naam met ë|1|msg=Hondenmeesters – überstraße 🐕"))
                guard case .cef(let record) = message.payload else {
                    throw TestFlowAssertionFailure(label: "edge.unicode", message: "expected cef", actual: "\(message.payload)", expected: "cef")
                }
                try Expect.equal(record.name, "Naam met ë", "edge.unicode.name")
                try Expect.equal(record["msg"], "Hondenmeesters – überstraße 🐕", "edge.unicode.msg")
            }
        }
    }

}
