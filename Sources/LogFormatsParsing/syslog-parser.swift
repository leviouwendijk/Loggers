import LogFormats

/// Parses one syslog datagram. Total: every input produces a ``SyslogMessage``.
///
/// Envelope detection, after an optional `<PRI>`:
/// 1. `CEF:` immediately: no envelope, the rest is a CEF body (`.unstructured`).
/// 2. `1 ` (version 1): RFC 5424.
/// 3. `Mmm dd hh:mm:ss ` (day may be space-padded): RFC 3164. If the text after the
///    hostname starts with `CEF:`, it is the body and there is no tag. This is how UniFi
///    sends its SIEM export, e.g. `<14>Nov 16 18:30:01 UDM-SE CEF:0|Ubiquiti|…`.
/// 4. Otherwise `.unstructured`.
///
/// Every typed value is built through its invariant initializer. A part that fails its
/// invariant is not kept: an invalid PRI stays in the body, an invalid SD element makes
/// the envelope fall back, an invalid pair is skipped.
public enum SyslogParser {
    public static func parse(_ raw: String) -> SyslogMessage {
        var scanner = Scanner(raw.trimmingTrailingNewlines())
        let priority = parsePriority(&scanner)

        if scanner.peekLiteral("CEF:") {
            return message(priority, .unstructured, body: scanner.remainder)
        }
        if let message = parseRFC5424(&scanner, priority) {
            return message
        }
        if let message = parseRFC3164(&scanner, priority) {
            return message
        }
        scanner.skipSpaces()
        return message(priority, .unstructured, body: scanner.remainder)
    }

    // MARK: PRI

    static func parsePriority(_ scanner: inout Scanner) -> SyslogPriority? {
        let start = scanner.mark()
        guard scanner.consume("<") else { return nil }
        let digits = scanner.take { $0.isASCII && $0.isNumber }
        guard (1...3).contains(digits.count), scanner.consume(">"),
              let value = Int(digits), let priority = try? SyslogPriority(value)
        else {
            scanner.restore(start)
            return nil
        }
        return priority
    }

    // MARK: RFC 5424

    static func parseRFC5424(_ scanner: inout Scanner, _ priority: SyslogPriority?) -> SyslogMessage? {
        let start = scanner.mark()
        guard scanner.consume("1 ") else { return nil }

        var header: [String?] = []
        for _ in 0..<5 {
            guard let value = scanner.token() else {
                scanner.restore(start)
                return nil
            }
            header.append(value == "-" ? nil : value)
        }
        scanner.skipSpaces()

        var elements: [SyslogStructuredDataElement] = []
        if scanner.peek() == "-" {
            scanner.advance()
        } else {
            while scanner.peek() == "[" {
                guard let element = parseStructuredElement(&scanner) else {
                    scanner.restore(start)
                    return nil
                }
                elements.append(element)
            }
        }
        if scanner.peek() == " " { scanner.advance() }
        var body = scanner.remainder
        if body.hasPrefix("\u{FEFF}") { body.removeFirst() }

        return SyslogMessage(
            priority: priority,
            format: .rfc5424,
            timestamp: header[0],
            hostname: header[1],
            appName: header[2],
            processID: header[3],
            messageID: header[4],
            structuredData: elements,
            body: body,
            payload: payload(for: body)
        )
    }

    /// `[id name="value" name="value"]` with `\"`, `\\` and `\]` escapes in values.
    static func parseStructuredElement(_ scanner: inout Scanner) -> SyslogStructuredDataElement? {
        guard scanner.consume("[") else { return nil }
        let id = scanner.take { $0 != " " && $0 != "]" }
        var parameters: [KeyValuePair] = []
        while true {
            scanner.skipSpaces()
            if scanner.consume("]") {
                return try? SyslogStructuredDataElement(.init(id: id, parameters: parameters))
            }
            let name = scanner.take { $0 != "=" && $0 != " " && $0 != "]" }
            guard scanner.consume("=\"") else { return nil }
            var value = ""
            while let character = scanner.peek(), character != "\"" {
                if character == "\\", let next = scanner.peek(1), next == "\"" || next == "\\" || next == "]" {
                    value.append(next)
                    scanner.advance(by: 2)
                } else {
                    value.append(character)
                    scanner.advance()
                }
            }
            guard scanner.consume("\""), let parameter = try? KeyValuePair(name, value) else { return nil }
            parameters.append(parameter)
        }
    }

    // MARK: RFC 3164

    static let months: Set<String> = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    static func parseRFC3164(_ scanner: inout Scanner, _ priority: SyslogPriority?) -> SyslogMessage? {
        let start = scanner.mark()
        guard let timestamp = bsdTimestamp(&scanner) else {
            scanner.restore(start)
            return nil
        }
        scanner.skipSpaces()
        if scanner.peekLiteral("CEF:") {
            return message(priority, .rfc3164, timestamp: timestamp, body: scanner.remainder)
        }
        let hostname = scanner.token()
        scanner.skipSpaces()

        if scanner.peekLiteral("CEF:") {
            return message(priority, .rfc3164, timestamp: timestamp, hostname: hostname, body: scanner.remainder)
        }

        // TAG: up to 48 characters of [A-Za-z0-9_.-/], optionally "[pid]", then ":".
        let tagStart = scanner.mark()
        let tag = scanner.take { $0.isLetter || $0.isNumber || "_.-/".contains($0) }
        var processID: String?
        if !tag.isEmpty, tag.count <= 48 {
            if scanner.consume("[") {
                processID = scanner.take { $0 != "]" }
                if !scanner.consume("]") { processID = nil }
            }
            if scanner.consume(":") {
                if scanner.peek() == " " { scanner.advance() }
                let body = scanner.remainder
                return SyslogMessage(
                    priority: priority,
                    format: .rfc3164,
                    timestamp: timestamp,
                    hostname: hostname,
                    appName: tag,
                    processID: processID,
                    messageID: nil,
                    structuredData: [],
                    body: body,
                    payload: payload(for: body)
                )
            }
        }
        scanner.restore(tagStart)
        return message(priority, .rfc3164, timestamp: timestamp, hostname: hostname, body: scanner.remainder)
    }

    /// `Mmm dd hh:mm:ss` or `Mmm  d hh:mm:ss`.
    static func bsdTimestamp(_ scanner: inout Scanner) -> String? {
        let start = scanner.mark()
        let month = scanner.take { $0.isLetter }
        guard months.contains(month), scanner.consume(" ") else {
            scanner.restore(start)
            return nil
        }
        if scanner.peek() == " " { scanner.advance() }
        let day = scanner.take { $0.isASCII && $0.isNumber }
        guard (1...2).contains(day.count), scanner.consume(" ") else {
            scanner.restore(start)
            return nil
        }
        let time = scanner.take { ($0.isASCII && $0.isNumber) || $0 == ":" }
        let parts = time.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ $0.count == 2 }) else {
            scanner.restore(start)
            return nil
        }
        let paddedDay = day.count == 1 ? " \(day)" : day
        return "\(month) \(paddedDay) \(time)"
    }

    // MARK: payload

    /// Interprets a body as CEF, key=value pairs, or text.
    public static func payload(for body: String) -> SyslogPayload {
        let trimmed = body.drop { $0 == " " }
        if trimmed.hasPrefix("CEF:") {
            do {
                return .cef(try CEFParser.parse(String(trimmed)))
            } catch {
                return .malformedCEF(error)
            }
        }
        let pairs = KeyValueParser.parse(String(trimmed))
        return pairs.isEmpty ? .text : .keyValues(pairs)
    }

    private static func message(
        _ priority: SyslogPriority?,
        _ format: SyslogMessage.Format,
        timestamp: String? = nil,
        hostname: String? = nil,
        body: String
    ) -> SyslogMessage {
        SyslogMessage(
            priority: priority,
            format: format,
            timestamp: timestamp,
            hostname: hostname,
            appName: nil,
            processID: nil,
            messageID: nil,
            structuredData: [],
            body: body,
            payload: payload(for: body)
        )
    }
}

/// Parses CEF records. Header fields unescape `\|` and `\\`; extension values unescape
/// `\=`, `\\`, `\n` and `\r`. An extension value runs until the next ` key=` boundary,
/// so values may contain spaces (`UNIFIhost=Office UDM Pro`). Key boundaries use
/// ``CEFRecord/isKeyStart(_:)`` and ``CEFRecord/isKeyCharacter(_:)``, the same rules the
/// record's invariant checks.
public enum CEFParser {
    public static func parse(_ text: String) throws(CEFParseError) -> CEFRecord {
        var scanner = Scanner(text)
        guard scanner.consume("CEF:") else { throw .missingPrefix }

        var fields: [String] = []
        var current = ""
        while fields.count < 7, let character = scanner.peek() {
            if character == "\\", let next = scanner.peek(1), next == "|" || next == "\\" {
                current.append(next)
                scanner.advance(by: 2)
                continue
            }
            if character == "|" {
                fields.append(current)
                current = ""
            } else {
                current.append(character)
            }
            scanner.advance()
        }
        guard fields.count == 7 else {
            throw .incompleteHeader(fieldsFound: fields.count + (current.isEmpty ? 0 : 1))
        }
        guard let version = Int(fields[0].trimmingSpaces()), version >= 0 else {
            throw .invalidVersion(fields[0])
        }
        do {
            return try CEFRecord(
                .init(
                    version: version,
                    deviceVendor: fields[1],
                    deviceProduct: fields[2],
                    deviceVersion: fields[3],
                    deviceEventClassID: fields[4],
                    name: fields[5],
                    severity: fields[6],
                    extensions: extensions(scanner.remainder)
                )
            )
        } catch {
            throw .invalidRecord(error.first.message)
        }
    }

    /// Splits `k1=v1 with spaces k2=v2` at each ` key=` boundary.
    static func extensions(_ text: String) -> [KeyValuePair] {
        let characters = Array(text)
        var boundaries: [(keyStart: Int, valueStart: Int)] = []
        var index = 0
        while index < characters.count {
            let atBoundary = index == 0 || characters[index - 1] == " "
            if atBoundary, CEFRecord.isKeyStart(characters[index]) {
                var end = index
                while end < characters.count, CEFRecord.isKeyCharacter(characters[end]) { end += 1 }
                if end < characters.count, characters[end] == "=", end - index <= KeyValuePair.maxKeyLength {
                    boundaries.append((index, end + 1))
                    index = end + 1
                    continue
                }
            }
            index += 1
        }

        return boundaries.enumerated().compactMap { position, boundary in
            let key = String(characters[boundary.keyStart..<(boundary.valueStart - 1)])
            let end = position + 1 < boundaries.count ? boundaries[position + 1].keyStart : characters.count
            var raw = Array(characters[boundary.valueStart..<end])
            while raw.last == " " { raw.removeLast() }
            return try? KeyValuePair(key, unescape(raw))
        }
    }

    static func unescape(_ characters: [Character]) -> String {
        var result = ""
        var index = 0
        while index < characters.count {
            let character = characters[index]
            if character == "\\", index + 1 < characters.count {
                switch characters[index + 1] {
                case "=": result.append("="); index += 2; continue
                case "\\": result.append("\\"); index += 2; continue
                case "n": result.append("\n"); index += 2; continue
                case "r": result.append("\r"); index += 2; continue
                default: break
                }
            }
            result.append(character)
            index += 1
        }
        return result
    }
}

/// `KEY=value` and `KEY="quoted value"` pairs separated by spaces, as in iptables-style
/// firewall lines (`DESCR="Allow: Default > [DMZ]" SRC=10.60.0.5 DPT=22`). Other words are skipped.
public enum KeyValueParser {
    public static let maxPairs = 64

    public static func parse(_ text: String) -> [KeyValuePair] {
        var scanner = Scanner(text)
        var pairs: [KeyValuePair] = []
        while !scanner.isAtEnd, pairs.count < maxPairs {
            scanner.skipSpaces()
            let start = scanner.mark()
            let key = scanner.take { $0.isLetter || $0.isNumber || "_.-".contains($0) }
            guard let first = key.first, first.isLetter || first == "_", scanner.consume("=") else {
                scanner.restore(start)
                if scanner.peek() == "\"" {
                    // a stray quoted run; skip it whole
                    scanner.advance()
                    _ = scanner.take { $0 != "\"" }
                    scanner.advance()
                } else {
                    _ = scanner.take { $0 != " " }
                    if scanner.mark() == start { scanner.advance() }
                }
                continue
            }
            let value: String
            if scanner.consume("\"") {
                value = scanner.take { $0 != "\"" }
                _ = scanner.consume("\"")
            } else {
                value = scanner.take { $0 != " " }
            }
            if let pair = try? KeyValuePair(key, value) {
                pairs.append(pair)
            }
        }
        return pairs
    }
}

extension Scanner {
    func peekLiteral(_ literal: String) -> Bool {
        var copy = self
        return copy.consume(literal)
    }
}

extension String {
    func trimmingTrailingNewlines() -> String {
        var copy = self
        // "\r\n" is a single Character in Swift, so it is listed separately.
        while let last = copy.last, last == "\n" || last == "\r" || last == "\r\n" || last == "\0" {
            copy.removeLast()
        }
        return copy
    }

    func trimmingSpaces() -> String {
        String(drop { $0 == " " }.reversed().drop { $0 == " " }.reversed())
    }
}
