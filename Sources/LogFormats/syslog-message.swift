/// A parsed syslog datagram.
///
/// An aggregate of already-guaranteed parts (``SyslogPriority``, ``SyslogStructuredDataElement``,
/// ``CEFRecord``, ``KeyValuePair``); its other fields are envelope text taken as sent, with no
/// further invariant. So it is a plain value rather than an `Invariant`. Produced by
/// `SyslogParser.parse(_:)` in `LogFormatsParsing`, which never fails: anything that does not
/// match a known envelope ends up in ``body`` with ``format`` `.unstructured`.
public struct SyslogMessage: Sendable, Hashable, Codable {
    /// Which envelope the datagram used.
    public enum Format: String, Sendable, Hashable, Codable {
        /// RFC 5424: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG`
        case rfc5424
        /// RFC 3164 (BSD): `<PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG`
        case rfc3164
        /// No recognizable envelope; the whole datagram (after an optional PRI) is the body.
        case unstructured
    }

    public let priority: SyslogPriority?
    public let format: Format
    /// As sent; not normalized (RFC 3164 timestamps carry no year or zone).
    public let timestamp: String?
    public let hostname: String?
    /// RFC 5424 APP-NAME, or the RFC 3164 TAG.
    public let appName: String?
    public let processID: String?
    public let messageID: String?
    /// RFC 5424 structured data; empty when absent.
    public let structuredData: [SyslogStructuredDataElement]
    /// The message text after the envelope.
    public let body: String
    /// The body interpreted as CEF, key=value pairs, or plain text.
    public let payload: SyslogPayload

    public init(
        priority: SyslogPriority?,
        format: Format,
        timestamp: String?,
        hostname: String?,
        appName: String?,
        processID: String?,
        messageID: String?,
        structuredData: [SyslogStructuredDataElement],
        body: String,
        payload: SyslogPayload
    ) {
        self.priority = priority
        self.format = format
        self.timestamp = timestamp
        self.hostname = hostname
        self.appName = appName
        self.processID = processID
        self.messageID = messageID
        self.structuredData = structuredData
        self.body = body
        self.payload = payload
    }
}

/// What the message body contains.
public enum SyslogPayload: Sendable, Hashable, Codable {
    /// A Common Event Format record (UniFi's SIEM export).
    case cef(CEFRecord)
    /// The body starts with `CEF:` but is not a valid record. Kept as text with the reason.
    case malformedCEF(CEFParseError)
    /// `KEY=value` / `KEY="quoted value"` pairs (e.g. iptables-style firewall lines).
    case keyValues([KeyValuePair])
    /// Anything else.
    case text
}
