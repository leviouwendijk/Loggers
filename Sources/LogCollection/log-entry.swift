import LogFormats

/// One collected datagram as stored (one JSON object per line) and returned by the
/// collector's `entries` route.
///
/// A record of what arrived, built from an already-parsed ``SyslogMessage``; it adds no
/// invariant of its own, so it is a plain value. `fields` flattens the payload for
/// querying: CEF header (`cef_*`) and extension keys, key=value pairs, and structured-data
/// parameters as `<sd-id>.<name>`.
public struct LogEntry: Codable, Sendable, Hashable {
    public let received_at: String
    /// Sender address.
    public let source: String
    /// `rfc5424`, `rfc3164` or `unstructured`.
    public let format: String
    public let facility: Int?
    /// Severity name, e.g. `informational`, `warning`.
    public let severity: String?
    public let timestamp: String?
    public let host: String?
    /// RFC 5424 APP-NAME or RFC 3164 TAG.
    public let app: String?
    public let procid: String?
    public let msgid: String?
    /// Body after the syslog envelope.
    public let message: String
    /// `cef`, `key_values`, `text` or `malformed_cef`.
    public let payload: String
    public let parse_error: String?
    /// The typed record when `payload == "cef"`.
    public let cef: CEFRecord?
    public let fields: [String: String]
    /// The datagram as received; kept so entries can be re-parsed.
    public let raw: String

    public init(message: SyslogMessage, raw: String, source: String, receivedAt: String) {
        var fields: [String: String] = [:]
        for element in message.structuredData {
            for parameter in element.parameters {
                fields["\(element.id).\(parameter.key)"] = parameter.value
            }
        }

        let payload: String
        var cef: CEFRecord?
        var parseError: String?
        switch message.payload {
        case .cef(let record):
            payload = "cef"
            cef = record
            fields["cef_version"] = String(record.version)
            fields["cef_vendor"] = record.deviceVendor
            fields["cef_product"] = record.deviceProduct
            fields["cef_device_version"] = record.deviceVersion
            fields["cef_event_class_id"] = record.deviceEventClassID
            fields["cef_name"] = record.name
            fields["cef_severity"] = record.severity
            for pair in record.extensions {
                fields[pair.key] = pair.value
            }
        case .malformedCEF(let error):
            payload = "malformed_cef"
            parseError = error.description
        case .keyValues(let pairs):
            payload = "key_values"
            for pair in pairs {
                fields[pair.key] = pair.value
            }
        case .text:
            payload = "text"
        }

        self.received_at = receivedAt
        self.source = source
        self.format = message.format.rawValue
        self.facility = message.priority?.facility
        self.severity = message.priority.map { "\($0.severity)" }
        self.timestamp = message.timestamp
        self.host = message.hostname
        self.app = message.appName
        self.procid = message.processID
        self.msgid = message.messageID
        self.message = message.body
        self.payload = payload
        self.parse_error = parseError
        self.cef = cef
        self.fields = fields
        self.raw = raw
    }
}
