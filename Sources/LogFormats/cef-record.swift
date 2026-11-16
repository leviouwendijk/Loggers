import Primitives

/// A Common Event Format record:
/// `CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension`
///
/// UniFi exports its system log in this format (Integration → System Logging / SIEM), e.g.
/// `CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|UNIFIcategory=System …`.
///
/// Invariant: `version >= 0`; every extension key starts with a letter and contains only
/// letters, digits, `_` and `.` (the boundary rule the parser uses to split extensions).
/// Header fields are free text; severity is kept as text because CEF allows `0...10`
/// or `Unknown`/`Low`/`Medium`/`High`/`Very-High`.
public struct CEFRecord: CodableInvariant, Sendable, Hashable {
    public struct Raw: Codable, Sendable, Hashable {
        public var version: Int
        public var deviceVendor: String
        public var deviceProduct: String
        public var deviceVersion: String
        public var deviceEventClassID: String
        public var name: String
        public var severity: String
        public var extensions: [KeyValuePair]

        public init(
            version: Int,
            deviceVendor: String,
            deviceProduct: String,
            deviceVersion: String,
            deviceEventClassID: String,
            name: String,
            severity: String,
            extensions: [KeyValuePair]
        ) {
            self.version = version
            self.deviceVendor = deviceVendor
            self.deviceProduct = deviceProduct
            self.deviceVersion = deviceVersion
            self.deviceEventClassID = deviceEventClassID
            self.name = name
            self.severity = severity
            self.extensions = extensions
        }
    }

    public let version: Int
    public let deviceVendor: String
    public let deviceProduct: String
    public let deviceVersion: String
    public let deviceEventClassID: String
    public let name: String
    public let severity: String
    /// In received order; duplicates preserved. Use ``subscript(_:)`` for lookup.
    public let extensions: [KeyValuePair]

    public var raw: Raw {
        Raw(
            version: version,
            deviceVendor: deviceVendor,
            deviceProduct: deviceProduct,
            deviceVersion: deviceVersion,
            deviceEventClassID: deviceEventClassID,
            name: name,
            severity: severity,
            extensions: extensions
        )
    }

    public init(_ raw: Raw) throws(InvarianceFailure) {
        guard raw.version >= 0 else {
            throw .at("version", InvarianceBelowMinimum(minimum: 0, actual: raw.version))
        }
        for (index, pair) in raw.extensions.enumerated() {
            let path: [InvariancePathComponent] = [.field("extensions"), .index(index), .field("key")]
            guard let first = pair.key.first, Self.isKeyStart(first) else {
                throw InvarianceFailure(InvarianceViolation(LogFormatsReason.invalid_key_start, path: path))
            }
            guard pair.key.allSatisfy(Self.isKeyCharacter) else {
                throw InvarianceFailure(InvarianceViolation(LogFormatsReason.invalid_key_character, path: path))
            }
        }
        self.version = raw.version
        self.deviceVendor = raw.deviceVendor
        self.deviceProduct = raw.deviceProduct
        self.deviceVersion = raw.deviceVersion
        self.deviceEventClassID = raw.deviceEventClassID
        self.name = raw.name
        self.severity = raw.severity
        self.extensions = raw.extensions
    }

    /// The last value for `key`, if present.
    public subscript(_ key: String) -> String? {
        extensions.last { $0.key == key }?.value
    }

    public static func isKeyStart(_ character: Character) -> Bool {
        character.isLetter
    }

    public static func isKeyCharacter(_ character: Character) -> Bool {
        character.isLetter || character.isNumber || character == "_" || character == "."
    }
}

/// Why a body that starts with `CEF:` is not a valid record.
public enum CEFParseError: Error, Sendable, Hashable, Codable, CustomStringConvertible {
    /// The text does not start with `CEF:`.
    case missingPrefix
    /// The version before the first `|` is not a non-negative integer.
    case invalidVersion(String)
    /// Fewer than the seven `|`-terminated header fields were present.
    case incompleteHeader(fieldsFound: Int)
    /// The fields parsed but do not satisfy ``CEFRecord``'s invariant (message of the first violation).
    case invalidRecord(String)

    public var description: String {
        switch self {
        case .missingPrefix:
            return "CEF record must start with 'CEF:'"
        case .invalidVersion(let value):
            return "invalid CEF version '\(value)'"
        case .incompleteHeader(let found):
            return "CEF header needs 7 '|'-separated fields, found \(found)"
        case .invalidRecord(let message):
            return "invalid CEF record: \(message)"
        }
    }
}
