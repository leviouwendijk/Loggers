import Primitives

/// An ordered key/value pair from a log record (CEF extension, `KEY=value` body, or
/// structured-data parameter). Order and duplicates are preserved by the containers.
///
/// Invariant: the key is 1...``maxKeyLength`` characters and contains no whitespace,
/// `=`, `"` or `]`. The value is free text (possibly empty).
public struct KeyValuePair: CodableInvariant, Sendable, Hashable {
    public struct Raw: Codable, Sendable, Hashable {
        public var key: String
        public var value: String

        public init(key: String, value: String) {
            self.key = key
            self.value = value
        }
    }

    public static let maxKeyLength = 64

    public let key: String
    public let value: String

    public var raw: Raw {
        Raw(key: key, value: value)
    }

    public init(_ raw: Raw) throws(InvarianceFailure) {
        guard !raw.key.isEmpty else {
            throw .at("key", InvarianceBlankText())
        }
        guard raw.key.count <= Self.maxKeyLength else {
            throw .at("key", InvarianceLengthTooLong(maximum: UInt(Self.maxKeyLength), actual: UInt(raw.key.count)))
        }
        guard raw.key.allSatisfy(Self.isKeyCharacter) else {
            throw .at("key", LogFormatsReason.invalid_key_character)
        }
        self.key = raw.key
        self.value = raw.value
    }

    public init(_ key: String, _ value: String) throws(InvarianceFailure) {
        try self.init(Raw(key: key, value: value))
    }

    /// Characters allowed anywhere in a key.
    public static func isKeyCharacter(_ character: Character) -> Bool {
        !character.isWhitespace && character != "=" && character != "\"" && character != "]"
    }
}
