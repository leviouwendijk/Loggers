import Primitives

/// One RFC 5424 SD-ELEMENT: `[id name="value" ...]`.
///
/// Invariant: the SD-ID and every parameter name are 1...32 printable US-ASCII
/// characters (33...126) excluding `=`, space, `]` and `"` (RFC 5424 §6.3).
public struct SyslogStructuredDataElement: CodableInvariant, Sendable, Hashable {
    public struct Raw: Codable, Sendable, Hashable {
        public var id: String
        public var parameters: [KeyValuePair]

        public init(id: String, parameters: [KeyValuePair]) {
            self.id = id
            self.parameters = parameters
        }
    }

    public static let maxNameLength = 32

    public let id: String
    public let parameters: [KeyValuePair]

    public var raw: Raw {
        Raw(id: id, parameters: parameters)
    }

    public init(_ raw: Raw) throws(InvarianceFailure) {
        try Self.checkName(raw.id, field: "id")
        for (index, parameter) in raw.parameters.enumerated() {
            do {
                try Self.checkName(parameter.key, field: "key")
            } catch {
                throw error.prefixed(.index(index)).prefixed(.field("parameters"))
            }
        }
        self.id = raw.id
        self.parameters = raw.parameters
    }

    /// Whether `character` may appear in an SD-ID or SD-NAME.
    public static func isNameCharacter(_ character: Character) -> Bool {
        guard let scalar = character.unicodeScalars.first,
              character.unicodeScalars.count == 1,
              (33...126).contains(scalar.value)
        else {
            return false
        }
        return character != "=" && character != "]" && character != "\""
    }

    private static func checkName(_ name: String, field: String) throws(InvarianceFailure) {
        guard !name.isEmpty else {
            throw .at(field, InvarianceBlankText())
        }
        guard name.count <= maxNameLength else {
            throw .at(field, InvarianceLengthTooLong(maximum: UInt(maxNameLength), actual: UInt(name.count)))
        }
        guard name.allSatisfy(isNameCharacter) else {
            throw .at(field, LogFormatsReason.invalid_structured_data_name)
        }
    }
}
