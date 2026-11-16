import Primitives

/// Reasons specific to log-format values. Generic reasons (blank text, bounds)
/// use Primitives' own `Invariance…` types.
public enum LogFormatsReason: InvarianceReason, Equatable {
    /// A key contains whitespace, `=`, `"` or `]`, or a character the format forbids.
    case invalid_key_character
    /// A CEF extension key does not start with a letter.
    case invalid_key_start
    /// An RFC 5424 SD-ID or SD-NAME is outside printable US-ASCII or contains `=`, space, `]` or `"`.
    case invalid_structured_data_name

    public var code: InvarianceCode {
        .custom("log_formats.\(self)")
    }

    public var message: String {
        switch self {
        case .invalid_key_character:
            return "A key must not contain whitespace, '=', '\"' or ']'."
        case .invalid_key_start:
            return "A CEF extension key must start with a letter."
        case .invalid_structured_data_name:
            return "SD-IDs and parameter names are printable ASCII without '=', space, ']' or '\"'."
        }
    }
}

extension InvarianceFailure {
    static func at(_ field: String, _ reason: any InvarianceReason) -> InvarianceFailure {
        InvarianceFailure(InvarianceViolation(reason, path: [.field(field)]))
    }

    func prefixed(_ component: InvariancePathComponent) -> InvarianceFailure {
        InvarianceFailure(first.prepending(component), remaining: remaining.map { $0.prepending(component) })
    }
}
