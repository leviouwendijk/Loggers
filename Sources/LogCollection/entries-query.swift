import Foundation
import LogFormats
import Primitives

/// A query for collected entries (`POST entries`). Newest first.
///
/// Raw is the loose wire shape; constructing (or decoding, via `CodableInvariant`) enforces:
/// - `since` / `until` are ISO 8601 (with or without fractional seconds), and `since <= until`;
/// - `field` and `value` are given together, and `field` is not blank;
/// - `contains` is not blank when given;
/// - `limit` is 1...``maxLimit`` (``defaultLimit`` when absent).
public struct EntriesQuery: CodableInvariant, Sendable, Hashable {
    public struct Raw: Codable, Sendable, Hashable {
        public var since: String?
        public var until: String?
        public var contains: String?
        public var field: String?
        public var value: String?
        public var limit: Int?

        public init(
            since: String? = nil,
            until: String? = nil,
            contains: String? = nil,
            field: String? = nil,
            value: String? = nil,
            limit: Int? = nil
        ) {
            self.since = since
            self.until = until
            self.contains = contains
            self.field = field
            self.value = value
            self.limit = limit
        }
    }

    public struct FieldMatch: Sendable, Hashable {
        public let field: String
        public let value: String

        public init(field: String, value: String) {
            self.field = field
            self.value = value
        }
    }

    public static let defaultLimit = 200
    public static let maxLimit = 2000

    public let raw: Raw
    public let since: Date?
    public let until: Date?
    /// Lowercased for case-insensitive matching.
    public let contains: String?
    public let match: FieldMatch?
    public let limit: Int

    public init(_ raw: Raw) throws(InvarianceFailure) {
        let since = try Self.date(raw.since, field: "since")
        let until = try Self.date(raw.until, field: "until")
        if let since, let until, since > until {
            throw .at("since", LogCollectionReason.inverted_range)
        }

        if let contains = raw.contains, contains.trimmingCharacters(in: .whitespaces).isEmpty {
            throw .at("contains", InvarianceBlankText())
        }

        var match: FieldMatch?
        switch (raw.field, raw.value) {
        case (nil, nil):
            match = nil
        case (let field?, let value?):
            guard !field.trimmingCharacters(in: .whitespaces).isEmpty else {
                throw .at("field", InvarianceBlankText())
            }
            match = FieldMatch(field: field, value: value)
        case (nil, _):
            throw .at("field", LogCollectionReason.incomplete_pair)
        case (_, nil):
            throw .at("value", LogCollectionReason.incomplete_pair)
        }

        let limit = raw.limit ?? Self.defaultLimit
        guard limit >= 1 else {
            throw .at("limit", InvarianceBelowMinimum(minimum: 1, actual: limit))
        }
        guard limit <= Self.maxLimit else {
            throw .at("limit", InvarianceAboveMaximum(maximum: Self.maxLimit, actual: limit))
        }

        self.raw = raw
        self.since = since
        self.until = until
        self.contains = raw.contains?.lowercased()
        self.match = match
        self.limit = limit
    }

    /// Parses ISO 8601 with or without fractional seconds.
    public static func parseDate(_ text: String) -> Date? {
        let plain = ISO8601DateFormatter()
        if let date = plain.date(from: text) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: text)
    }

    private static func date(_ text: String?, field: String) throws(InvarianceFailure) -> Date? {
        guard let text else { return nil }
        guard let date = parseDate(text) else {
            throw .at(field, LogCollectionReason.invalid_timestamp)
        }
        return date
    }
}

/// Reasons specific to collector queries.
public enum LogCollectionReason: InvarianceReason, Equatable {
    case inverted_range
    case invalid_timestamp
    case incomplete_pair

    public var code: InvarianceCode {
        .custom("log_collection.\(self)")
    }

    public var message: String {
        switch self {
        case .inverted_range: return "'since' must not be later than 'until'."
        case .invalid_timestamp: return "Expected an ISO 8601 timestamp."
        case .incomplete_pair: return "'field' and 'value' must be given together."
        }
    }
}

extension InvarianceFailure {
    static func at(_ field: String, _ reason: any InvarianceReason) -> InvarianceFailure {
        InvarianceFailure(InvarianceViolation(reason, path: [.field(field)]))
    }
}
