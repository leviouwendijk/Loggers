import Primitives

/// A syslog `<PRI>` value: `facility * 8 + severity`, 0...191.
///
/// Raw is the integer as written on the wire, which is also its JSON encoding.
public struct SyslogPriority: CodableInvariant, Sendable, Hashable {
    public enum Severity: Int, Sendable, Hashable, Codable, CaseIterable {
        case emergency = 0, alert, critical, error, warning, notice, informational, debug
    }

    public static let range = 0...191

    public let raw: Int

    public init(_ raw: Int) throws(InvarianceFailure) {
        guard raw >= Self.range.lowerBound else {
            throw .at("priority", InvarianceBelowMinimum(minimum: Self.range.lowerBound, actual: raw))
        }
        guard raw <= Self.range.upperBound else {
            throw .at("priority", InvarianceAboveMaximum(maximum: Self.range.upperBound, actual: raw))
        }
        self.raw = raw
    }

    /// 0...23 (e.g. 0 kern, 1 user, 4 auth, 16...23 local0...local7).
    public var facility: Int { raw / 8 }

    public var severity: Severity {
        // Total: raw % 8 is always 0...7.
        Severity(rawValue: raw % 8) ?? .debug
    }
}
