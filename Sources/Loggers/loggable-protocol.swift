public protocol Loggable: 
    RawRepresentable,
    Comparable,
    Sendable,
    CaseIterable,
    Codable
    where RawValue == String {
        var precedence: Int { get }
        var label: String { get }
}

public extension Loggable {
    static func < (lhs: Self, rhs: Self) -> Bool {
        // lhs.precedence < rhs.precedence
        lhs.precedence > rhs.precedence
    }
}
