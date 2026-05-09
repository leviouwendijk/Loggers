import Foundation

public actor LogAliasBank {
    private var aliases: [String: String] = [:]
    private var counters: [String: Int] = [:]

    public init() {}

    public func alias(
        for rawValue: String?,
        namespace: String,
        prefix: String? = nil
    ) -> String {
        guard let normalized = Self.normalized(rawValue) else {
            return "\(Self.cleanPrefix(prefix ?? namespace))-UNKNOWN"
        }

        let key = Self.key(
            namespace: namespace,
            value: normalized
        )

        if let existing = aliases[key] {
            return existing
        }

        let next = (counters[namespace] ?? 0) + 1
        counters[namespace] = next

        let alias = "\(Self.cleanPrefix(prefix ?? namespace))-\(Self.base36(next, minWidth: 4))"
        aliases[key] = alias

        return alias
    }

    public func aliases(
        for rawValues: [String],
        namespace: String,
        prefix: String? = nil
    ) -> [String] {
        rawValues.map {
            alias(
                for: $0,
                namespace: namespace,
                prefix: prefix
            )
        }
    }

    public func aliasesForCommaSeparatedValues(
        _ rawValue: String?,
        namespace: String,
        prefix: String? = nil
    ) -> String {
        guard let rawValue else {
            return "none"
        }

        let values = rawValue
            .split(separator: ",")
            .map {
                String($0).trimmingCharacters(
                    in: .whitespacesAndNewlines
                )
            }
            .filter {
                !$0.isEmpty
            }

        guard !values.isEmpty else {
            return "none"
        }

        return aliases(
            for: values,
            namespace: namespace,
            prefix: prefix
        ).joined(separator: ",")
    }

    public func snapshot() -> [String: String] {
        aliases
    }

    public func reset() {
        aliases.removeAll()
        counters.removeAll()
    }

    private static func normalized(
        _ value: String?
    ) -> String? {
        guard let value else {
            return nil
        }

        let trimmed = value.trimmingCharacters(
            in: .whitespacesAndNewlines
        )

        guard !trimmed.isEmpty else {
            return nil
        }

        return trimmed
    }

    private static func key(
        namespace: String,
        value: String
    ) -> String {
        namespace + "\u{1F}" + value
    }

    private static func cleanPrefix(
        _ value: String
    ) -> String {
        let allowed = value
            .uppercased()
            .filter {
                $0.isLetter || $0.isNumber
            }

        return allowed.isEmpty ? "ID" : String(allowed)
    }

    private static func base36(
        _ value: Int,
        minWidth: Int
    ) -> String {
        let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        var number = max(value, 0)
        var output = ""

        repeat {
            let index = number % 36
            output.insert(alphabet[index], at: output.startIndex)
            number /= 36
        } while number > 0

        while output.count < minWidth {
            output.insert("0", at: output.startIndex)
        }

        return output
    }
}
