/// A minimal character cursor for the line-oriented formats in this module.
struct Scanner {
    private let characters: [Character]
    private(set) var index: Int = 0

    init<S: StringProtocol>(_ text: S) {
        self.characters = Array(text)
    }

    var isAtEnd: Bool { index >= characters.count }

    func peek(_ offset: Int = 0) -> Character? {
        let position = index + offset
        return position < characters.count ? characters[position] : nil
    }

    mutating func advance(by count: Int = 1) {
        index = min(index + count, characters.count)
    }

    /// Consumes `literal` if the input continues with it.
    mutating func consume(_ literal: String) -> Bool {
        let expected = Array(literal)
        guard index + expected.count <= characters.count,
              Array(characters[index..<(index + expected.count)]) == expected
        else {
            return false
        }
        index += expected.count
        return true
    }

    mutating func take(while predicate: (Character) -> Bool) -> String {
        let start = index
        while index < characters.count, predicate(characters[index]) {
            index += 1
        }
        return String(characters[start..<index])
    }

    mutating func skipSpaces() {
        _ = take { $0 == " " }
    }

    /// The next run of non-space characters, or nil at the end.
    mutating func token() -> String? {
        skipSpaces()
        let value = take { $0 != " " }
        return value.isEmpty ? nil : value
    }

    var remainder: String {
        String(characters[min(index, characters.count)...])
    }

    mutating func mark() -> Int { index }

    mutating func restore(_ mark: Int) { index = mark }
}
