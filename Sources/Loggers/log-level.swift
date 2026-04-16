public enum LogLevel: String, Loggable {
    case debug 
    case info 
    case warn 
    case error 
    case critical 
    
    public var precedence: Int {
        switch self {
        case .critical:  return 0
        case .error:     return 1
        case .warn:      return 2
        case .info:      return 3
        case .debug:     return 4
        }
    }
    
    public var label: String {
        return self.rawValue.uppercased()
    }

    public static let warning: LogLevel = .warn 
}
