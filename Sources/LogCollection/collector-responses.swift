/// Response of `POST entries`.
public struct EntriesResponse: Codable, Sendable, Hashable {
    public let count: Int
    /// More entries matched than `limit` allowed.
    public let truncated: Bool
    public let entries: [LogEntry]

    public init(entries: [LogEntry], truncated: Bool) {
        self.count = entries.count
        self.truncated = truncated
        self.entries = entries
    }
}

/// Response of `GET stats`: collector counters and settings.
public struct CollectorStats: Codable, Sendable, Hashable {
    public struct DayFile: Codable, Sendable, Hashable {
        public let day: String
        public let bytes: Int

        public init(day: String, bytes: Int) {
            self.day = day
            self.bytes = bytes
        }
    }

    public let started_at: String
    public let udp_port: Int
    public let allowed_sources: [String]
    public let directory: String
    public let retention_days: Int
    public let received: Int
    public let rejected: Int
    public let last_received_at: String?
    /// Most recent rejected sender; useful when the source sends from an unexpected IP.
    public let last_rejected_source: String?
    public let write_failures: Int
    /// `recvfrom` errors on the UDP socket, and the most recent one.
    public let receive_failures: Int
    public let last_receive_error: String?
    public let files: [DayFile]

    public init(
        started_at: String,
        udp_port: Int,
        allowed_sources: [String],
        directory: String,
        retention_days: Int,
        received: Int,
        rejected: Int,
        last_received_at: String?,
        last_rejected_source: String?,
        write_failures: Int,
        receive_failures: Int,
        last_receive_error: String?,
        files: [DayFile]
    ) {
        self.started_at = started_at
        self.udp_port = udp_port
        self.allowed_sources = allowed_sources
        self.directory = directory
        self.retention_days = retention_days
        self.received = received
        self.rejected = rejected
        self.last_received_at = last_received_at
        self.last_rejected_source = last_rejected_source
        self.write_failures = write_failures
        self.receive_failures = receive_failures
        self.last_receive_error = last_receive_error
        self.files = files
    }
}
