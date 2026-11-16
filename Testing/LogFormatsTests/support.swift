import Foundation
import LogFormats
import LogFormatsParsing
import Primitives
import Testing

/// UniFi doc examples, wrapped as the UDM sends them.
enum Fixture {
    static let adminAccessCEF =
        "CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIsubCategory=Admin UNIFIhost=Office UDM Pro UNIFIaccessMethod=web UNIFIadmin=Craig src=105.5.138.59 msg=Craig accessed UniFi Network using the web. Source IP: 105.5.138.59"

    static let wifiDisconnectCEF =
        "CEF:0|Ubiquiti|UniFi Network|9.3.33|401|WiFi Client Disconnected|2|UNIFIcategory=Monitoring UNIFIsubCategory=WiFi UNIFIhost=Office UDM Pro UNIFIlastConnectedToDeviceName=Lobby AP UNIFIlastConnectedToDeviceIp=192.168.100.5 UNIFIclientAlias=Apple Watch 0d:87 UNIFIduration=6m 22s UNIFIusageDown=11.78 KB UNIFIusageUp=4.46 KB UNIFInetworkSubnet=192.168.10.0/24 UNIFInetworkVlan=10 msg=Apple Watch 0d:87 disconnected from Employee WiFi. Time Connected: 6m 22s. Data Used: 4.46 KB (up) / 11.78 KB (down). Last Connected To: Lobby AP at -77 dBm."

    static func bsd(_ body: String, pri: Int = 14, host: String = "UDM-SE") -> String {
        "<\(pri)>Nov 16 18:30:01 \(host) \(body)"
    }

    static func cef(_ raw: String) throws -> CEFRecord {
        let message = SyslogParser.parse(raw)
        guard case .cef(let record) = message.payload else {
            throw TestFlowAssertionFailure(
                label: "fixture.cef",
                message: "expected a CEF payload",
                actual: String(describing: message.payload),
                expected: "cef"
            )
        }
        return record
    }
}

/// A pair known to be valid; fails the test if construction throws.
func kv(_ key: String, _ value: String) throws(InvarianceFailure) -> KeyValuePair {
    try KeyValuePair(key, value)
}

/// The first violation's code and path of a typed construction failure, or nil when it succeeded.
/// Usage: `violation(try KeyValuePair("a b", "x"))`.
func violation<T>(_ build: @autoclosure () throws(InvarianceFailure) -> T) -> (InvarianceCode, [InvariancePathComponent])? {
    do {
        _ = try build()
        return nil
    } catch {
        return (error.first.code, error.first.path)
    }
}

func caught(_ text: String) -> CEFParseError? {
    do {
        _ = try CEFParser.parse(text)
        return nil
    } catch {
        return error
    }
}
