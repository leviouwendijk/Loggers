# Loggers

Server logging, plus typed log record formats and the contract of a log collector.

| Product | Purpose | Depends on |
|---|---|---|
| `Loggers` | `StandardLogger`, activity logs, `LogAliasBank` | Milieu, Writers |
| `LogFormats` | Log record types (syslog, CEF, key=value) as Primitives invariants | Primitives |
| `LogFormatsParsing` | Total parsers producing `LogFormats` values | LogFormats |
| `LogCollection` | Collector wire contract: stored `LogEntry`, `EntriesQuery`, `EntriesResponse`, `CollectorStats` | LogFormats, Primitives |
| `t_log_formats` | Test executable (`Testing/LogFormatsTests`, Testing lib) | all of the above |

```
sbm test       # runs t_log_formats (build-object.pkl tests {})
```

Used by the syslogger service (api-hondenmeesters `api/swift/syslogger/v1`), which receives the UDM's SIEM export, and by `unifi logs` (UniFi package), which reads it.

## Invariants (`LogFormats`, `LogCollection`)

Each type with a real invariant conforms to Primitives' `CodableInvariant`. `init(_ raw:) throws(InvarianceFailure)` is the only way in, and decoding goes through it, so a decoded value carries the same guarantee as a constructed one. Failures carry a code and a field path (for example `extensions[1].key`).

| Type | Raw | Invariant |
|---|---|---|
| `KeyValuePair` | `{key, value}` | key 1–64 characters, no whitespace, `=`, `"` or `]` |
| `SyslogPriority` | `Int` | 0–191; exposes `facility`, `severity` |
| `SyslogStructuredDataElement` | `{id, parameters}` | SD-ID and parameter names: 1–32 printable US-ASCII, no `=`, space, `]`, `"` (RFC 5424 §6.3) |
| `CEFRecord` | `{version, deviceVendor, …, extensions}` | `version >= 0`; extension keys start with a letter and contain only letters, digits, `_`, `.` |
| `EntriesQuery` | `{since?, until?, contains?, field?, value?, limit?}` | ISO 8601 dates (fractional seconds allowed), `since <= until`; `field`/`value` together; no blank `field`/`contains`; `limit` 1–2000 (default 200) |

`SyslogMessage`, `LogEntry`, `EntriesResponse` and `CollectorStats` are plain records of values that are already guaranteed; they add no constraint of their own.

The parsers use the same predicates the invariants check (`CEFRecord.isKeyStart` / `isKeyCharacter`, `KeyValuePair.isKeyCharacter`, `SyslogStructuredDataElement.isNameCharacter`), so parser output always satisfies them. A part that would not is dropped, never stored half-valid.

## Input formats (`LogFormatsParsing`)

`SyslogParser.parse(_:)` is total: every datagram produces a `SyslogMessage`.

**Envelope**, after an optional `<PRI>`:

| Detected as | Shape | Notes |
|---|---|---|
| `unstructured` | `CEF:…` directly after PRI | no envelope |
| `rfc5424` | `1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG` | `-` means nil; SD `[id k="v" …]` with `\"`, `\\`, `\]` escapes; leading BOM removed; invalid SD falls back to `unstructured` |
| `rfc3164` | `Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG` | day may be space-padded; text starting with `CEF:` after the hostname is the body, not a tag (UniFi's format) |
| `unstructured` | anything else | whole text is the body |

**Payload:**

| Payload | When | Value |
|---|---|---|
| `cef` | body starts with `CEF:` and is valid | `CEFRecord` |
| `malformedCEF` | body starts with `CEF:` but is invalid | `CEFParseError`: `missingPrefix`, `invalidVersion`, `incompleteHeader(fieldsFound:)`, `invalidRecord` |
| `keyValues` | `KEY=value` / `KEY="quoted"` pairs | ordered `KeyValuePair`s (iptables-style `DESCR=… SRC=… DPT=…`) |
| `text` | otherwise | — |

**CEF:** the header is `CEF:Version|Vendor|Product|DeviceVersion|EventClassID|Name|Severity|`, with `\|` and `\\` escapes. In the extension, a value runs until the next ` key=`, so values can contain spaces (`UNIFIhost=Office UDM Pro`). Extension escapes are `\=`, `\\`, `\n` and `\r`; other backslashes are kept. Duplicate keys keep their order, and lookup returns the last.

## Stored entry (`LogCollection.LogEntry`)

`LogEntry(message:raw:source:receivedAt:)` flattens a parsed message into one JSON object:

| Field | Meaning |
|---|---|
| `received_at`, `source` | arrival time (ISO 8601) and sender IP |
| `format` | `rfc5424`, `rfc3164`, `unstructured` |
| `facility`, `severity` | from PRI; severity as a name (`informational`, `warning`, …) |
| `timestamp`, `host`, `app`, `procid`, `msgid` | envelope fields as sent |
| `message` | body after the envelope |
| `payload` | `cef`, `malformed_cef`, `key_values`, `text` |
| `parse_error` | set for `malformed_cef` |
| `cef` | the typed `CEFRecord` when `payload == "cef"` |
| `fields` | for queries: `cef_*` header fields and CEF extension keys (`UNIFIcategory`, `src`, `msg`, …), key=value pairs, SD parameters as `<sd-id>.<name>` |
| `raw` | the datagram as received; kept so entries can be re-parsed |
