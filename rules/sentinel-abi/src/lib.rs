//! sentinel-abi: the binary event payload the WasmSentinel host hands to rule
//! modules through `detect_raw(ptr, len)`.
//!
//! Layout, all little-endian:
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 16 | header: magic `u32` = 0x3142_5357 ("WSB1"), version `u16` = 1, flags `u16`, record_len `u32` (= 592), strings_len `u32` |
//! | 16 | 592 | the kernel event record exactly as written by `host/internal/ebpf/bpf/sentinel.bpf.c` |
//! | 608 | strings_len | NUL-terminated strings resolved by the host: user, group, syscall_name |
//!
//! [`to_value`] rebuilds the JSON structure the host emits on the JSON path
//! (`collector.EventFromEBPF` in Go), so a rule can run one detection routine
//! on both encodings and the two paths agree by construction.

use serde_json::{json, Map, Value};

pub const MAGIC: u32 = 0x3142_5357;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const RECORD_LEN: usize = 592;

pub const EVENT_PROCESS_EXEC: u32 = 1;
pub const EVENT_PROCESS_EXIT: u32 = 2;
pub const EVENT_FILE_OPEN: u32 = 3;
pub const EVENT_NETWORK_CONNECT: u32 = 4;
pub const EVENT_NETWORK_ACCEPT: u32 = 5;
pub const EVENT_SYSCALL: u32 = 6;

const AF_INET: u16 = 2;

/// The kernel record. Field order and sizes mirror `struct event` in
/// `sentinel.bpf.c`; every member is naturally aligned so no padding exists.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawRecord {
    pub timestamp_ns: u64,
    pub retval: i64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub event_type: u32,
    pub syscall_nr: u32,
    pub flags: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u16,
    pub args_len: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub args: [u8; 256],
}

const _: () = assert!(core::mem::size_of::<RawRecord>() == RECORD_LEN);

impl Default for RawRecord {
    fn default() -> Self {
        // SAFETY: all-zero is a valid bit pattern for every field (integers and byte arrays).
        unsafe { core::mem::zeroed() }
    }
}

impl RawRecord {
    /// The record as bytes, in the layout the host writes.
    pub fn as_bytes(&self) -> &[u8; RECORD_LEN] {
        // SAFETY: RawRecord is repr(C), padding-free and exactly RECORD_LEN bytes.
        unsafe { &*(self as *const RawRecord as *const [u8; RECORD_LEN]) }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TooShort,
    BadMagic(u32),
    BadVersion(u16),
    BadLength,
}

/// A parsed payload: the record plus the host-resolved strings.
pub struct Payload<'a> {
    pub record: RawRecord,
    pub user: &'a str,
    pub group: &'a str,
    pub syscall_name: &'a str,
}

/// Parse a payload produced by the host (Go package `wire`).
pub fn parse(bytes: &[u8]) -> Result<Payload<'_>, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::TooShort);
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(Error::BadMagic(magic));
    }
    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if version != VERSION {
        return Err(Error::BadVersion(version));
    }
    let record_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let strings_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if record_len != RECORD_LEN || bytes.len() < HEADER_LEN + record_len + strings_len {
        return Err(Error::BadLength);
    }
    // SAFETY: bounds checked above; RawRecord accepts any bit pattern; read is unaligned.
    let record =
        unsafe { core::ptr::read_unaligned(bytes[HEADER_LEN..].as_ptr() as *const RawRecord) };
    let strings = &bytes[HEADER_LEN + RECORD_LEN..HEADER_LEN + RECORD_LEN + strings_len];
    let mut parts = strings.split(|b| *b == 0);
    let mut next = || {
        parts
            .next()
            .map(|b| core::str::from_utf8(b).unwrap_or(""))
            .unwrap_or("")
    };
    let user = next();
    let group = next();
    let syscall_name = next();
    Ok(Payload {
        record,
        user,
        group,
        syscall_name,
    })
}

/// Build a payload (the inverse of [`parse`]); the host does the same in Go.
pub fn encode(record: &RawRecord, user: &str, group: &str, syscall_name: &str) -> Vec<u8> {
    let strings_len = user.len() + group.len() + syscall_name.len() + 3;
    let mut out = Vec::with_capacity(HEADER_LEN + RECORD_LEN + strings_len);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(RECORD_LEN as u32).to_le_bytes());
    out.extend_from_slice(&(strings_len as u32).to_le_bytes());
    out.extend_from_slice(record.as_bytes());
    for s in [user, group, syscall_name] {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    out
}

/// Name of an event type, as used in event ids ("process_exec", ...).
pub fn type_name(event_type: u32) -> &'static str {
    match event_type {
        EVENT_PROCESS_EXEC => "process_exec",
        EVENT_PROCESS_EXIT => "process_exit",
        EVENT_FILE_OPEN => "file_open",
        EVENT_NETWORK_CONNECT => "network_connect",
        EVENT_NETWORK_ACCEPT => "network_accept",
        EVENT_SYSCALL => "syscall",
        _ => "unknown",
    }
}

/// Rebuild the host's JSON event (`events.Event` as emitted by
/// `collector.EventFromEBPF`) from a payload. The timestamp is omitted; rules
/// do not read it.
pub fn to_value(p: &Payload) -> Value {
    let r = &p.record;
    let comm = cstr(&r.comm);
    let mut data = Map::new();
    data.insert("pid".into(), json!(r.pid));
    data.insert("uid".into(), json!(r.uid));
    data.insert("comm".into(), json!(comm));

    let event_type = match r.event_type {
        EVENT_PROCESS_EXEC | EVENT_PROCESS_EXIT => {
            let (argv, truncated) = split_argv(&r.args, r.args_len);
            data.insert(
                "process".into(),
                json!({
                    "pid": r.pid as i32,
                    "ppid": r.ppid as i32,
                    "name": comm,
                    "executable": cstr(&r.filename),
                    "command_line": argv.join(" "),
                    "user": p.user,
                    "group": p.group,
                }),
            );
            if r.event_type == EVENT_PROCESS_EXEC {
                data.insert("action".into(), json!("exec"));
                if truncated {
                    data.insert("command_line_truncated".into(), json!(true));
                }
                "process"
            } else {
                data.insert("action".into(), json!("exit"));
                data.insert("exit_code".into(), json!(r.retval as i32));
                "process_exit"
            }
        }
        EVENT_FILE_OPEN => {
            data.insert(
                "file".into(),
                json!({
                    "path": cstr(&r.filename),
                    "operation": open_operation(r.flags),
                    "permissions": "",
                    "process_name": comm,
                    "user": p.user,
                }),
            );
            data.insert("flags".into(), json!(r.flags));
            "file"
        }
        EVENT_NETWORK_CONNECT | EVENT_NETWORK_ACCEPT => {
            let (src, dst) = if r.family == AF_INET {
                (ipv4(r.saddr), ipv4(r.daddr))
            } else {
                (String::new(), String::new())
            };
            data.insert(
                "network".into(),
                json!({
                    "protocol": "tcp",
                    "source_ip": src,
                    "source_port": r.sport as i64,
                    "dest_ip": dst,
                    "dest_port": r.dport as i64,
                    "direction": if r.event_type == EVENT_NETWORK_CONNECT { "outbound" } else { "inbound" },
                    "data_size": 0,
                    "process_name": comm,
                }),
            );
            data.insert("family".into(), json!(r.family));
            "network"
        }
        EVENT_SYSCALL => {
            data.insert("syscall_nr".into(), json!(r.syscall_nr));
            data.insert("syscall_name".into(), json!(p.syscall_name));
            data.insert("process_name".into(), json!(comm));
            data.insert("ppid".into(), json!(r.ppid));
            "syscall"
        }
        _ => "unknown",
    };

    json!({
        "id": format!("ebpf_{}_{}_{}", type_name(r.event_type), r.pid, r.timestamp_ns),
        "type": event_type,
        "source": "ebpf",
        "data": Value::Object(data),
    })
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Split the NUL-separated argv block the way the Go host does
/// (`bytes.Split(bytes.TrimRight(bs, "\x00"), []byte{0})`).
fn split_argv(args: &[u8; 256], n: u32) -> (Vec<String>, bool) {
    let n = (n as usize).min(args.len());
    if n == 0 {
        return (Vec::new(), false);
    }
    let bs = &args[..n];
    let truncated = n == args.len() && bs[n - 1] != 0;
    let end = bs.iter().rposition(|c| *c != 0).map_or(0, |i| i + 1);
    let argv = bs[..end]
        .split(|c| *c == 0)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    (argv, truncated)
}

const O_WRONLY: u32 = 0x1;
const O_RDWR: u32 = 0x2;
const O_CREAT: u32 = 0x40;
const O_TRUNC: u32 = 0x200;
const O_APPEND: u32 = 0x400;

fn open_operation(flags: u32) -> &'static str {
    if flags & O_CREAT != 0 {
        "create"
    } else if flags & (O_WRONLY | O_RDWR) != 0 || flags & (O_TRUNC | O_APPEND) != 0 {
        "write"
    } else {
        "read"
    }
}

fn ipv4(n: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        n & 0xff,
        (n >> 8) & 0xff,
        (n >> 16) & 0xff,
        (n >> 24) & 0xff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(dst: &mut [u8], s: &[u8]) -> u32 {
        dst[..s.len()].copy_from_slice(s);
        s.len() as u32
    }

    #[test]
    fn record_is_592_bytes() {
        assert_eq!(core::mem::size_of::<RawRecord>(), 592);
    }

    #[test]
    fn exec_round_trip_matches_host_shape() {
        let mut r = RawRecord::default();
        r.event_type = EVENT_PROCESS_EXEC;
        r.timestamp_ns = 7;
        r.pid = 4242;
        r.ppid = 1;
        put(&mut r.comm, b"bash");
        put(&mut r.filename, b"/usr/bin/bash");
        r.args_len = put(&mut r.args, b"bash\0-c\0rm -rf /tmp/x\0");
        let bytes = encode(&r, "root", "root", "");
        let p = parse(&bytes).unwrap();
        assert_eq!(p.user, "root");
        let v = to_value(&p);
        assert_eq!(v["type"], "process");
        assert_eq!(v["id"], "ebpf_process_exec_4242_7");
        assert_eq!(v["data"]["action"], "exec");
        assert_eq!(
            v["data"]["process"]["command_line"],
            "bash -c rm -rf /tmp/x"
        );
        assert_eq!(v["data"]["process"]["executable"], "/usr/bin/bash");
        assert_eq!(v["data"]["process"]["user"], "root");
        assert!(v["data"].get("command_line_truncated").is_none());
    }

    #[test]
    fn file_network_syscall_shapes() {
        let mut r = RawRecord::default();
        r.event_type = EVENT_FILE_OPEN;
        put(&mut r.filename, b"/etc/shadow");
        r.flags = O_WRONLY | O_TRUNC;
        let v = to_value(&parse(&encode(&r, "alice", "alice", "")).unwrap());
        assert_eq!(v["type"], "file");
        assert_eq!(v["data"]["file"]["operation"], "write");
        assert_eq!(v["data"]["file"]["path"], "/etc/shadow");

        let mut r = RawRecord::default();
        r.event_type = EVENT_NETWORK_CONNECT;
        r.family = AF_INET;
        r.daddr = 0x0101a8c0; // 192.168.1.1 in network byte order
        r.dport = 4444;
        let v = to_value(&parse(&encode(&r, "", "", "")).unwrap());
        assert_eq!(v["type"], "network");
        assert_eq!(v["data"]["network"]["dest_ip"], "192.168.1.1");
        assert_eq!(v["data"]["network"]["dest_port"], 4444);
        assert_eq!(v["data"]["network"]["direction"], "outbound");

        let mut r = RawRecord::default();
        r.event_type = EVENT_SYSCALL;
        r.syscall_nr = 101;
        let v = to_value(&parse(&encode(&r, "root", "root", "ptrace")).unwrap());
        assert_eq!(v["type"], "syscall");
        assert_eq!(v["data"]["syscall_name"], "ptrace");
        assert_eq!(v["data"]["syscall_nr"], 101);
    }

    #[test]
    fn rejects_bad_payloads() {
        assert_eq!(parse(&[0u8; 8]).err(), Some(Error::TooShort));
        let mut bytes = encode(&RawRecord::default(), "", "", "");
        bytes[0] ^= 0xff;
        assert!(matches!(parse(&bytes), Err(Error::BadMagic(_))));
        let mut bytes = encode(&RawRecord::default(), "", "", "");
        bytes[4] = 9;
        assert_eq!(parse(&bytes).err(), Some(Error::BadVersion(9)));
        let bytes = encode(&RawRecord::default(), "", "", "");
        assert_eq!(
            parse(&bytes[..bytes.len() - 1]).err(),
            Some(Error::BadLength)
        );
    }

    #[test]
    fn truncated_argv_is_flagged() {
        let mut r = RawRecord::default();
        r.event_type = EVENT_PROCESS_EXEC;
        r.args = [b'a'; 256];
        r.args_len = 256;
        let v = to_value(&parse(&encode(&r, "", "", "")).unwrap());
        assert_eq!(v["data"]["command_line_truncated"], true);
        assert_eq!(
            v["data"]["process"]["command_line"].as_str().unwrap().len(),
            256
        );
    }
}

// ---------------------------------------------------------------------------
// Field access without building a JSON tree.
//
// `EventFields` is the handful of fields the rules actually read. `JsonEvent`
// serves them from a parsed `serde_json::Value` (the JSON path); `RawEvent`
// serves them straight from the kernel record (the binary path) with no
// allocation except for the joined command line. A rule written against the
// trait therefore behaves identically on both paths and pays the parse cost on
// neither when fed the binary form.
// ---------------------------------------------------------------------------

use std::borrow::Cow;

/// The fields rules read, independent of the encoding they arrived in.
pub trait EventFields {
    /// "process", "process_exit", "file", "network", "syscall" or "".
    fn event_type(&self) -> &str;
    fn executable(&self) -> Option<&str>;
    /// process.name, file.process_name or network.process_name.
    fn process_name(&self) -> Option<&str>;
    fn command_line(&self) -> Option<Cow<'_, str>>;
    fn user(&self) -> Option<&str>;
    fn action(&self) -> Option<&str>;
    fn file_path(&self) -> Option<&str>;
    fn file_operation(&self) -> Option<&str>;
    fn dest_ip(&self) -> Option<Cow<'_, str>>;
    fn dest_port(&self) -> Option<i64>;
    fn protocol(&self) -> Option<&str>;
    fn direction(&self) -> Option<&str>;
    fn syscall_name(&self) -> Option<&str>;
    fn pid(&self) -> Option<u64>;
}

/// JSON-path view over `events.Event` as serialized by the host.
pub struct JsonEvent<'a>(pub &'a Value);

impl<'a> JsonEvent<'a> {
    fn data(&self) -> &'a Value {
        &self.0["data"]
    }
    fn block(&self) -> &'a Value {
        let d = self.data();
        match self.event_type() {
            "process" | "process_exit" => &d["process"],
            "file" => &d["file"],
            "network" => &d["network"],
            _ => &Value::Null,
        }
    }
}

impl<'a> EventFields for JsonEvent<'a> {
    fn event_type(&self) -> &str {
        self.0["type"].as_str().unwrap_or("")
    }
    fn executable(&self) -> Option<&str> {
        self.data()["process"]["executable"].as_str()
    }
    fn process_name(&self) -> Option<&str> {
        match self.event_type() {
            "process" | "process_exit" => self.data()["process"]["name"].as_str(),
            "syscall" => self.data()["process_name"].as_str(),
            _ => self.block()["process_name"].as_str(),
        }
    }
    fn command_line(&self) -> Option<Cow<'_, str>> {
        self.data()["process"]["command_line"]
            .as_str()
            .map(Cow::Borrowed)
    }
    fn user(&self) -> Option<&str> {
        self.block()["user"].as_str()
    }
    fn action(&self) -> Option<&str> {
        self.data()["action"].as_str()
    }
    fn file_path(&self) -> Option<&str> {
        self.data()["file"]["path"].as_str()
    }
    fn file_operation(&self) -> Option<&str> {
        self.data()["file"]["operation"].as_str()
    }
    fn dest_ip(&self) -> Option<Cow<'_, str>> {
        self.data()["network"]["dest_ip"]
            .as_str()
            .map(Cow::Borrowed)
    }
    fn dest_port(&self) -> Option<i64> {
        self.data()["network"]["dest_port"].as_i64()
    }
    fn protocol(&self) -> Option<&str> {
        self.data()["network"]["protocol"].as_str()
    }
    fn direction(&self) -> Option<&str> {
        self.data()["network"]["direction"].as_str()
    }
    fn syscall_name(&self) -> Option<&str> {
        self.data()["syscall_name"].as_str()
    }
    fn pid(&self) -> Option<u64> {
        self.data()["pid"].as_u64()
    }
}

/// Binary-path view straight over the kernel record.
pub struct RawEvent<'a>(pub &'a Payload<'a>);

fn cstr_ref(b: &[u8]) -> &str {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..end]).unwrap_or("")
}

impl<'a> RawEvent<'a> {
    fn rec(&self) -> &'a RawRecord {
        &self.0.record
    }
    fn is_process(&self) -> bool {
        matches!(
            self.rec().event_type,
            EVENT_PROCESS_EXEC | EVENT_PROCESS_EXIT
        )
    }
    fn is_network(&self) -> bool {
        matches!(
            self.rec().event_type,
            EVENT_NETWORK_CONNECT | EVENT_NETWORK_ACCEPT
        )
    }
}

impl<'a> EventFields for RawEvent<'a> {
    fn event_type(&self) -> &str {
        match self.rec().event_type {
            EVENT_PROCESS_EXEC => "process",
            EVENT_PROCESS_EXIT => "process_exit",
            EVENT_FILE_OPEN => "file",
            EVENT_NETWORK_CONNECT | EVENT_NETWORK_ACCEPT => "network",
            EVENT_SYSCALL => "syscall",
            _ => "",
        }
    }
    fn executable(&self) -> Option<&str> {
        self.is_process().then(|| cstr_ref(&self.rec().filename))
    }
    fn process_name(&self) -> Option<&str> {
        match self.rec().event_type {
            EVENT_PROCESS_EXEC
            | EVENT_PROCESS_EXIT
            | EVENT_FILE_OPEN
            | EVENT_NETWORK_CONNECT
            | EVENT_NETWORK_ACCEPT
            | EVENT_SYSCALL => Some(cstr_ref(&self.rec().comm)),
            _ => None,
        }
    }
    fn command_line(&self) -> Option<Cow<'_, str>> {
        if !self.is_process() {
            return None;
        }
        let (argv, _) = split_argv(&self.rec().args, self.rec().args_len);
        Some(Cow::Owned(argv.join(" ")))
    }
    fn user(&self) -> Option<&str> {
        match self.rec().event_type {
            EVENT_PROCESS_EXEC | EVENT_PROCESS_EXIT | EVENT_FILE_OPEN => Some(self.0.user),
            _ => None,
        }
    }
    fn action(&self) -> Option<&str> {
        match self.rec().event_type {
            EVENT_PROCESS_EXEC => Some("exec"),
            EVENT_PROCESS_EXIT => Some("exit"),
            _ => None,
        }
    }
    fn file_path(&self) -> Option<&str> {
        (self.rec().event_type == EVENT_FILE_OPEN).then(|| cstr_ref(&self.rec().filename))
    }
    fn file_operation(&self) -> Option<&str> {
        (self.rec().event_type == EVENT_FILE_OPEN).then(|| open_operation(self.rec().flags))
    }
    fn dest_ip(&self) -> Option<Cow<'_, str>> {
        if !self.is_network() {
            return None;
        }
        Some(if self.rec().family == AF_INET {
            Cow::Owned(ipv4(self.rec().daddr))
        } else {
            Cow::Borrowed("")
        })
    }
    fn dest_port(&self) -> Option<i64> {
        self.is_network().then(|| self.rec().dport as i64)
    }
    fn protocol(&self) -> Option<&str> {
        self.is_network().then_some("tcp")
    }
    fn direction(&self) -> Option<&str> {
        match self.rec().event_type {
            EVENT_NETWORK_CONNECT => Some("outbound"),
            EVENT_NETWORK_ACCEPT => Some("inbound"),
            _ => None,
        }
    }
    fn syscall_name(&self) -> Option<&str> {
        (self.rec().event_type == EVENT_SYSCALL).then_some(self.0.syscall_name)
    }
    fn pid(&self) -> Option<u64> {
        Some(self.rec().pid as u64)
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;

    fn put(dst: &mut [u8], s: &[u8]) -> u32 {
        dst[..s.len()].copy_from_slice(s);
        s.len() as u32
    }

    /// Every accessor must agree between the raw view and the JSON view of the
    /// same record, for every event type.
    #[test]
    fn raw_view_matches_json_view() {
        let mut records = Vec::new();
        let mut r = RawRecord::default();
        r.event_type = EVENT_PROCESS_EXEC;
        r.pid = 1;
        put(&mut r.comm, b"bash");
        put(&mut r.filename, b"/usr/bin/bash");
        r.args_len = put(&mut r.args, b"bash\0-c\0id\0");
        records.push((r, "root", "root", ""));
        let mut r = RawRecord::default();
        r.event_type = EVENT_PROCESS_EXIT;
        r.pid = 1;
        put(&mut r.comm, b"bash");
        records.push((r, "root", "root", ""));
        let mut r = RawRecord::default();
        r.event_type = EVENT_FILE_OPEN;
        put(&mut r.comm, b"vi");
        put(&mut r.filename, b"/etc/shadow");
        r.flags = O_WRONLY | O_TRUNC;
        records.push((r, "alice", "", ""));
        let mut r = RawRecord::default();
        r.event_type = EVENT_NETWORK_CONNECT;
        put(&mut r.comm, b"nc");
        r.family = AF_INET;
        r.daddr = 0x0401_02_01u32.swap_bytes();
        r.dport = 4444;
        records.push((r, "", "", ""));
        let mut r = RawRecord::default();
        r.event_type = EVENT_NETWORK_ACCEPT;
        r.family = 10;
        r.dport = 22;
        records.push((r, "", "", ""));
        let mut r = RawRecord::default();
        r.event_type = EVENT_SYSCALL;
        put(&mut r.comm, b"gdb");
        r.syscall_nr = 101;
        records.push((r, "", "", "ptrace"));

        for (rec, user, group, sys) in records {
            let bytes = encode(&rec, user, group, sys);
            let payload = parse(&bytes).unwrap();
            let value = to_value(&payload);
            let raw = RawEvent(&payload);
            let json = JsonEvent(&value);
            let t = raw.event_type();
            assert_eq!(raw.event_type(), json.event_type(), "{t}");
            assert_eq!(raw.executable(), json.executable(), "{t}");
            assert_eq!(raw.process_name(), json.process_name(), "{t}");
            assert_eq!(raw.command_line(), json.command_line(), "{t}");
            assert_eq!(raw.user(), json.user(), "{t}");
            assert_eq!(raw.action(), json.action(), "{t}");
            assert_eq!(raw.file_path(), json.file_path(), "{t}");
            assert_eq!(raw.file_operation(), json.file_operation(), "{t}");
            assert_eq!(raw.dest_ip(), json.dest_ip(), "{t}");
            assert_eq!(raw.dest_port(), json.dest_port(), "{t}");
            assert_eq!(raw.protocol(), json.protocol(), "{t}");
            assert_eq!(raw.direction(), json.direction(), "{t}");
            assert_eq!(raw.syscall_name(), json.syscall_name(), "{t}");
            assert_eq!(raw.pid(), json.pid(), "{t}");
        }
    }
}
