use common::{InterceptEvent, PrintEvent};

fn cstr(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..len]).unwrap_or("<invalid>")
}

pub fn handle_print_event(data: &[u8], nr_names: &std::collections::HashMap<u32, String>) -> i32 {
    let mut e = PrintEvent::default();
    if common::plain::copy_from_bytes(&mut e, data).is_err() {
        return 0;
    }
    let name = nr_names.get(&e.syscall_nr).map(|s| s.as_str()).unwrap_or("?");
    crate::log::info!(
        "pid={:<6} tid={:<6} uid={:<5} comm={:<16} {:<12} ret={:<4} file={}",
        e.pid, e.tid, e.uid, cstr(&e.comm), name, e.ret, cstr(&e.fname)
    );
    0
}

pub fn handle_intercept_event(data: &[u8]) -> i32 {
    let mut e = InterceptEvent::default();
    if common::plain::copy_from_bytes(&mut e, data).is_err() {
        return 0;
    }
    let from = cstr(&e.from);
    crate::log::info!(
        "[REDIRECT] pid={:<6} tid={:<6} uid={:<5} comm={:<16} {} -> {}",
        e.pid, e.tid, e.uid, cstr(&e.comm), from, cstr(&e.to)
    );
    if e.write_ret < 0 {
        eprintln!("[REDIRECT FAILED] pid={} write_user={} path={}", e.pid, e.write_ret, from);
    }
    0
}
