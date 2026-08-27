#![no_main]
use libfuzzer_sys::fuzz_target;

// Proves the Nmap XML parser is total: any bytes parse or error, never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = import::parse_nmap_hosts(s);
    }
});
