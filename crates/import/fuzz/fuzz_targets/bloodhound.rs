#![no_main]
use libfuzzer_sys::fuzz_target;

// Proves the SharpHound JSON parser is total on hostile input.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = import::parse_bloodhound(s);
    }
});
