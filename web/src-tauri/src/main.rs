#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// WebKitGTK reliability fallbacks for hostile environments (VMs without 3D,
/// CPUs without AVX). The end user cannot fix these; the app must just work.
/// All are set only when unset, so power users can still override.
///
/// 1. Rendering: WebKitGTK's GPU paths (DMA-BUF, threaded compositing) freeze
///    or crawl without working GL acceleration. Force the always-works
///    software path.
/// 2. JavaScriptCore: JSC's `ctiMasmProbeTrampoline` executes AVX
///    instructions (vmovaps) whenever any JIT tier is active. On CPUs without
///    AVX — old hardware, or VMs that mask AVX from the host (e.g. VMware on
///    Zen 4) — that is a SIGILL that kills the web process mid-operation and
///    leaves a gray frozen window. On such machines we disable the JIT
///    entirely (interpreted JS/WASM): slower, but the only config verified
///    stable. Machines with AVX keep the full JIT.
#[cfg(target_os = "linux")]
fn cpu_has_avx() -> bool {
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|cpuinfo| {
            cpuinfo
                .lines()
                .filter(|l| l.starts_with("flags"))
                .any(|l| l.split_whitespace().any(|f| f == "avx"))
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn webkit_software_fallback() {
    // Must run before GTK/WebKit spawn any threads or web processes.
    for (key, value) in [
        ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
        ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
    ] {
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
    if !cpu_has_avx() && std::env::var_os("JSC_useJIT").is_none() {
        std::env::set_var("JSC_useJIT", "0");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    webkit_software_fallback();
    desktop_lib::run();
}
