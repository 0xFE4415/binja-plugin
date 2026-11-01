//! binja_plugin_native: native-speed MCP tools for Binary Ninja.
//!
//! Registers two BinaryView-scoped MCP tools:
//!
//! - `rx_data_find`: the Python plugin's `rex_data_find` contract with the
//!   byte scan running in native Rust (SIMD memchr prefilter + verification).
//! - `rx_multi_find`: many hex patterns in one pass via a multi-pattern
//!   automaton, a capability the Python plugin cannot offer.
//!
//! The plugin links against the core at the exact `api_REVISION.txt` commit of
//! the Binary Ninja this targets and registers its tools from `CorePluginInit`
//! so clients that cached the tool list before startup still see them.

mod hexpattern;
mod multi;
mod scan;
mod tools;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    if tools::register() {
        true
    } else {
        binaryninja::logger::bn_log(
            "binja_plugin_native",
            binaryninja::logger::BnLogLevel::ErrorLog,
            "failed to register rx_data_find / rx_multi_find MCP tools",
        );
        false
    }
}
