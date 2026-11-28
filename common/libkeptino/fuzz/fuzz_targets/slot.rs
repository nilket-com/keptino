#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| libkeptino::fuzz::slot(data));
