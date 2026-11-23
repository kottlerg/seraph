// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/tests/exec.rs

//! The executor's panic catch. It replaces the process's panic hook, so it is
//! tested in a test binary of its own, where no other test can panic while
//! the hook is installed.

#[cfg(test)]
mod tests
{
    use std::fs::File;

    use fuzz_engine::cov::Counters;
    use fuzz_engine::exec::{Executor, Outcome, catch_panics, read_current};

    fn fails_on_a(data: &[u8])
    {
        assert!(data.first() != Some(&b'A'), "input starts with A");
    }

    // Defect caught: a panic that escapes the catch, is reported with another
    // location, or leaves the supervisor's file naming the wrong input.
    #[test]
    fn a_panic_is_caught_with_its_location_and_the_input_is_saved_first()
    {
        catch_panics();
        let path = std::env::temp_dir().join(format!("fuzz-engine-exec-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        // SAFETY: this test binary holds no instrumented code, so none runs at all.
        let counters = unsafe { Counters::registered() };
        let mut executor = Executor::new(fails_on_a, counters, Some(file));
        assert!(matches!(executor.run(b"BBBB"), Outcome::Passed));
        let Outcome::Panicked(record) = executor.run(b"AB")
        else
        {
            panic!("the property's panic was not caught");
        };
        let _ = std::panic::take_hook();
        assert_eq!(record.message, "input starts with A");
        assert!(record.location.contains("exec.rs"), "{}", record.location);
        let saved = std::fs::read(&path).unwrap();
        assert_eq!(read_current(&saved), Some((2, &b"AB"[..])));
        assert_eq!(executor.executions(), 2);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read_current(&[1, 2, 3]), None);
    }
}
