// seraph-overlay: std::sys::env::seraph
//
// Backing for `std::env::{var, vars, set_var, remove_var}` on seraph.
//
// Storage model: a process-global `Mutex<BTreeMap<OsString, OsString>>` lazily
// initialised on first access. The seed source is `StartupInfo::env_blob` (a
// concatenation of NUL-terminated UTF-8 `KEY=VALUE` strings written by the
// spawner into the read-only `ProcessInfo` page). Spawner-side env wiring is
// not yet implemented, so the seed is currently empty in every process — the
// API works, but `var()` returns `None` for any key not first set with
// `set_var()` from inside this process.
//
// `BTreeMap` instead of `HashMap` to avoid std::collections::HashMap, which
// would pull in randomness for hash DoS resistance — seraph does not yet
// expose a kernel RNG (see `sys/random/seraph.rs` stub). The set is small
// (dozens of entries at most) and lookup is rare; ordered tree is fine.

use crate::collections::BTreeMap;
use crate::ffi::{OsStr, OsString};
use crate::io;
use crate::os::seraph::try_startup_info;
use crate::sync::{Mutex, OnceLock};

static ENV: OnceLock<Mutex<BTreeMap<OsString, OsString>>> = OnceLock::new();

fn env_map() -> &'static Mutex<BTreeMap<OsString, OsString>> {
    ENV.get_or_init(|| {
        let mut map = BTreeMap::new();
        if let Some(info) = try_startup_info() {
            seed_from_blob(&mut map, info.env_blob, info.env_count);
        }
        Mutex::new(map)
    })
}

/// Parse the spawner-written blob (concatenation of NUL-terminated
/// `KEY=VALUE` UTF-8 strings) into the process-global map. Entries without
/// a `=` are skipped — there's no sane interpretation. Invalid UTF-8 is
/// surfaced via `String::from_utf8_lossy` on the way through.
fn seed_from_blob(map: &mut BTreeMap<OsString, OsString>, blob: &[u8], count: usize) {
    let mut cursor = 0;
    let mut left = count;
    while left > 0 && cursor < blob.len() {
        let end = match blob[cursor..].iter().position(|&b| b == 0) {
            Some(off) => cursor + off,
            None => blob.len(),
        };
        if let Some(eq) = blob[cursor..end].iter().position(|&b| b == b'=') {
            let key = OsString::from(
                String::from_utf8_lossy(&blob[cursor..cursor + eq]).into_owned(),
            );
            let val = OsString::from(
                String::from_utf8_lossy(&blob[cursor + eq + 1..end]).into_owned(),
            );
            map.insert(key, val);
        }
        cursor = end.saturating_add(1);
        left -= 1;
    }
}

pub struct Env {
    items: crate::vec::IntoIter<(OsString, OsString)>,
}

impl crate::fmt::Debug for Env {
    fn fmt(&self, f: &mut crate::fmt::Formatter<'_>) -> crate::fmt::Result {
        f.debug_struct("Env").finish_non_exhaustive()
    }
}

impl Iterator for Env {
    type Item = (OsString, OsString);
    fn next(&mut self) -> Option<(OsString, OsString)> {
        self.items.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.items.size_hint()
    }
}

pub fn env() -> Env {
    let guard = env_map().lock().unwrap_or_else(|p| p.into_inner());
    let snapshot: Vec<(OsString, OsString)> =
        guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    Env { items: snapshot.into_iter() }
}

pub fn getenv(key: &OsStr) -> Option<OsString> {
    let guard = env_map().lock().unwrap_or_else(|p| p.into_inner());
    guard.get(key).cloned()
}

pub unsafe fn setenv(key: &OsStr, val: &OsStr) -> io::Result<()> {
    let mut guard = env_map().lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(key.to_os_string(), val.to_os_string());
    Ok(())
}

pub unsafe fn unsetenv(key: &OsStr) -> io::Result<()> {
    let mut guard = env_map().lock().unwrap_or_else(|p| p.into_inner());
    guard.remove(key);
    Ok(())
}
