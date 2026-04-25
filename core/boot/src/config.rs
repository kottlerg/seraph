// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/config.rs

//! Boot configuration parser for `\EFI\seraph\boot.conf`.
//!
//! Reads and parses the Seraph boot configuration file from the ESP. The file
//! format is a simple `key=value` text format with `#` comments.
//!
//! ## Format
//!
//! ```text
//! # Seraph boot configuration
//! path=\EFI\seraph
//! kernel=kernel
//! init=init
//! modules=procmgr, devmgr, vfsd, fat
//! cmdline=placeholder
//! ```
//!
//! - `path` — required. Base ESP directory. Prepended (with `\` separator) to
//!   kernel, init, and all module names to form full ESP paths.
//! - `kernel` — required. Kernel filename, resolved against `path`.
//! - `init` — required. Init filename, resolved against `path`.
//! - `modules` — optional. Comma-separated module filenames. Whitespace around
//!   each name is trimmed; empty tokens are skipped. Absent or empty means no
//!   additional modules.
//! - `cmdline` — optional. Passed verbatim to the kernel via
//!   `BootInfo.command_line`. Absent means empty command line.

/// Maximum number of characters in a config-file path value (base + separator
/// + filename). Used to size the `Utf16Path` buffer.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum number of boot modules that may be listed in `boot.conf`.
///
/// Covers a typical early-boot module set (procmgr, devmgr, block driver,
/// FS driver, vfsd, netd) with room for future additions.
pub const MAX_MODULES: usize = 16;

/// Maximum length of the kernel command line string in bytes.
pub const MAX_CMDLINE_LEN: usize = 512;

/// Maximum size of the boot configuration file in bytes.
pub const MAX_CONFIG_SIZE: usize = 4096;

/// A null-terminated UTF-16 path string backed by a fixed-size stack buffer.
///
/// Used to pass file paths to `EFI_FILE_PROTOCOL->Open()` without heap
/// allocation. The path is always ASCII-widened: each source byte becomes one
/// UTF-16 code unit.
#[derive(Clone, Copy)]
pub struct Utf16Path
{
    buf: [u16; MAX_PATH_LEN + 1],
    len: usize,
}

impl Utf16Path
{
    /// Return a pointer to the null-terminated UTF-16 string.
    ///
    /// The returned pointer is valid as long as this struct is alive.
    pub fn as_ptr(&self) -> *const u16
    {
        self.buf.as_ptr()
    }

    /// Construct a zero-initialised (empty, null-terminated) path.
    const fn zeroed() -> Self
    {
        Self {
            buf: [0u16; MAX_PATH_LEN + 1],
            len: 0,
        }
    }
}

/// Configuration loaded from `\EFI\seraph\boot.conf`.
pub struct BootConfig
{
    /// UTF-16 representation of the `path` value (base ESP directory).
    ///
    /// Retained for diagnostic use; path resolution is fully done during
    /// parsing so callers do not need to access this field directly.
    #[allow(dead_code)]
    pub base_path: Utf16Path,
    /// Full resolved kernel path: `path` + `\` + kernel name.
    pub kernel_path: Utf16Path,
    /// Full resolved init path: `path` + `\` + init name.
    pub init_path: Utf16Path,
    /// Full resolved paths for each additional boot module.
    ///
    /// Valid entries occupy indices `[0..module_count]`.
    pub module_paths: [Utf16Path; MAX_MODULES],
    /// Number of valid entries in `module_paths`.
    pub module_count: usize,
    /// Raw ASCII bytes of the kernel command line (not null-terminated).
    ///
    /// Valid bytes occupy `[0..cmdline_len]`.
    pub cmdline: [u8; MAX_CMDLINE_LEN],
    /// Number of valid bytes in `cmdline`.
    pub cmdline_len: usize,
}

/// Widen an ASCII byte slice into a `Utf16Path`.
///
/// Returns `false` if any byte is non-ASCII (> 0x7F) or if the path exceeds
/// `MAX_PATH_LEN` characters. On success, the buffer is null-terminated and
/// `len` is set to the number of code units written (not counting the null).
fn ascii_to_utf16(path: &[u8], out: &mut Utf16Path) -> bool
{
    if path.len() > MAX_PATH_LEN
    {
        return false;
    }
    for (i, &b) in path.iter().enumerate()
    {
        if b > 0x7F
        {
            return false;
        }
        out.buf[i] = u16::from(b);
    }
    out.buf[path.len()] = 0u16;
    out.len = path.len();
    true
}

/// Concatenate `base + '\' + name` into `out` as a null-terminated UTF-16 path.
///
/// Returns `false` if the combined length exceeds `MAX_PATH_LEN` or if any
/// byte in `base` or `name` is non-ASCII (> 0x7F).
fn resolve_path(base: &[u8], name: &[u8], out: &mut Utf16Path) -> bool
{
    // Total length: base + backslash separator + name.
    let Some(total) = base
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(name.len()))
    else
    {
        return false;
    };
    if total > MAX_PATH_LEN
    {
        return false;
    }

    for (i, &b) in base.iter().enumerate()
    {
        if b > 0x7F
        {
            return false;
        }
        out.buf[i] = u16::from(b);
    }
    out.buf[base.len()] = u16::from(b'\\');
    for (i, &b) in name.iter().enumerate()
    {
        if b > 0x7F
        {
            return false;
        }
        out.buf[base.len() + 1 + i] = u16::from(b);
    }
    out.buf[total] = 0u16;
    out.len = total;
    true
}

/// Parse a `boot.conf` byte slice into a `BootConfig`.
///
/// ## Format
///
/// One `key=value` pair per line; `#` introduces a comment; blank lines are
/// ignored. Unknown keys are silently skipped for forward compatibility.
/// `path`, `kernel`, and `init` are required. `modules` and `cmdline` are
/// optional.
///
/// Whitespace (space, tab, `\r`) is trimmed from keys and values. Module names
/// in `modules` are comma-separated; whitespace around each name is trimmed and
/// empty tokens are skipped. Paths are resolved as `path\<name>`. The `cmdline`
/// string is copied verbatim into a fixed-size buffer.
// This parser handles five key types, inline comment/blank-line filtering, module
// list tokenisation, and path resolution — necessarily longer than 100 lines.
#[allow(clippy::too_many_lines)]
pub fn parse_config(data: &[u8]) -> Result<BootConfig, crate::error::BootError>
{
    // Collect raw byte-slice views into `data` for each key.
    // These are set during the line-parsing loop and resolved after.
    let mut raw_path: Option<&[u8]> = None;
    let mut raw_kernel: Option<&[u8]> = None;
    let mut raw_init: Option<&[u8]> = None;
    let mut raw_modules: Option<&[u8]> = None;
    let mut raw_cmdline: Option<&[u8]> = None;

    // Split on '\n'; handle '\r\n' line endings via trim_ascii below.
    let mut remaining = data;
    loop
    {
        if remaining.is_empty()
        {
            break;
        }

        let (line_bytes, rest) = match remaining.iter().position(|&b| b == b'\n')
        {
            Some(pos) => (&remaining[..pos], &remaining[pos + 1..]),
            None => (remaining, &[][..]),
        };
        remaining = rest;

        let line = trim_ascii(line_bytes);

        // Skip blank lines and comment lines.
        if line.is_empty() || line[0] == b'#'
        {
            continue;
        }

        // Every non-blank, non-comment line must contain '='.
        let Some(eq) = line.iter().position(|&b| b == b'=')
        else
        {
            return Err(crate::error::BootError::InvalidConfig(
                "missing '=' in line",
            ));
        };

        let key = trim_ascii(&line[..eq]);
        let value = trim_ascii(&line[eq + 1..]);

        if key == b"path"
        {
            raw_path = Some(value);
        }
        else if key == b"kernel"
        {
            raw_kernel = Some(value);
        }
        else if key == b"init"
        {
            raw_init = Some(value);
        }
        else if key == b"modules"
        {
            raw_modules = Some(value);
        }
        else if key == b"cmdline"
        {
            raw_cmdline = Some(value);
        }
        // Unknown keys: skip silently.
    }

    // All three required keys must be present.
    let path_bytes =
        raw_path.ok_or(crate::error::BootError::InvalidConfig("missing 'path' key"))?;
    let kernel_bytes = raw_kernel.ok_or(crate::error::BootError::InvalidConfig(
        "missing 'kernel' key",
    ))?;
    let init_bytes =
        raw_init.ok_or(crate::error::BootError::InvalidConfig("missing 'init' key"))?;

    // Convert the base path to UTF-16 for direct use by EFI_FILE_PROTOCOL.
    let mut base_path = Utf16Path::zeroed();
    if !ascii_to_utf16(path_bytes, &mut base_path)
    {
        return Err(crate::error::BootError::InvalidConfig("path value invalid"));
    }

    // Resolve kernel_path = path + '\' + kernel name.
    let mut kernel_path = Utf16Path::zeroed();
    if !resolve_path(path_bytes, kernel_bytes, &mut kernel_path)
    {
        return Err(crate::error::BootError::InvalidConfig(
            "kernel path invalid",
        ));
    }

    // Resolve init_path = path + '\' + init name.
    let mut init_path = Utf16Path::zeroed();
    if !resolve_path(path_bytes, init_bytes, &mut init_path)
    {
        return Err(crate::error::BootError::InvalidConfig("init path invalid"));
    }

    // Parse the comma-separated module list and resolve each name against path.
    // To add support for quoted names or semicolon separators, modify this loop.
    let mut module_paths = [Utf16Path::zeroed(); MAX_MODULES];
    let mut module_count: usize = 0;

    if let Some(mod_list) = raw_modules
    {
        let mut cursor = mod_list;
        loop
        {
            let (token, rest) = match cursor.iter().position(|&b| b == b',')
            {
                Some(pos) => (&cursor[..pos], &cursor[pos + 1..]),
                None => (cursor, &[][..]),
            };
            cursor = rest;

            let name = trim_ascii(token);
            if !name.is_empty()
            {
                if module_count >= MAX_MODULES
                {
                    return Err(crate::error::BootError::InvalidConfig(
                        "too many modules (max 16)",
                    ));
                }
                if !resolve_path(path_bytes, name, &mut module_paths[module_count])
                {
                    return Err(crate::error::BootError::InvalidConfig(
                        "module path invalid",
                    ));
                }
                module_count += 1;
            }

            if cursor.is_empty()
            {
                break;
            }
        }
    }

    // Copy cmdline bytes into the fixed buffer (no null terminator here;
    // main.rs appends one when writing into the cmdline page).
    let mut cmdline = [0u8; MAX_CMDLINE_LEN];
    let mut cmdline_len: usize = 0;
    if let Some(cl) = raw_cmdline
    {
        if cl.len() > MAX_CMDLINE_LEN
        {
            return Err(crate::error::BootError::InvalidConfig(
                "cmdline exceeds maximum length",
            ));
        }
        cmdline[..cl.len()].copy_from_slice(cl);
        cmdline_len = cl.len();
    }

    Ok(BootConfig {
        base_path,
        kernel_path,
        init_path,
        module_paths,
        module_count,
        cmdline,
        cmdline_len,
    })
}

/// Trim leading and trailing ASCII whitespace (space, tab, `\r`) from a byte slice.
fn trim_ascii(s: &[u8]) -> &[u8]
{
    let is_ws = |b: &u8| *b == b' ' || *b == b'\t' || *b == b'\r';
    let start = s.iter().position(|b| !is_ws(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !is_ws(b)).map_or(0, |i| i + 1);
    if start >= end { &[] } else { &s[start..end] }
}

/// Open `\EFI\seraph\boot.conf`, read it into a 4096-byte stack buffer, and
/// parse it with [`parse_config`].
///
/// # Safety
/// `esp_root` must be a valid `EFI_FILE_PROTOCOL` directory handle.
pub unsafe fn load_boot_config(
    esp_root: *mut crate::uefi::EfiFileProtocol,
) -> Result<BootConfig, crate::error::BootError>
{
    // Null-terminated UTF-16 path to the config file.
    // '\', 'E', 'F', 'I', '\', 's', 'e', 'r', 'a', 'p', 'h', '\', 'b', 'o', 'o', 't', '.', 'c', 'o', 'n', 'f', NUL
    static BOOT_CONF_PATH: [u16; 22] = [
        b'\\' as u16,
        b'E' as u16,
        b'F' as u16,
        b'I' as u16,
        b'\\' as u16,
        b's' as u16,
        b'e' as u16,
        b'r' as u16,
        b'a' as u16,
        b'p' as u16,
        b'h' as u16,
        b'\\' as u16,
        b'b' as u16,
        b'o' as u16,
        b'o' as u16,
        b't' as u16,
        b'.' as u16,
        b'c' as u16,
        b'o' as u16,
        b'n' as u16,
        b'f' as u16,
        0u16,
    ];

    // SAFETY: esp_root is a valid directory handle; path is null-terminated UTF-16.
    let conf_file = unsafe {
        crate::uefi::open_file(
            esp_root,
            BOOT_CONF_PATH.as_ptr(),
            "\\EFI\\seraph\\boot.conf",
        )?
    };
    // SAFETY: conf_file is a valid open file handle.
    // cast_possible_truncation: file_size returns u64; on all UEFI targets
    // (x86_64, riscv64) usize is 64-bit so no truncation occurs.
    #[allow(clippy::cast_possible_truncation)]
    let conf_size = unsafe { crate::uefi::file_size(conf_file)? } as usize;
    if conf_size > MAX_CONFIG_SIZE
    {
        return Err(crate::error::BootError::InvalidConfig(
            "boot.conf exceeds maximum size",
        ));
    }

    // Read into a stack buffer — no heap allocation needed.
    let mut buf = [0u8; MAX_CONFIG_SIZE];
    // SAFETY: conf_file is open at position 0; buf[..conf_size] is within the allocation.
    unsafe { crate::uefi::file_read(conf_file, &mut buf[..conf_size])? };

    parse_config(&buf[..conf_size])
}

#[cfg(test)]
mod tests
{
    use super::*;

    // ── Existing tests updated for the new format ─────────────────────────────

    #[test]
    fn parse_config_succeeds_with_required_keys()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\n";
        let cfg = parse_config(input).unwrap();
        // base_path = "\EFI\seraph" (11 chars)
        assert_eq!(cfg.base_path.len, 11);
        // kernel_path = "\EFI\seraph\kernel" (18 chars)
        assert_eq!(cfg.kernel_path.len, 18);
        // init_path = "\EFI\seraph\init" (16 chars)
        assert_eq!(cfg.init_path.len, 16);
    }

    #[test]
    fn parse_config_skips_comments_and_blank_lines()
    {
        let input = b"# comment\n\npath=\\EFI\\seraph\nkernel=kernel\ninit=init\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.kernel_path.len, 18);
    }

    #[test]
    fn parse_config_trims_whitespace()
    {
        let input = b"path = \\EFI\\seraph\r\nkernel = kernel\r\ninit = init\r\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.kernel_path.len, 18);
    }

    #[test]
    fn parse_config_missing_path_returns_error()
    {
        let input = b"kernel=kernel\ninit=init\n";
        assert!(parse_config(input).is_err());
    }

    #[test]
    fn parse_config_missing_kernel_returns_error()
    {
        let input = b"path=\\EFI\\seraph\ninit=init\n";
        assert!(parse_config(input).is_err());
    }

    #[test]
    fn parse_config_missing_init_returns_error()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\n";
        assert!(parse_config(input).is_err());
    }

    #[test]
    fn parse_config_missing_equals_returns_error()
    {
        let input = b"path\\EFI\\seraph\nkernel=kernel\ninit=init\n";
        assert!(parse_config(input).is_err());
    }

    #[test]
    fn parse_config_unknown_keys_are_skipped()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\nfoo=bar\n";
        assert!(parse_config(input).is_ok());
    }

    // ── Module parsing ────────────────────────────────────────────────────────

    #[test]
    fn parse_config_no_modules_key_gives_zero_count()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.module_count, 0);
    }

    #[test]
    fn parse_config_empty_modules_value_gives_zero_count()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\nmodules=\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.module_count, 0);
    }

    #[test]
    fn parse_config_single_module()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\nmodules=procmgr\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.module_count, 1);
        // "\EFI\seraph\procmgr" = 19 chars
        assert_eq!(cfg.module_paths[0].len, 19);
    }

    #[test]
    fn parse_config_multiple_modules_with_whitespace()
    {
        let input =
            b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\nmodules=procmgr, devmgr, vfsd\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.module_count, 3);
        // "\EFI\seraph\procmgr" = 19
        assert_eq!(cfg.module_paths[0].len, 19);
        // "\EFI\seraph\devmgr" = 18
        assert_eq!(cfg.module_paths[1].len, 18);
        // "\EFI\seraph\vfsd" = 16
        assert_eq!(cfg.module_paths[2].len, 16);
    }

    #[test]
    fn parse_config_trailing_comma_in_modules_is_ignored()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\nmodules=procmgr,\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.module_count, 1);
    }

    #[test]
    fn parse_config_modules_only_commas_gives_zero_count()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\nmodules=,,,\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.module_count, 0);
    }

    // ── Cmdline parsing ───────────────────────────────────────────────────────

    #[test]
    fn parse_config_cmdline_absent_gives_zero_len()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.cmdline_len, 0);
    }

    #[test]
    fn parse_config_cmdline_present()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\ncmdline=hello world\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.cmdline_len, 11);
        assert_eq!(&cfg.cmdline[..11], b"hello world");
    }

    #[test]
    fn parse_config_cmdline_empty_value_gives_zero_len()
    {
        let input = b"path=\\EFI\\seraph\nkernel=kernel\ninit=init\ncmdline=\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.cmdline_len, 0);
    }

    // ── Path resolution ───────────────────────────────────────────────────────

    #[test]
    fn resolve_path_combines_base_and_name()
    {
        let mut p = Utf16Path::zeroed();
        let ok = resolve_path(b"\\EFI\\seraph", b"kernel", &mut p);
        assert!(ok);
        // "\EFI\seraph\kernel" = 18 chars
        assert_eq!(p.len, 18);
        // Verify backslash separator at position 11 (after "\EFI\seraph").
        assert_eq!(p.buf[11], b'\\' as u16);
        // Verify null terminator.
        assert_eq!(p.buf[18], 0u16);
    }

    #[test]
    fn resolve_path_rejects_non_ascii_in_base()
    {
        let mut p = Utf16Path::zeroed();
        let ok = resolve_path(b"path\x80", b"name", &mut p);
        assert!(!ok);
    }

    #[test]
    fn resolve_path_rejects_non_ascii_in_name()
    {
        let mut p = Utf16Path::zeroed();
        let ok = resolve_path(b"path", b"na\x80me", &mut p);
        assert!(!ok);
    }

    // ── Existing utility tests (unchanged) ────────────────────────────────────

    #[test]
    fn trim_ascii_removes_leading_and_trailing_whitespace()
    {
        let result = trim_ascii(b"  hello  ");
        assert_eq!(result, b"hello");
    }

    #[test]
    fn trim_ascii_returns_empty_slice_for_all_whitespace()
    {
        let result = trim_ascii(b"   \t\r  ");
        assert_eq!(result, b"");
    }

    #[test]
    fn ascii_to_utf16_widens_correctly()
    {
        let mut p = Utf16Path::zeroed();
        let ok = ascii_to_utf16(b"\\EFI\\seraph\\init", &mut p);
        assert!(ok);
        assert_eq!(p.len, 16);
        assert_eq!(p.buf[0], b'\\' as u16);
        assert_eq!(p.buf[16], 0u16);
    }

    #[test]
    fn ascii_to_utf16_rejects_non_ascii()
    {
        let mut p = Utf16Path::zeroed();
        let ok = ascii_to_utf16(b"path\x80here", &mut p);
        assert!(!ok);
    }
}
