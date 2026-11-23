// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/path-account-plugin/src/qemu.rs

//! The plugin's side of QEMU's TCG plugin API (`qemu-plugin.h`, version 7):
//! the install entry point, and the callbacks that drive the
//! [`Recorder`].
//!
//! QEMU exports its plugin API from its own binary, and links `GLib`, so the
//! plugin resolves each function it calls in the process that loads it
//! (`dlsym(RTLD_DEFAULT)`) when it installs, and refuses to install when one
//! is missing. Nothing is linked against QEMU, so the crate also builds as
//! the library xtask reads the record through.
//!
//! The plugin takes one argument, `out=<file>`, the record's path, and
//! installs only into a system emulation of one vCPU, whose callbacks QEMU
//! makes from that vCPU's thread, one at a time; the state sits behind a
//! mutex all the same, since the exit callback comes from the main thread.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::fs::File;
use std::io::BufWriter;
use std::ptr;
use std::sync::{Mutex, PoisonError};

use crate::class::{Arch, Class, Dest};
use crate::recorder::{INSN_MAX, Recorder};

/// An opaque translation block (`struct qemu_plugin_tb`).
#[repr(C)]
struct Tb
{
    _opaque: [u8; 0],
}

/// An opaque instruction of a translation block (`struct qemu_plugin_insn`).
#[repr(C)]
struct Insn
{
    _opaque: [u8; 0],
}

/// An opaque scoreboard (`struct qemu_plugin_scoreboard`).
#[repr(C)]
struct Scoreboard
{
    _opaque: [u8; 0],
}

/// An opaque register handle (`struct qemu_plugin_register`).
#[repr(C)]
struct Register
{
    _opaque: [u8; 0],
}

/// `qemu_plugin_u64`: one `u64` of each vCPU's scoreboard entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct U64Entry
{
    score: *mut Scoreboard,
    _offset: usize,
}

/// `qemu_info_t`'s system half.
#[repr(C)]
#[derive(Clone, Copy)]
struct SystemInfo
{
    smp_vcpus: c_int,
    max_vcpus: c_int,
}

/// `qemu_info_t`.
#[repr(C)]
struct Info
{
    target_name: *const c_char,
    _version_min: c_int,
    version_cur: c_int,
    system_emulation: bool,
    system: SystemInfo,
}

/// `qemu_plugin_reg_descriptor`.
#[repr(C)]
struct RegDescriptor
{
    handle: *mut Register,
    name: *const c_char,
    _feature: *const c_char,
    _is_readonly: bool,
}

/// `GLib`'s `GArray`, as far as the plugin reads it.
#[repr(C)]
struct GArray
{
    /// `gchar *` in `GLib`'s header; `g_malloc` aligns it for any element.
    data: *mut c_void,
    len: c_uint,
}

/// `GLib`'s `GByteArray`.
#[repr(C)]
struct GByteArray
{
    data: *mut u8,
    len: c_uint,
}

/// `qemu_plugin_vcpu_tb_trans_cb_t`.
type TbTransCb = unsafe extern "C" fn(*mut Tb, *mut c_void);
/// `qemu_plugin_vcpu_udata_cb_t`.
type VcpuUdataCb = unsafe extern "C" fn(c_uint, *mut c_void);
/// `qemu_plugin_vcpu_discon_cb_t`.
type DisconCb = unsafe extern "C" fn(c_uint, c_int, u64, u64, *mut c_void);
/// `qemu_plugin_udata_cb_t`.
type UdataCb = unsafe extern "C" fn(*mut c_void);

/// `QEMU_PLUGIN_CB_NO_REGS`.
const CB_NO_REGS: c_int = 0;
/// `QEMU_PLUGIN_CB_R_REGS`.
const CB_R_REGS: c_int = 1;
/// `QEMU_PLUGIN_COND_NE`.
const COND_NE: c_int = 3;
/// `QEMU_PLUGIN_DISCON_ALL`.
const DISCON_ALL: c_int = -1;

unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Declares [`Api`], a field per function the plugin calls, and its
/// resolution.
macro_rules! api {
    ($($field:ident = $symbol:literal: fn($($arg:ty),*) $(-> $ret:ty)?;)*) => {
        /// The functions of QEMU's plugin API, and of `GLib`, the plugin calls.
        #[derive(Clone, Copy)]
        struct Api
        {
            $($field: unsafe extern "C" fn($($arg),*) $(-> $ret)?,)*
        }

        impl Api
        {
            /// Resolve every function in the loading process.
            fn resolve() -> Result<Self, String>
            {
                Ok(Self {
                    $($field: {
                        let symbol = lookup($symbol)?;
                        // SAFETY: `symbol` is the address of the function
                        // the header (`qemu-plugin.h`, API version 7) or GLib
                        // declares under this name, with this signature.
                        unsafe {
                            std::mem::transmute::<*mut c_void, unsafe extern "C" fn($($arg),*) $(-> $ret)?>(symbol)
                        }
                    },)*
                })
            }
        }
    };
}

api! {
    register_vcpu_tb_trans_cb = c"qemu_plugin_register_vcpu_tb_trans_cb":
        fn(u64, TbTransCb, *mut c_void);
    register_vcpu_discon_cb = c"qemu_plugin_register_vcpu_discon_cb":
        fn(u64, c_int, DisconCb, *mut c_void);
    register_vcpu_init_cb = c"qemu_plugin_register_vcpu_init_cb":
        fn(u64, VcpuUdataCb, *mut c_void);
    register_atexit_cb = c"qemu_plugin_register_atexit_cb": fn(u64, UdataCb, *mut c_void);
    tb_n_insns = c"qemu_plugin_tb_n_insns": fn(*const Tb) -> usize;
    tb_get_insn = c"qemu_plugin_tb_get_insn": fn(*const Tb, usize) -> *mut Insn;
    insn_data = c"qemu_plugin_insn_data": fn(*const Insn, *mut c_void, usize) -> usize;
    insn_vaddr = c"qemu_plugin_insn_vaddr": fn(*const Insn) -> u64;
    register_vcpu_insn_exec_cb = c"qemu_plugin_register_vcpu_insn_exec_cb":
        fn(*mut Insn, VcpuUdataCb, c_int, *mut c_void);
    register_vcpu_insn_exec_cond_cb = c"qemu_plugin_register_vcpu_insn_exec_cond_cb":
        fn(*mut Insn, VcpuUdataCb, c_int, c_int, U64Entry, u64, *mut c_void);
    scoreboard_new = c"qemu_plugin_scoreboard_new": fn(usize) -> *mut Scoreboard;
    scoreboard_find = c"qemu_plugin_scoreboard_find": fn(*mut Scoreboard, c_uint) -> *mut c_void;
    get_registers = c"qemu_plugin_get_registers": fn() -> *mut GArray;
    read_register = c"qemu_plugin_read_register": fn(*mut Register, *mut GByteArray) -> bool;
    g_array_free = c"g_array_free": fn(*mut GArray, c_int) -> *mut c_char;
    g_byte_array_new = c"g_byte_array_new": fn() -> *mut GByteArray;
    g_byte_array_set_size = c"g_byte_array_set_size": fn(*mut GByteArray, c_uint) -> *mut GByteArray;
}

/// The address of `symbol` in the loading process.
fn lookup(symbol: &CStr) -> Result<*mut c_void, String>
{
    // SAFETY: `symbol` is NUL-terminated; a null handle is glibc's
    // `RTLD_DEFAULT`, the global search order of the process.
    let address = unsafe { dlsym(ptr::null_mut(), symbol.as_ptr()) };
    if address.is_null()
    {
        Err(format!(
            "QEMU does not provide {}",
            symbol.to_string_lossy()
        ))
    }
    else
    {
        Ok(address)
    }
}

/// The plugin's state once installed.
struct Plugin
{
    api: Api,
    recorder: Recorder<BufWriter<File>>,
    /// The scoreboard whose one `u64` is set while a read's value is due:
    /// the value callback's condition.
    due: U64Entry,
    /// The vCPU's registers, by the name QEMU gives them.
    registers: Vec<(String, *mut Register)>,
    /// The buffer a register is read into.
    buffer: *mut GByteArray,
}

// SAFETY: the raw pointers `Plugin` holds (`due`'s scoreboard, the register
// handles, the read buffer) are QEMU's and GLib's objects, valid for the
// plugin's lifetime and used only under `STATE`'s lock.
unsafe impl Send for Plugin {}

/// The plugin, once `qemu_plugin_install` succeeded.
static STATE: Mutex<Option<Plugin>> = Mutex::new(None);

/// Run `f` on the installed plugin.
fn with_plugin(f: impl FnOnce(&mut Plugin))
{
    let mut state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(plugin) = state.as_mut()
    {
        f(plugin);
    }
}

/// The API version the plugin was written against; QEMU refuses a plugin
/// newer than itself.
#[unsafe(no_mangle)]
pub static qemu_plugin_version: c_int = 7;

/// The slot index a callback's `userdata` carries.
fn slot_of(userdata: *mut c_void) -> u32
{
    u32::try_from(userdata.addr()).unwrap_or(u32::MAX)
}

impl Plugin
{
    /// Set or clear the due flag.
    fn set_due(&self, value: u64)
    {
        // SAFETY: the scoreboard was made by `qemu_plugin_scoreboard_new` and
        // vCPU 0 exists once a callback runs.
        let entry = unsafe { (self.api.scoreboard_find)(self.due.score, 0) };
        if !entry.is_null()
        {
            // SAFETY: the scoreboard's elements are one aligned `u64` each
            // (`scoreboard_new(8)`), and only the vCPU's thread touches it
            // while the guest runs.
            unsafe { entry.cast::<u64>().write(value) };
        }
    }

    /// The register QEMU names `name`, read now, little-endian.
    fn register(&self, name: &str) -> Option<u64>
    {
        let handle = self.registers.iter().find(|(n, _)| n == name)?.1;
        let buffer = self.buffer;
        // SAFETY: `buffer` is the plugin's `GByteArray`; truncating it to
        // empty keeps its allocation.
        unsafe { (self.api.g_byte_array_set_size)(buffer, 0) };
        // SAFETY: `handle` came from `qemu_plugin_get_registers` for this
        // vCPU, and the value callback was registered with
        // `QEMU_PLUGIN_CB_R_REGS`.
        if !unsafe { (self.api.read_register)(handle, buffer) }
        {
            return None;
        }
        // SAFETY: `buffer` is a live `GByteArray`.
        let array = unsafe { &*buffer };
        // SAFETY: `read_register` appended the register's bytes to the array:
        // `data` holds `len` of them.
        let bytes = unsafe {
            std::slice::from_raw_parts(array.data, usize::try_from(array.len).unwrap_or(0))
        };
        let mut word = [0u8; 8];
        for (w, b) in word.iter_mut().zip(bytes)
        {
            *w = *b;
        }
        Some(u64::from_le_bytes(word))
    }

    /// The value a read left at `dest`.
    fn value(&self, dest: Dest) -> Option<u64>
    {
        match dest
        {
            Dest::EdxEax =>
            {
                let low = self.register("rax")? & 0xffff_ffff;
                let high = self.register("rdx")? & 0xffff_ffff;
                Some((high << 32) | low)
            }
            Dest::Gpr(rd) =>
            {
                let names = RISCV_GPRS.get(usize::from(rd))?;
                names.iter().find_map(|name| self.register(name))
            }
        }
    }
}

/// The names QEMU's riscv64 register description gives `x0` to `x31`.
const RISCV_GPRS: [&[&str]; 32] = [
    &["zero", "x0"],
    &["ra", "x1"],
    &["sp", "x2"],
    &["gp", "x3"],
    &["tp", "x4"],
    &["t0", "x5"],
    &["t1", "x6"],
    &["t2", "x7"],
    &["fp", "s0", "x8"],
    &["s1", "x9"],
    &["a0", "x10"],
    &["a1", "x11"],
    &["a2", "x12"],
    &["a3", "x13"],
    &["a4", "x14"],
    &["a5", "x15"],
    &["a6", "x16"],
    &["a7", "x17"],
    &["s2", "x18"],
    &["s3", "x19"],
    &["s4", "x20"],
    &["s5", "x21"],
    &["s6", "x22"],
    &["s7", "x23"],
    &["s8", "x24"],
    &["s9", "x25"],
    &["s10", "x26"],
    &["s11", "x27"],
    &["t3", "x28"],
    &["t4", "x29"],
    &["t5", "x30"],
    &["t6", "x31"],
];

/// QEMU's entry point: install the plugin.
///
/// # Safety
/// QEMU calls it once, with `info` valid for the call and `args` holding
/// `count` NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qemu_plugin_install(
    id: u64,
    info: *const c_void,
    count: c_int,
    args: *const *const c_char,
) -> c_int
{
    // SAFETY: the caller's contract.
    match unsafe { install(id, info.cast::<Info>(), count, args) }
    {
        Ok(()) => 0,
        Err(e) =>
        {
            eprintln!("path-account plugin: {e}");
            -1
        }
    }
}

/// [`qemu_plugin_install`]'s work.
///
/// # Safety
/// As [`qemu_plugin_install`].
unsafe fn install(
    id: u64,
    info: *const Info,
    count: c_int,
    args: *const *const c_char,
) -> Result<(), String>
{
    // SAFETY: QEMU passes a valid `qemu_info_t`.
    let info = unsafe { info.as_ref() }.ok_or("no system information")?;
    // SAFETY: `target_name` is a NUL-terminated string.
    let target = unsafe { CStr::from_ptr(info.target_name) }.to_string_lossy();
    let arch = Arch::from_target(&target).ok_or_else(|| format!("unknown target {target:?}"))?;
    if info.version_cur < qemu_plugin_version
    {
        return Err(format!("QEMU's plugin API is version {}", info.version_cur));
    }
    if !info.system_emulation
    {
        return Err("records a system emulation only".into());
    }
    if info.system.smp_vcpus != 1 || info.system.max_vcpus != 1
    {
        return Err(format!(
            "records a guest of one vCPU, not {} (at most {})",
            info.system.smp_vcpus, info.system.max_vcpus
        ));
    }
    let mut out = None;
    for i in 0..usize::try_from(count).unwrap_or(0)
    {
        // SAFETY: `args` holds `count` pointers, `i` is below `count`.
        let at = unsafe { args.add(i) };
        // SAFETY: `at` is one of those pointers, aligned and initialized.
        let pointer = unsafe { at.read() };
        // SAFETY: each is a NUL-terminated string.
        let arg = unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned();
        match arg.split_once('=')
        {
            Some(("out", path)) => out = Some(path.to_owned()),
            _ => return Err(format!("unknown argument {arg:?} (takes out=<file>)")),
        }
    }
    let out = out.ok_or("no out=<file> argument")?;
    let file = File::create(&out).map_err(|e| format!("creating {out}: {e}"))?;
    let api = Api::resolve()?;
    // SAFETY: a scoreboard of one `u64` per vCPU.
    let score = unsafe { (api.scoreboard_new)(8) };
    if score.is_null()
    {
        return Err("no scoreboard".into());
    }
    // SAFETY: GLib allocates the buffer; the plugin keeps it for its lifetime.
    let buffer = unsafe { (api.g_byte_array_new)() };
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(Plugin {
        api,
        recorder: Recorder::new(arch, BufWriter::with_capacity(1 << 20, file)),
        due: U64Entry { score, _offset: 0 },
        registers: Vec::new(),
        buffer,
    });
    // SAFETY: `id` is the plugin's, and `vcpu_init` is a
    // `qemu_plugin_vcpu_udata_cb_t`.
    unsafe { (api.register_vcpu_init_cb)(id, vcpu_init, ptr::null_mut()) };
    // SAFETY: `id` is the plugin's, and `tb_trans` is a
    // `qemu_plugin_vcpu_tb_trans_cb_t`.
    unsafe { (api.register_vcpu_tb_trans_cb)(id, tb_trans, ptr::null_mut()) };
    // SAFETY: `id` is the plugin's, and `discon` is a
    // `qemu_plugin_vcpu_discon_cb_t`.
    unsafe { (api.register_vcpu_discon_cb)(id, DISCON_ALL, discon, ptr::null_mut()) };
    // SAFETY: `id` is the plugin's, and `at_exit` is a `qemu_plugin_udata_cb_t`.
    unsafe { (api.register_atexit_cb)(id, at_exit, ptr::null_mut()) };
    Ok(())
}

/// The vCPU starts: note its registers' handles.
unsafe extern "C" fn vcpu_init(_vcpu: c_uint, _userdata: *mut c_void)
{
    with_plugin(|p| {
        // SAFETY: called in the vCPU's context, as the API requires.
        let array = unsafe { (p.api.get_registers)() };
        if array.is_null()
        {
            return;
        }
        // SAFETY: `array` is a live `GArray`.
        let a = unsafe { &*array };
        // SAFETY: its `data` holds `len` register descriptors.
        let descriptors = unsafe {
            std::slice::from_raw_parts(
                a.data.cast::<RegDescriptor>(),
                usize::try_from(a.len).unwrap_or(0),
            )
        };
        for d in descriptors
        {
            if d.name.is_null()
            {
                continue;
            }
            // SAFETY: a descriptor's name is a NUL-terminated string QEMU owns.
            let name = unsafe { CStr::from_ptr(d.name) }
                .to_string_lossy()
                .into_owned();
            p.registers.push((name, d.handle));
        }
        // SAFETY: the caller frees the array, not the names (qemu-plugin.h).
        unsafe { (p.api.g_array_free)(array, 1) };
    });
}

/// A block is translated: give each instruction its slot and callbacks.
unsafe extern "C" fn tb_trans(tb: *mut Tb, _userdata: *mut c_void)
{
    with_plugin(|p| {
        // SAFETY: `tb` is the block being translated.
        let n = unsafe { (p.api.tb_n_insns)(tb) };
        for i in 0..n
        {
            // SAFETY: `i` is below the block's instruction count.
            let insn = unsafe { (p.api.tb_get_insn)(tb, i) };
            // SAFETY: `insn` is an instruction of the block.
            let pc = unsafe { (p.api.insn_vaddr)(insn) };
            let mut bytes = [0u8; INSN_MAX];
            // SAFETY: `bytes` holds `INSN_MAX` bytes.
            let len = unsafe { (p.api.insn_data)(insn, bytes.as_mut_ptr().cast(), INSN_MAX) };
            let Some((slot, class)) = p.recorder.slot(pc, bytes.get(..len).unwrap_or(&bytes))
            else
            {
                continue;
            };
            let userdata =
                ptr::without_provenance_mut::<c_void>(usize::try_from(slot).unwrap_or(usize::MAX));
            // The callbacks run in registration order: the value of a read
            // due, then the read, then the count (crate::recorder).
            // SAFETY: `insn` is an instruction of the block being translated,
            // `value` is a `qemu_plugin_vcpu_udata_cb_t`, and the condition's
            // entry is the plugin's scoreboard of one `u64`.
            unsafe {
                (p.api.register_vcpu_insn_exec_cond_cb)(
                    insn,
                    value,
                    CB_R_REGS,
                    COND_NE,
                    p.due,
                    0,
                    ptr::null_mut(),
                );
            };
            if matches!(class, Class::Read(_)) && p.recorder.is_user_read(slot)
            {
                // SAFETY: `insn` is an instruction of the block being
                // translated, and `read` is a `qemu_plugin_vcpu_udata_cb_t`.
                unsafe { (p.api.register_vcpu_insn_exec_cb)(insn, read, CB_NO_REGS, userdata) };
            }
            // SAFETY: `insn` is an instruction of the block being translated,
            // and `exec` is a `qemu_plugin_vcpu_udata_cb_t`.
            unsafe { (p.api.register_vcpu_insn_exec_cb)(insn, exec, CB_NO_REGS, userdata) };
        }
    });
}

/// An instruction runs.
unsafe extern "C" fn exec(_vcpu: c_uint, userdata: *mut c_void)
{
    with_plugin(|p| p.recorder.exec(slot_of(userdata)));
}

/// A user-mode counter read runs.
unsafe extern "C" fn read(_vcpu: c_uint, userdata: *mut c_void)
{
    with_plugin(|p| {
        p.recorder.read(slot_of(userdata));
        p.set_due(1);
    });
}

/// The instruction after a read runs: the read's value is in its registers.
unsafe extern "C" fn value(_vcpu: c_uint, _userdata: *mut c_void)
{
    with_plugin(|p| {
        p.set_due(0);
        if let Some(dest) = p.recorder.due()
        {
            let value = p.value(dest);
            p.recorder.value(value);
        }
    });
}

/// Control leaves the instruction stream (an interrupt, an exception).
unsafe extern "C" fn discon(
    _vcpu: c_uint,
    _kind: c_int,
    from: u64,
    _to: u64,
    _userdata: *mut c_void,
)
{
    with_plugin(|p| p.recorder.discon(from));
}

/// QEMU exits: flush the record, and report the first error writing it.
unsafe extern "C" fn at_exit(_userdata: *mut c_void)
{
    with_plugin(|p| {
        if let Err(e) = p.recorder.finish()
        {
            eprintln!("path-account plugin: the record is incomplete: {e}");
        }
    });
}
