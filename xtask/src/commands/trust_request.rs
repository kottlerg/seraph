// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/trust_request.rs

//! `cargo xtask trust-request`: write a trust request, which the bootloader
//! applies to the trust store it keeps in firmware storage
//! (docs/signing.md § Trust Store), into the sysroot's ESP for the next pack,
//! or to a file to copy onto a machine's ESP as `\EFI\seraph\trust-request`.

use std::fs;

use crate::cli::TrustRequestArgs;
use crate::context::Context;
use crate::error::{Context as _, Result, ensure};
use crate::signing::{Signer, request};
use crate::sysroot;
use crate::util::step;

pub fn run(ctx: &Context, args: &TrustRequestArgs) -> Result<()>
{
    if args.clear
    {
        ensure!(
            args.add.is_empty() && args.revoke.is_empty() && !args.sign && args.out.is_none(),
            "--clear takes no other option"
        );
        request::clear(ctx)?;
        step(&format!(
            "trust request: none staged in {}",
            ctx.sysroot_efi_seraph().display()
        ));
        return Ok(());
    }
    let mut stores = Vec::new();
    for path in &args.add
    {
        stores.push(fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    }
    let revoke = args
        .revoke
        .iter()
        .map(|hex| request::parse_key_id(hex))
        .collect::<Result<Vec<_>>>()?;
    // A staged signed request is for the sysroot's bootloader, which refuses
    // a signature for another architecture and falls back to the console:
    // its `--arch` is checked as every command that writes into the sysroot
    // checks its own. An unsigned request names no architecture, and one
    // written with `--out` is for whatever machine `--arch` names.
    if args.sign && args.out.is_none()
    {
        sysroot::check_arch(ctx, args.arch)?;
    }
    let signer = if args.sign
    {
        Some(Signer::open(ctx, args.arch)?)
    }
    else
    {
        None
    };
    let bytes = request::build(&stores, &revoke, signer.as_ref())?;
    let how = if signer.is_some()
    {
        "signed in the enrolment role"
    }
    else
    {
        "unsigned: the console confirms it"
    };
    let path = match &args.out
    {
        Some(out) =>
        {
            fs::write(out, &bytes).with_context(|| format!("writing {}", out.display()))?;
            out.clone()
        }
        None => request::stage(ctx, &bytes)?,
    };
    step(&format!(
        "trust request: {} ({} bytes, {how})",
        path.display(),
        bytes.len()
    ));
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arch::Arch;
    use crate::signing::testing::scratch;

    /// Defect caught: a signed request staged for an architecture other than
    /// the sysroot's, `--arch`'s default on a riscv64 sysroot, which that
    /// bootloader does not apply unattended as `--sign` promises.
    #[test]
    fn a_signed_request_for_another_architecture_is_refused_before_staging()
    {
        let dir = scratch("trust-request-arch");
        let ctx = Context {
            root: dir.clone(),
            sysroot: dir.join("sysroot"),
            target_dir: dir.join("target"),
        };
        sysroot::record_arch(&ctx, Arch::Riscv64).unwrap();
        let args = TrustRequestArgs {
            arch: Arch::X86_64,
            add: Vec::new(),
            revoke: vec!["00112233445566778899aabbccddeeff".to_owned()],
            sign: true,
            out: None,
            clear: false,
        };
        let err = run(&ctx, &args).unwrap_err().to_string();
        assert!(err.contains("sysroot was built for 'riscv64'"), "{err}");
        assert!(!request::staged_path(&ctx).exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
