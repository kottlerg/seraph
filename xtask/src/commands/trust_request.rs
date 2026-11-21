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
