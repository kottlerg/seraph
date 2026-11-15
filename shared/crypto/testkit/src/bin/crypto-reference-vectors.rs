// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/bin/crypto-reference-vectors.rs

//! Regenerate the reference vectors under `vectors/reference/` with OpenSSL,
//! or, with `--check`, regenerate them in memory and fail unless the files
//! in the tree are byte-identical. `cargo xtask crypto-vectors` runs it.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use crypto_testkit::generate;

fn main() -> ExitCode
{
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = match args.as_slice()
    {
        [] => false,
        [flag] if flag == "--check" => true,
        _ =>
        {
            eprintln!("usage: crypto-reference-vectors [--check]");
            return ExitCode::FAILURE;
        }
    };
    match generate::reference_version()
    {
        Ok(version) => println!("reference: {version}"),
        Err(e) =>
        {
            eprintln!("crypto-reference-vectors: {e}");
            return ExitCode::FAILURE;
        }
    }
    let files = match generate::generate()
    {
        Ok(files) => files,
        Err(e) =>
        {
            eprintln!("crypto-reference-vectors: {e}");
            return ExitCode::FAILURE;
        }
    };
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/reference");
    let mut status = ExitCode::SUCCESS;
    for (name, text) in &files.files
    {
        let path = dir.join(name);
        if check
        {
            if fs::read_to_string(&path).ok().as_deref() == Some(text.as_str())
            {
                println!("{}: regenerates identically", path.display());
            }
            else
            {
                eprintln!("{}: differs from what the generator writes", path.display());
                status = ExitCode::FAILURE;
            }
        }
        else if let Err(e) = fs::write(&path, text)
        {
            eprintln!("writing {}: {e}", path.display());
            status = ExitCode::FAILURE;
        }
        else
        {
            println!("wrote {}", path.display());
        }
    }
    status
}
