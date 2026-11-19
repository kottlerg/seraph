// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/tpm/src/command.rs

//! TPM 2.0 command marshalling: the two commands the driver issues,
//! `TPM2_GetRandom` and `TPM2_Startup(TPM_SU_CLEAR)`, and the response
//! header and `TPM2_GetRandom` response parameters they return (TPM 2.0
//! Library, Part 3, § 9.3 and § 16.1). Every field is big-endian.

/// Bytes of a command or response header: the tag (`u16`), the size of the
/// whole command or response (`u32`), and the command or response code
/// (`u32`).
pub const HEADER_LEN: usize = 10;

/// Bytes of each command this module builds: the header and one `u16`
/// parameter.
pub const COMMAND_LEN: usize = HEADER_LEN + 2;

/// [`COMMAND_LEN`] as the header's `u32` size field.
const COMMAND_SIZE: u32 = 12;
const _: () = assert!(COMMAND_SIZE as usize == COMMAND_LEN);

/// `TPM_ST_NO_SESSIONS`: the tag of a command without an authorization
/// area, and of its response.
const TPM_ST_NO_SESSIONS: u16 = 0x8001;

/// `TPM_ST_RSP_COMMAND`: the tag a TPM gives an error response to a command
/// it could not read as TPM 2.0.
const TPM_ST_RSP_COMMAND: u16 = 0x00C4;

/// `TPM_CC_Startup`.
const TPM_CC_STARTUP: u32 = 0x0000_0144;

/// `TPM_CC_GetRandom`.
const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;

/// `TPM_SU_CLEAR`: the startup type of a TPM reset.
const TPM_SU_CLEAR: u16 = 0x0000;

/// The response codes the driver acts on (TPM 2.0 Library, Part 2, § 6.6).
pub mod rc
{
    /// The command succeeded.
    pub const SUCCESS: u32 = 0x000;
    /// The TPM has not run `TPM2_Startup`, or a `TPM2_Startup` found it
    /// already started.
    pub const INITIALIZE: u32 = 0x100;
    /// The TPM is in failure mode.
    pub const FAILURE: u32 = 0x101;
    /// The TPM ended the command early to service other work; ask again.
    pub const YIELDED: u32 = 0x908;
    /// The TPM is running its self-tests; ask again.
    pub const TESTING: u32 = 0x90A;
    /// The TPM was busy; ask again.
    pub const RETRY: u32 = 0x922;
}

/// Whether a response code asks the caller to send the command again
/// unchanged: `TPM_RC_YIELDED`, `TPM_RC_TESTING`, or `TPM_RC_RETRY`.
#[must_use]
pub const fn retryable(code: u32) -> bool
{
    matches!(code, rc::YIELDED | rc::TESTING | rc::RETRY)
}

/// A command of code `code` with no sessions whose one parameter is the
/// `u16` `param`.
fn command(code: u32, param: u16) -> [u8; COMMAND_LEN]
{
    let mut out = [0u8; COMMAND_LEN];
    let fields = TPM_ST_NO_SESSIONS
        .to_be_bytes()
        .into_iter()
        .chain(COMMAND_SIZE.to_be_bytes())
        .chain(code.to_be_bytes())
        .chain(param.to_be_bytes());
    for (byte, field) in out.iter_mut().zip(fields)
    {
        *byte = field;
    }
    out
}

/// `TPM2_GetRandom` asking for `bytes_requested` bytes. A TPM returns at
/// most the size of its largest digest per call, so a caller wanting more
/// sends the command again.
#[must_use]
pub fn get_random(bytes_requested: u16) -> [u8; COMMAND_LEN]
{
    command(TPM_CC_GET_RANDOM, bytes_requested)
}

/// `TPM2_Startup(TPM_SU_CLEAR)`: the start-up a TPM needs after its reset
/// when no firmware sent one.
#[must_use]
pub fn startup_clear() -> [u8; COMMAND_LEN]
{
    command(TPM_CC_STARTUP, TPM_SU_CLEAR)
}

/// The size a response header gives for the whole response, `None` for a
/// header shorter than [`HEADER_LEN`] or a size below it.
#[must_use]
pub fn response_size(header: &[u8]) -> Option<usize>
{
    let size = u32::from_be_bytes(*header.get(2..6)?.first_chunk::<4>()?);
    let size = usize::try_from(size).ok()?;
    (header.len() >= HEADER_LEN && size >= HEADER_LEN).then_some(size)
}

/// What a response says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response<'a>
{
    /// `TPM_RC_SUCCESS`, with the response parameters after the header.
    Success(&'a [u8]),
    /// Any other response code.
    Code(u32),
}

/// Read the whole response `rsp`. `None` when its header's size is not
/// `rsp`'s length, a success carries a tag other than
/// `TPM_ST_NO_SESSIONS`, or an error carries a tag that is neither that nor
/// `TPM_ST_RSP_COMMAND`. The bytes are the device's, so each is checked
/// rather than trusted.
#[must_use]
pub fn parse_response(rsp: &[u8]) -> Option<Response<'_>>
{
    if response_size(rsp)? != rsp.len()
    {
        return None;
    }
    let tag = u16::from_be_bytes(*rsp.first_chunk::<2>()?);
    let code = u32::from_be_bytes(*rsp.get(6..HEADER_LEN)?.first_chunk::<4>()?);
    match code
    {
        rc::SUCCESS if tag == TPM_ST_NO_SESSIONS => Some(Response::Success(rsp.get(HEADER_LEN..)?)),
        rc::SUCCESS => None,
        _ if tag == TPM_ST_NO_SESSIONS || tag == TPM_ST_RSP_COMMAND => Some(Response::Code(code)),
        _ => None,
    }
}

/// The random bytes of a `TPM2_GetRandom` response's parameters `params`,
/// a `TPM2B_DIGEST`: a `u16` count and that many bytes. `None` when the
/// count is past what was `asked` or the parameters are not exactly the
/// count and its bytes.
#[must_use]
pub fn random_bytes(params: &[u8], asked: usize) -> Option<&[u8]>
{
    let (count, bytes) = params.split_first_chunk::<2>()?;
    let count = usize::from(u16::from_be_bytes(*count));
    (count <= asked && count == bytes.len()).then_some(bytes)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn get_random_is_the_twelve_byte_no_session_command()
    {
        assert_eq!(
            get_random(0x0040),
            [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0x00, 0x40]
        );
    }

    #[test]
    fn startup_clear_is_startup_with_su_clear()
    {
        assert_eq!(
            startup_clear(),
            [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0x00, 0x00]
        );
    }

    #[test]
    fn a_success_response_yields_its_parameters()
    {
        let rsp = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 0, 2, 0xAA, 0xBB];
        assert_eq!(
            parse_response(&rsp),
            Some(Response::Success(&[0, 2, 0xAA, 0xBB][..]))
        );
    }

    #[test]
    fn an_error_response_yields_its_code()
    {
        let rsp = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x00];
        assert_eq!(parse_response(&rsp), Some(Response::Code(rc::INITIALIZE)));
        let legacy = [0x00, 0xC4, 0, 0, 0, 10, 0, 0, 0x01, 0x01];
        assert_eq!(parse_response(&legacy), Some(Response::Code(rc::FAILURE)));
    }

    #[test]
    fn a_response_whose_size_is_not_its_length_is_refused()
    {
        // The header claims more bytes than arrived, then fewer.
        assert_eq!(parse_response(&[0x80, 0x01, 0, 0, 0, 12, 0, 0, 0, 0]), None);
        assert_eq!(
            parse_response(&[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0]),
            None
        );
        // A header too short to hold its own fields.
        assert_eq!(parse_response(&[0x80, 0x01, 0, 0, 0, 6]), None);
    }

    #[test]
    fn a_success_with_a_foreign_tag_is_refused()
    {
        assert_eq!(parse_response(&[0x80, 0x02, 0, 0, 0, 10, 0, 0, 0, 0]), None);
        assert_eq!(
            parse_response(&[0x12, 0x34, 0, 0, 0, 10, 0, 0, 0x01, 0x00]),
            None
        );
    }

    #[test]
    fn random_bytes_refuses_a_count_past_the_request_or_the_parameters()
    {
        assert_eq!(random_bytes(&[0, 2, 7, 9], 2), Some(&[7, 9][..]));
        assert_eq!(random_bytes(&[0, 0], 8), Some(&[][..]));
        // More than was asked for.
        assert_eq!(random_bytes(&[0, 2, 7, 9], 1), None);
        // A count the parameters do not hold, then trailing bytes past it.
        assert_eq!(random_bytes(&[0, 3, 7, 9], 8), None);
        assert_eq!(random_bytes(&[0, 1, 7, 9], 8), None);
        assert_eq!(random_bytes(&[0], 8), None);
    }

    #[test]
    fn only_the_busy_codes_are_retried()
    {
        assert!(retryable(rc::RETRY));
        assert!(retryable(rc::TESTING));
        assert!(retryable(rc::YIELDED));
        assert!(!retryable(rc::INITIALIZE));
        assert!(!retryable(rc::FAILURE));
    }
}
