// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/chacha20poly1305.rs

//! `AEAD_CHACHA20_POLY1305` (RFC 8439 § 2.8): authenticated encryption with
//! associated data.
//!
//! [`seal`] encrypts a buffer in place and returns its 16-byte tag; [`open`]
//! checks the tag and only then decrypts in place, so a buffer whose tag does
//! not verify is never decrypted and is returned unchanged. The tag is
//! detached: the caller stores it beside the ciphertext. Nothing is
//! allocated and no key schedule is kept, so a caller seals fixed-size chunks
//! from a key it holds, with no state between calls.
//!
//! The caller MUST NOT seal two buffers under one key with one nonce: the two
//! would share keystream, and the Poly1305 key with it.
//!
//! No branch and no memory index depends on the key, the keystream, the
//! plaintext or a tag; they depend on the buffer and AAD lengths only. The
//! tag comparison folds both tags into one difference before the single
//! accept-or-refuse branch, so its time does not depend on where they differ.

use crate::chacha20::{self, CounterOverflow};
use crate::poly1305::{self, Poly1305};

/// Key length in bytes.
pub const KEY_LEN: usize = chacha20::KEY_LEN;

/// Nonce length in bytes.
pub const NONCE_LEN: usize = chacha20::NONCE_LEN;

/// Tag length in bytes.
pub const TAG_LEN: usize = poly1305::TAG_LEN;

/// The longest buffer [`seal`] and [`open`] take, in bytes: `2^32 - 1`
/// keystream blocks of 64 bytes, since block 0 makes the Poly1305 key and
/// the 32-bit block counter must not wrap (RFC 8439 § 2.8). A format bound:
/// no realistic buffer reaches its 256 GiB.
pub const MAX_LEN: usize = 274_877_906_880;

/// Why [`seal`] refused a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError
{
    /// The buffer is longer than [`MAX_LEN`].
    TooLong,
}

/// Why [`open`] refused a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError
{
    /// The buffer is longer than [`MAX_LEN`]: no [`seal`] produced it.
    TooLong,
    /// The tag does not authenticate the ciphertext and AAD under the key
    /// and nonce: one of them is not what was sealed.
    TagMismatch,
}

/// Encrypt `buffer` in place under `key` and `nonce`, and authenticate the
/// ciphertext with `aad`.
///
/// # Arguments
///
/// - `key`: the 32-byte key.
/// - `nonce`: the 12-byte nonce, used for no other buffer under `key`.
/// - `aad`: data authenticated with the buffer but not encrypted, any length;
///   [`open`] needs the same bytes.
/// - `buffer`: the plaintext, replaced by the ciphertext of the same length.
///
/// # Returns
///
/// The 16-byte tag, which [`open`] checks.
///
/// # Errors
///
/// [`SealError::TooLong`] when `buffer` is longer than [`MAX_LEN`]; `buffer`
/// is then unchanged.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], SealError>
{
    chacha20::xor_keystream(key, 1, nonce, buffer).map_err(|CounterOverflow| SealError::TooLong)?;
    Ok(compute_tag(key, nonce, aad, buffer))
}

/// Check `tag` over the ciphertext in `buffer` and `aad` under `key` and
/// `nonce`, and on a match decrypt `buffer` in place.
///
/// # Arguments
///
/// - `key`, `nonce`, `aad`: as [`seal`] was given them.
/// - `buffer`: the ciphertext, replaced by the plaintext when the tag
///   verifies.
/// - `tag`: the tag [`seal`] returned.
///
/// # Errors
///
/// `buffer` is unchanged on every error:
/// - [`OpenError::TooLong`]: `buffer` is longer than [`MAX_LEN`].
/// - [`OpenError::TagMismatch`]: the tag does not verify.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), OpenError>
{
    if !chacha20::fits(1, buffer.len())
    {
        return Err(OpenError::TooLong);
    }
    if !tags_equal(&compute_tag(key, nonce, aad, buffer), tag)
    {
        return Err(OpenError::TagMismatch);
    }
    chacha20::xor_keystream(key, 1, nonce, buffer).map_err(|CounterOverflow| OpenError::TooLong)
}

/// The Poly1305 key for `key` and `nonce`: the first 32 bytes of keystream
/// block 0 (RFC 8439 § 2.6).
fn one_time_key(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; poly1305::KEY_LEN]
{
    let mut one_time = [0u8; poly1305::KEY_LEN];
    for (dst, src) in one_time.iter_mut().zip(chacha20::block(key, 0, nonce))
    {
        *dst = src;
    }
    one_time
}

/// The tag over `aad` and `ciphertext` (RFC 8439 § 2.8): each zero-padded to
/// 16 bytes, then both lengths as 64-bit little-endian words.
fn compute_tag(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; TAG_LEN]
{
    let mut mac = Poly1305::new(&one_time_key(key, nonce));
    mac.update_padded(aad);
    mac.update_padded(ciphertext);
    let mut lengths = [0u8; 16];
    for (bytes, len) in lengths
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip([aad.len(), ciphertext.len()])
    {
        *bytes = (len as u64).to_le_bytes();
    }
    mac.update_padded(&lengths);
    mac.finalize()
}

/// Whether two tags are equal, in a time that does not depend on where they
/// differ: their difference is one 128-bit word, which
/// [`core::hint::black_box`] hides from the optimiser so it cannot compare
/// byte by byte and stop at the first difference.
///
/// Out of line so that its compiled body can be read on its own.
#[inline(never)]
fn tags_equal(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool
{
    let difference = u128::from_ne_bytes(*a) ^ u128::from_ne_bytes(*b);
    core::hint::black_box(difference) == 0
}

// ── Known-answer tests ───────────────────────────────────────────────────────

/// `text`, `2 * N` lower-case hex digits, as `N` bytes. Called only in the
/// initialisers of the constants below, so a malformed vector fails the
/// build.
#[expect(
    clippy::panic,
    reason = "evaluated only in constant initialisers, where a panic is a build error naming \
              the malformed vector, never a runtime panic"
)]
const fn hex<const N: usize>(text: &str) -> [u8; N]
{
    let mut out = [0u8; N];
    let mut digits = text.as_bytes();
    let mut slots = out.as_mut_slice();
    while let Some((slot, more)) = slots.split_first_mut()
    {
        let [high, low, rest @ ..] = digits
        else
        {
            panic!("hex vector shorter than its array");
        };
        *slot = (nibble(*high) << 4) | nibble(*low);
        digits = rest;
        slots = more;
    }
    assert!(digits.is_empty(), "hex vector longer than its array");
    out
}

/// The value of one lower-case hex digit.
#[expect(
    clippy::panic,
    reason = "evaluated only in constant initialisers through `hex`, where a panic is a build \
              error naming the malformed vector, never a runtime panic"
)]
const fn nibble(digit: u8) -> u8
{
    match digit
    {
        b'0'..=b'9' => digit.wrapping_sub(b'0'),
        b'a'..=b'f' => digit.wrapping_sub(b'a').wrapping_add(10),
        _ => panic!("not a lower-case hex digit"),
    }
}

/// A keystream block (RFC 8439 § 2.3.2, A.1).
struct BlockKat
{
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    keystream: [u8; 64],
}

/// A `ChaCha20` encryption (RFC 8439 § 2.4.2, A.2).
struct CipherKat
{
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
}

/// A Poly1305 tag (RFC 8439 § 2.5.2, A.3).
struct MacKat
{
    key: [u8; poly1305::KEY_LEN],
    message: &'static [u8],
    tag: [u8; TAG_LEN],
}

/// A Poly1305 key derivation (RFC 8439 § 2.6.2, A.4).
struct KeyGenKat
{
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    one_time_key: [u8; poly1305::KEY_LEN],
}

/// An AEAD sealing (RFC 8439 § 2.8.2, A.5).
struct AeadKat
{
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: [u8; 12],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
    tag: [u8; TAG_LEN],
}

/// The key 00 01 .. 1f of RFC 8439 § 2.3.2 and § 2.4.2.
const KEY_SEQUENCE: [u8; KEY_LEN] =
    hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

/// The key 80 81 .. 9f of RFC 8439 § 2.6.2 and § 2.8.2.
const KEY_HIGH_SEQUENCE: [u8; KEY_LEN] =
    hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

/// The key of RFC 8439 A.2 test vector #3, A.4 #3 and A.5.
const KEY_JABBERWOCKY: [u8; KEY_LEN] =
    hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");

/// The key 00 .. 00 01 of RFC 8439 A.1 #3, A.2 #2 and A.4 #2.
const KEY_ONE: [u8; KEY_LEN] =
    hex("0000000000000000000000000000000000000000000000000000000000000001");

/// The nonce 00 .. 00 02 of RFC 8439 A.1 #5, A.2 #2 and #3, A.4 #2 and #3.
const NONCE_TWO: [u8; NONCE_LEN] = hex("000000000000000000000002");

/// The "sunscreen" plaintext of RFC 8439 § 2.4.2 and § 2.8.2.
const SUNSCREEN: [u8; 114] = hex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
);

/// The IETF contribution text of RFC 8439 A.2 #2 and A.3 #2 and #3.
const IETF_TEXT: [u8; 375] = hex(
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
);

/// The Jabberwocky stanza of RFC 8439 A.2 #3 and A.3 #4.
const JABBERWOCKY: [u8; 127] = hex(
    "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
);

const BLOCK_KATS: &[BlockKat] = &[
    // § 2.3.2.
    BlockKat {
        key: KEY_SEQUENCE,
        nonce: hex("000000090000004a00000000"),
        counter: 1,
        keystream: hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        ),
    },
    // A.1 #1.
    BlockKat {
        key: [0; KEY_LEN],
        nonce: [0; NONCE_LEN],
        counter: 0,
        keystream: hex(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        ),
    },
    // A.1 #2.
    BlockKat {
        key: [0; KEY_LEN],
        nonce: [0; NONCE_LEN],
        counter: 1,
        keystream: hex(
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
        ),
    },
    // A.1 #3.
    BlockKat {
        key: KEY_ONE,
        nonce: [0; NONCE_LEN],
        counter: 1,
        keystream: hex(
            "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
        ),
    },
    // A.1 #4.
    BlockKat {
        key: hex("00ff000000000000000000000000000000000000000000000000000000000000"),
        nonce: [0; NONCE_LEN],
        counter: 2,
        keystream: hex(
            "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
        ),
    },
    // A.1 #5.
    BlockKat {
        key: [0; KEY_LEN],
        nonce: NONCE_TWO,
        counter: 0,
        keystream: hex(
            "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
        ),
    },
];

const CIPHER_KATS: &[CipherKat] = &[
    // § 2.4.2.
    CipherKat {
        key: KEY_SEQUENCE,
        nonce: hex("000000000000004a00000000"),
        counter: 1,
        plaintext: &SUNSCREEN,
        ciphertext: &hex::<114>(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
        ),
    },
    // A.2 #1.
    CipherKat {
        key: [0; KEY_LEN],
        nonce: [0; NONCE_LEN],
        counter: 0,
        plaintext: &[0; 64],
        ciphertext: &hex::<64>(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        ),
    },
    // A.2 #2.
    CipherKat {
        key: KEY_ONE,
        nonce: NONCE_TWO,
        counter: 1,
        plaintext: &IETF_TEXT,
        ciphertext: &hex::<375>(
            "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
        ),
    },
    // A.2 #3.
    CipherKat {
        key: KEY_JABBERWOCKY,
        nonce: NONCE_TWO,
        counter: 42,
        plaintext: &JABBERWOCKY,
        ciphertext: &hex::<127>(
            "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
        ),
    },
];

const MAC_KATS: &[MacKat] = &[
    // § 2.5.2.
    MacKat {
        key: hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
        message: &hex::<34>("43727970746f6772617068696320466f72756d2052657365617263682047726f7570"),
        tag: hex("a8061dc1305136c6c22b8baf0c0127a9"),
    },
    // A.3 #1.
    MacKat {
        key: [0; poly1305::KEY_LEN],
        message: &[0; 64],
        tag: [0; TAG_LEN],
    },
    // A.3 #2: r = 0, so the tag is s.
    MacKat {
        key: hex("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e"),
        message: &IETF_TEXT,
        tag: hex("36e5f6b5c5e06070f0efca96227a863e"),
    },
    // A.3 #3.
    MacKat {
        key: hex("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000"),
        message: &IETF_TEXT,
        tag: hex("f3477e7cd95417af89a6b8794c310cf0"),
    },
    // A.3 #4.
    MacKat {
        key: KEY_JABBERWOCKY,
        message: &JABBERWOCKY,
        tag: hex("4541669a7eaaee61e708dc7cbcc5eb62"),
    },
    // A.3 #5: a partially reduced result that is not fully reduced.
    MacKat {
        key: hex("0200000000000000000000000000000000000000000000000000000000000000"),
        message: &hex::<16>("ffffffffffffffffffffffffffffffff"),
        tag: hex("03000000000000000000000000000000"),
    },
    // A.3 #6: the addition of s overflows modulo 2^128.
    MacKat {
        key: hex("02000000000000000000000000000000ffffffffffffffffffffffffffffffff"),
        message: &hex::<16>("02000000000000000000000000000000"),
        tag: hex("03000000000000000000000000000000"),
    },
    // A.3 #7: an all-ones limb with a carry from the limb below.
    MacKat {
        key: hex("0100000000000000000000000000000000000000000000000000000000000000"),
        message: &hex::<48>(
            "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
        ),
        tag: hex("05000000000000000000000000000000"),
    },
    // A.3 #8: the polynomial part is exactly 2^130 - 5.
    MacKat {
        key: hex("0100000000000000000000000000000000000000000000000000000000000000"),
        message: &hex::<48>(
            "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101",
        ),
        tag: hex("00000000000000000000000000000000"),
    },
    // A.3 #9: the polynomial part is exactly 2^130 - 6.
    MacKat {
        key: hex("0200000000000000000000000000000000000000000000000000000000000000"),
        message: &hex::<16>("fdffffffffffffffffffffffffffffff"),
        tag: hex("faffffffffffffffffffffffffffffff"),
    },
    // A.3 #10: a 131-bit intermediate result of the 5 * H + L reduction.
    MacKat {
        key: hex("0100000000000000040000000000000000000000000000000000000000000000"),
        message: &hex::<64>(
            "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000",
        ),
        tag: hex("14000000000000005500000000000000"),
    },
    // A.3 #11: a 131-bit final result of the 5 * H + L reduction.
    MacKat {
        key: hex("0100000000000000040000000000000000000000000000000000000000000000"),
        message: &hex::<48>(
            "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000",
        ),
        tag: hex("13000000000000000000000000000000"),
    },
];

const KEY_GEN_KATS: &[KeyGenKat] = &[
    // § 2.6.2.
    KeyGenKat {
        key: KEY_HIGH_SEQUENCE,
        nonce: hex("000000000001020304050607"),
        one_time_key: hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"),
    },
    // A.4 #1.
    KeyGenKat {
        key: [0; KEY_LEN],
        nonce: [0; NONCE_LEN],
        one_time_key: hex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"),
    },
    // A.4 #2.
    KeyGenKat {
        key: KEY_ONE,
        nonce: NONCE_TWO,
        one_time_key: hex("ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739"),
    },
    // A.4 #3.
    KeyGenKat {
        key: KEY_JABBERWOCKY,
        nonce: NONCE_TWO,
        one_time_key: hex("965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae"),
    },
];

const AEAD_KATS: &[AeadKat] = &[
    // § 2.8.2.
    AeadKat {
        key: KEY_HIGH_SEQUENCE,
        nonce: hex("070000004041424344454647"),
        aad: hex("50515253c0c1c2c3c4c5c6c7"),
        plaintext: &SUNSCREEN,
        ciphertext: &hex::<114>(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        ),
        tag: hex("1ae10b594f09e26a7e902ecbd0600691"),
    },
    // A.5.
    AeadKat {
        key: KEY_JABBERWOCKY,
        nonce: hex("000000000102030405060708"),
        aad: hex("f33388860000000000004e91"),
        plaintext: &hex::<265>(
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
        ),
        ciphertext: &hex::<265>(
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
        ),
        tag: hex("eead9d67890cbb22392336fea1851f38"),
    },
];

/// Room for the longest message among the vectors, the IETF text of 375
/// bytes.
const KAT_SCRATCH: usize = 384;

/// `data` copied into the front of `scratch`.
fn staged<'a>(scratch: &'a mut [u8; KAT_SCRATCH], data: &[u8])
-> Result<&'a mut [u8], &'static str>
{
    let staged = scratch
        .get_mut(..data.len())
        .ok_or("chacha20-poly1305: vector longer than the scratch buffer")?;
    staged.copy_from_slice(data);
    Ok(staged)
}

/// Run the ChaCha20-Poly1305 known-answer tests: every vector of RFC 8439
/// § 2 and Appendix A for the block function, the cipher, Poly1305, the
/// Poly1305 key derivation and the AEAD, sealing and opening, and the
/// refusal of a sealed buffer with a flipped bit in its tag, ciphertext,
/// nonce or AAD, or opened under another key, with the buffer left as it
/// was. Returns the first failure as an error string. Compiled in all builds
/// so host and on-target (ktest) runs share identical logic.
///
/// # Errors
///
/// Returns a descriptive `&'static str` on the first failing case.
pub fn run_chacha20_poly1305_kats() -> Result<(), &'static str>
{
    for kat in BLOCK_KATS
    {
        if chacha20::block(&kat.key, kat.counter, &kat.nonce) != kat.keystream
        {
            return Err("chacha20: block function KAT mismatch");
        }
    }
    let mut scratch = [0u8; KAT_SCRATCH];
    for kat in CIPHER_KATS
    {
        let buffer = staged(&mut scratch, kat.plaintext)?;
        chacha20::xor_keystream(&kat.key, kat.counter, &kat.nonce, buffer)
            .map_err(|CounterOverflow| "chacha20: cipher KAT refused")?;
        if *buffer != *kat.ciphertext
        {
            return Err("chacha20: cipher KAT mismatch");
        }
    }
    for kat in MAC_KATS
    {
        if poly1305::mac(&kat.key, kat.message) != kat.tag
        {
            return Err("poly1305: KAT tag mismatch");
        }
    }
    for kat in KEY_GEN_KATS
    {
        if one_time_key(&kat.key, &kat.nonce) != kat.one_time_key
        {
            return Err("chacha20-poly1305: one-time key KAT mismatch");
        }
    }
    for kat in AEAD_KATS
    {
        run_aead_kat(kat, &mut scratch)?;
    }
    let base = AEAD_KATS
        .first()
        .ok_or("chacha20-poly1305: missing vector")?;
    run_tamper_kats(base, &mut scratch)
}

/// Seal the vector's plaintext to its ciphertext and tag, and open the
/// ciphertext back to the plaintext.
fn run_aead_kat(kat: &AeadKat, scratch: &mut [u8; KAT_SCRATCH]) -> Result<(), &'static str>
{
    let buffer = staged(scratch, kat.plaintext)?;
    let tag = seal(&kat.key, &kat.nonce, &kat.aad, buffer)
        .map_err(|SealError::TooLong| "chacha20-poly1305: KAT seal refused")?;
    if tag != kat.tag || *buffer != *kat.ciphertext
    {
        return Err("chacha20-poly1305: KAT seal mismatch");
    }
    if open(&kat.key, &kat.nonce, &kat.aad, buffer, &kat.tag).is_err() || *buffer != *kat.plaintext
    {
        return Err("chacha20-poly1305: KAT open failed");
    }
    Ok(())
}

/// Open the vector's ciphertext with one bit of its tag, ciphertext, nonce
/// or AAD flipped, and under another key: each is refused, and the buffer
/// still holds the ciphertext.
fn run_tamper_kats(kat: &AeadKat, scratch: &mut [u8; KAT_SCRATCH]) -> Result<(), &'static str>
{
    let mut bad_tag = kat.tag;
    bad_tag[15] ^= 0x80;
    let mut bad_nonce = kat.nonce;
    bad_nonce[0] ^= 0x01;
    let mut bad_aad = kat.aad;
    bad_aad[11] ^= 0x01;
    let mut bad_key = kat.key;
    bad_key[31] ^= 0x01;
    let sealed = Tampered {
        key: &kat.key,
        nonce: &kat.nonce,
        aad: &kat.aad,
        tag: &kat.tag,
        flipped_byte: None,
    };
    let cases = [
        Tampered {
            tag: &bad_tag,
            ..sealed
        },
        Tampered {
            flipped_byte: Some(57),
            ..sealed
        },
        Tampered {
            nonce: &bad_nonce,
            ..sealed
        },
        Tampered {
            aad: &bad_aad,
            ..sealed
        },
        Tampered {
            key: &bad_key,
            ..sealed
        },
    ];
    for case in cases
    {
        let buffer = staged(scratch, kat.ciphertext)?;
        if let Some(byte) = case.flipped_byte.and_then(|at| buffer.get_mut(at))
        {
            *byte ^= 0x04;
        }
        let sent = *scratch;
        let buffer = scratch
            .get_mut(..kat.ciphertext.len())
            .ok_or("chacha20-poly1305: vector longer than the scratch buffer")?;
        if open(case.key, case.nonce, case.aad, buffer, case.tag) != Err(OpenError::TagMismatch)
        {
            return Err("chacha20-poly1305: tampered buffer accepted");
        }
        if *scratch != sent
        {
            return Err("chacha20-poly1305: refused buffer changed");
        }
    }
    Ok(())
}

/// The inputs of one opening of a sealed vector, one of them tampered.
#[derive(Clone, Copy)]
struct Tampered<'a>
{
    key: &'a [u8; KEY_LEN],
    nonce: &'a [u8; NONCE_LEN],
    aad: &'a [u8],
    tag: &'a [u8; TAG_LEN],
    /// The ciphertext byte to flip a bit of, if any.
    flipped_byte: Option<usize>,
}

#[cfg(test)]
mod tests
{
    use super::*;

    use crypto_testkit::differential;
    use crypto_testkit::rng::Rng;
    use crypto_testkit::wycheproof::{self, Case as _, aead};

    #[test]
    fn kats_pass()
    {
        assert_eq!(run_chacha20_poly1305_kats(), Ok(()));
    }

    /// A Wycheproof case's key, nonce and tag at the lengths the API takes;
    /// `None` for any other length, which the API's types refuse.
    fn sized(case: &aead::Case) -> Option<([u8; KEY_LEN], [u8; NONCE_LEN], [u8; TAG_LEN])>
    {
        let key = <[u8; KEY_LEN]>::try_from(case.key.as_slice()).ok()?;
        let nonce = <[u8; NONCE_LEN]>::try_from(case.iv.as_slice()).ok()?;
        let tag = <[u8; TAG_LEN]>::try_from(case.tag.as_slice()).ok()?;
        Some((key, nonce, tag))
    }

    /// Every Wycheproof ChaCha20-Poly1305 case: `open` turns the ciphertext
    /// of a valid case back into its plaintext, and refuses every invalid
    /// one (a modified tag; a nonce of another size, which the API's
    /// `&[u8; 12]` refuses).
    #[test]
    fn open_passes_every_wycheproof_case()
    {
        let file = wycheproof::load::<aead::Group>(&wycheproof::CHACHA20_POLY1305).unwrap();
        let report = wycheproof::run(
            &file,
            "wycheproof chacha20-poly1305 open",
            |_, case| {
                sized(case).is_some_and(|(key, nonce, tag)| {
                    let mut buffer = case.ct.clone();
                    open(&key, &nonce, &case.aad, &mut buffer, &tag).is_ok() && buffer == case.msg
                })
            },
            |_, case| panic!("the file holds no acceptable case, but tcId {}", case.id()),
        );
        assert!(report.agrees(), "{report}");
    }

    /// Every valid Wycheproof case: `seal` turns the plaintext into exactly
    /// the case's ciphertext and tag.
    #[test]
    fn seal_produces_the_ciphertext_and_tag_of_every_valid_wycheproof_case()
    {
        let file = wycheproof::load::<aead::Group>(&wycheproof::CHACHA20_POLY1305).unwrap();
        let valid = file
            .groups
            .iter()
            .flat_map(|group| group.tests.iter())
            .filter(|case| case.expected() == wycheproof::Expected::Valid);
        let report = differential::compare(
            "wycheproof chacha20-poly1305 seal",
            valid,
            |case| {
                let (key, nonce, _) = sized(case).unwrap();
                let mut buffer = case.msg.clone();
                let tag = seal(&key, &nonce, &case.aad, &mut buffer).unwrap();
                (buffer, tag.to_vec())
            },
            |case| (case.ct.clone(), case.tag.clone()),
        );
        assert!(report.agrees(), "{report}");
    }

    /// The seed of the generated inputs; any fixed value serves.
    const SEED: u64 = 0x5e4a_c20b;

    /// A buffer of every length from 0 to 300 bytes (the 16-byte Poly1305
    /// and 64-byte keystream block boundaries among them) and of a page,
    /// each with AAD of a length that varies with it, opens back to its
    /// plaintext after sealing.
    #[test]
    fn open_returns_what_seal_sealed_at_every_length()
    {
        let mut rng = Rng::new(SEED);
        for len in (0..=300).chain([1023, 1024, 1025, 4096])
        {
            let key = rng.array::<KEY_LEN>();
            let nonce = rng.array::<NONCE_LEN>();
            let aad = rng.bytes(len % 37);
            let plaintext = rng.bytes(len);
            let mut buffer = plaintext.clone();
            let tag = seal(&key, &nonce, &aad, &mut buffer).unwrap();
            assert!(
                len == 0 || buffer != plaintext,
                "length {len}: not encrypted"
            );
            open(&key, &nonce, &aad, &mut buffer, &tag).unwrap();
            assert_eq!(buffer, plaintext, "length {len}");
        }
    }

    /// Whether `open` refuses the inputs with `TagMismatch` and leaves the
    /// buffer holding `ciphertext`.
    fn refused(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> bool
    {
        let mut buffer = ciphertext.to_vec();
        let result = open(key, nonce, aad, &mut buffer, tag);
        result == Err(OpenError::TagMismatch) && buffer == ciphertext
    }

    /// Every one-bit change to a sealed page's tag, nonce and AAD, one bit
    /// of every ciphertext byte (rotating through the bit positions), a
    /// truncated ciphertext and another key are each refused with
    /// `TagMismatch`, the buffer still holding the ciphertext.
    #[test]
    fn open_refuses_any_flipped_bit_and_leaves_the_buffer_unchanged()
    {
        let mut rng = Rng::new(SEED);
        let key = rng.array::<KEY_LEN>();
        let nonce = rng.array::<NONCE_LEN>();
        let aad = rng.bytes(24);
        let mut sealed = rng.bytes(4096);
        let tag = seal(&key, &nonce, &aad, &mut sealed).unwrap();
        assert!(!refused(&key, &nonce, &aad, &sealed, &tag));

        for bit in 0..TAG_LEN * 8
        {
            let mut bad = tag;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(refused(&key, &nonce, &aad, &sealed, &bad), "tag bit {bit}");
        }
        for bit in 0..NONCE_LEN * 8
        {
            let mut bad = nonce;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(refused(&key, &bad, &aad, &sealed, &tag), "nonce bit {bit}");
        }
        for bit in 0..aad.len() * 8
        {
            let mut bad = aad.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(refused(&key, &nonce, &bad, &sealed, &tag), "aad bit {bit}");
        }
        for byte in 0..sealed.len()
        {
            let mut bad = sealed.clone();
            bad[byte] ^= 1 << (byte % 8);
            assert!(
                refused(&key, &nonce, &aad, &bad, &tag),
                "ciphertext byte {byte}"
            );
        }
        assert!(
            refused(&key, &nonce, &aad, &sealed[..4095], &tag),
            "truncated"
        );
        let mut other_key = key;
        other_key[0] ^= 1;
        assert!(
            refused(&other_key, &nonce, &aad, &sealed, &tag),
            "another key"
        );
    }

    /// The length bound: `MAX_LEN` bytes of keystream from block 1 on fit
    /// the 32-bit counter and one more byte does not; at the last counter
    /// value one block fits and a byte more does not. `seal` and `open`
    /// refuse a buffer by this check before touching it.
    #[test]
    fn the_keystream_covers_max_len_bytes_and_no_more()
    {
        assert!(chacha20::fits(1, MAX_LEN));
        assert!(!chacha20::fits(1, MAX_LEN + 1));
        assert!(chacha20::fits(u32::MAX, 64));
        assert!(!chacha20::fits(u32::MAX, 65));
        assert!(chacha20::fits(0, MAX_LEN + 64));
        assert!(!chacha20::fits(0, MAX_LEN + 65));
    }

    /// `xor_keystream` refuses a buffer the counter cannot cover, leaving it
    /// unchanged, and covers one that ends on the last counter value.
    #[test]
    fn the_keystream_refuses_a_buffer_past_the_last_counter_value()
    {
        let mut buffer = [7u8; 65];
        assert_eq!(
            chacha20::xor_keystream(&[0; KEY_LEN], u32::MAX, &[0; NONCE_LEN], &mut buffer),
            Err(CounterOverflow)
        );
        assert_eq!(buffer, [7u8; 65]);
        let mut block = [0u8; 64];
        chacha20::xor_keystream(&[0; KEY_LEN], u32::MAX, &[0; NONCE_LEN], &mut block).unwrap();
        assert_eq!(
            block,
            chacha20::block(&[0; KEY_LEN], u32::MAX, &[0; NONCE_LEN])
        );
    }

    /// A difference in any one byte makes two tags unequal.
    #[test]
    fn tags_equal_compares_every_byte()
    {
        let tag = [0x5au8; TAG_LEN];
        assert!(tags_equal(&tag, &tag));
        for byte in 0..TAG_LEN
        {
            let mut other = tag;
            other[byte] ^= 0x80;
            assert!(!tags_equal(&tag, &other), "byte {byte}");
        }
    }
}
