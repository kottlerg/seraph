// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/driver-binding/src/resources.rs

//! The resource list devmgr delivers a bound driver over `ipc::bootstrap`:
//! one delivery shape for every driver (docs/driver-binding.md § Binding).
//!
//! Every round names what it carries in `data[0]`:
//!
//! | `data[0]` | Caps | Further data words | Terminal |
//! |---|---|---|---|
//! | [`kind::MMIO`] | 1 `Mmio` cap | PCI BAR index or [`NO_BAR`], physical base, bytes (non-zero), offset in the BAR (0 with [`NO_BAR`]) | no |
//! | [`kind::IO_PORT`] | 1 `IoPort` cap | base port, port count (non-zero) | no |
//! | [`kind::INTERRUPT`] | 1 to `MSG_CAP_SLOTS_MAX` `Interrupt` caps, one per vector | [`InterruptKind`], first vector, `SYS_IRQ_REGISTER` mode | no |
//! | [`kind::END`] | the present endpoint slots | presence word of the slots ([`SLOT_SERVICE`], [`SLOT_DEVMGR_QUERY`], [`SLOT_DMA`]), packed by `ipc::bootstrap::pack_slots` | yes |
//!
//! Resource rounds come first, in the device record's order, then the one
//! terminal end round. A wired interrupt is one cap, vector 0; a
//! message-signaled interrupt spans as many rounds as its vectors need, each
//! naming its first vector. A round of any other shape, a resource past
//! [`MAX_RESOURCES`], or a round after the end round fails the decode, and the
//! driver exits.

use ipc::bootstrap::BootstrapRound;
use syscall_abi::{IRQ_MODE_MASK, MSG_CAP_SLOTS_MAX};

use crate::decl::MAX_MSI_VECTORS;

/// Round kinds, carried in `data[0]`.
pub mod kind
{
    /// One `Mmio` cap.
    pub const MMIO: u64 = 1;
    /// One `IoPort` cap.
    pub const IO_PORT: u64 = 2;
    /// One or more `Interrupt` caps of one kind.
    pub const INTERRUPT: u64 = 3;
    /// The endpoint slots; the terminal round.
    pub const END: u64 = 4;
}

/// The BAR word of an `Mmio` resource that is no PCI BAR.
pub const NO_BAR: u64 = u64::MAX;
/// PCI BARs a type-0 function has; a BAR index is below this.
pub const PCI_BAR_COUNT: u8 = 6;
/// Most `Mmio` ranges a PCI function's BARs are delivered as: one per BAR,
/// and two more, since each of the two page spans devmgr withholds from the
/// driver (those holding the function's MSI-X table and its Pending Bit
/// Array) splits at most one range in two.
pub const MAX_PCI_RANGES: usize = PCI_BAR_COUNT as usize + 2;
/// Most resources one list carries: every range of a PCI function's BARs and
/// every vector a declaration may request.
pub const MAX_RESOURCES: usize = MAX_PCI_RANGES + MAX_MSI_VECTORS as usize;

/// End-round slot of the driver's service endpoint.
pub const SLOT_SERVICE: usize = 0;
/// End-round slot of the per-device badged SEND on devmgr's private driver
/// endpoint of the driver's settle batch, for `QUERY_DEVICE_INFO` and
/// `DRIVER_READY` (`ipc::devmgr_labels`). devmgr revokes it once the batch
/// has settled.
pub const SLOT_DEVMGR_QUERY: usize = 1;
/// End-round slot of the device's DMA capability, a SEND on devmgr's DMA
/// endpoint badged with the device's badge (`ipc::devmgr_dma_labels`);
/// present only for a DMA declaration bound to a device with a `Dma`
/// resource.
pub const SLOT_DMA: usize = 2;
/// Slots the end round carries.
pub const END_SLOTS: usize = 3;

const _: () = assert!(END_SLOTS <= MSG_CAP_SLOTS_MAX);

/// Most data words a round carries, `data[0]` included: an `Mmio` round's
/// five.
const MAX_ROUND_WORDS: usize = 5;

/// An interrupt resource's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptKind
{
    /// One wired line.
    Wired = 1,
    /// PCI MSI vectors.
    Msi = 2,
    /// PCI MSI-X vectors.
    MsiX = 3,
}

impl InterruptKind
{
    fn from_word(word: u64) -> Option<Self>
    {
        match word
        {
            1 => Some(Self::Wired),
            2 => Some(Self::Msi),
            3 => Some(Self::MsiX),
            _ => None,
        }
    }
}

/// One delivered resource and its capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource
{
    Mmio
    {
        cap: u64,
        /// The PCI BAR the range is part of, `None` for a range of no BAR.
        bar: Option<u8>,
        phys: u64,
        bytes: u64,
        /// The range's offset from the start of its BAR; 0 for a range of no
        /// BAR. A BAR is delivered as more than one range when devmgr withholds
        /// pages of it from the driver (the pages holding the function's MSI-X
        /// table and Pending Bit Array), each range at its own offset.
        offset: u64,
    },
    IoPort
    {
        cap: u64, base: u64, count: u64
    },
    Interrupt
    {
        cap: u64,
        kind: InterruptKind,
        /// The vector this cap is; 0 for a wired line.
        vector: u8,
        /// The mode the driver passes to `SYS_IRQ_REGISTER`.
        mode: u64,
    },
}

impl Resource
{
    /// The resource's capability.
    #[must_use]
    pub fn cap(&self) -> u64
    {
        match *self
        {
            Self::Mmio { cap, .. } | Self::IoPort { cap, .. } | Self::Interrupt { cap, .. } => cap,
        }
    }
}

/// The endpoint caps of the end round; `0` marks an absent slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Endpoints
{
    pub service: u64,
    pub devmgr_query: u64,
    /// `0` for a driver given no DMA capability.
    pub dma: u64,
}

// ── Encoder (devmgr) ────────────────────────────────────────────────────────

/// One round devmgr serves, built by a constructor below.
pub struct Round
{
    caps: [u64; MSG_CAP_SLOTS_MAX],
    cap_count: usize,
    data: [u64; MAX_ROUND_WORDS],
    data_words: usize,
    done: bool,
}

impl Round
{
    fn new(caps: &[u64], data: &[u64], done: bool) -> Self
    {
        // The counts never exceed the arrays, which is what `caps` and `data`
        // rely on; a longer input is cut to fit.
        let mut round = Self {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: caps.len().min(MSG_CAP_SLOTS_MAX),
            data: [0; MAX_ROUND_WORDS],
            data_words: data.len().min(MAX_ROUND_WORDS),
            done,
        };
        for (dst, &src) in round.caps.iter_mut().zip(caps)
        {
            *dst = src;
        }
        for (dst, &src) in round.data.iter_mut().zip(data)
        {
            *dst = src;
        }
        round
    }

    /// An `Mmio` round: `cap` covers `bytes` at `phys`, the whole of a
    /// range of no BAR or the start of PCI BAR `bar`.
    #[must_use]
    pub fn mmio(cap: u64, bar: Option<u8>, phys: u64, bytes: u64) -> Self
    {
        Self::mmio_at(cap, bar, phys, bytes, 0)
    }

    /// An `Mmio` round: `cap` covers `bytes` at `phys`, `offset` bytes into
    /// PCI BAR `bar` (`offset` is 0 for a range of no BAR).
    #[must_use]
    pub fn mmio_at(cap: u64, bar: Option<u8>, phys: u64, bytes: u64, offset: u64) -> Self
    {
        let bar = bar.map_or(NO_BAR, u64::from);
        Self::new(&[cap], &[kind::MMIO, bar, phys, bytes, offset], false)
    }

    /// An `IoPort` round: `cap` covers `count` ports from `base`.
    #[must_use]
    pub fn io_port(cap: u64, base: u64, count: u64) -> Self
    {
        Self::new(&[cap], &[kind::IO_PORT, base, count], false)
    }

    /// An `Interrupt` round: `caps` are vectors `first_vector` onwards of
    /// kind `irq_kind`, each registered with `mode`. Returns `None` when
    /// `caps` is empty or longer than a round carries.
    #[must_use]
    pub fn interrupts(
        irq_kind: InterruptKind,
        first_vector: u8,
        mode: u64,
        caps: &[u64],
    ) -> Option<Self>
    {
        if caps.is_empty() || caps.len() > MSG_CAP_SLOTS_MAX
        {
            return None;
        }
        Some(Self::new(
            caps,
            &[
                kind::INTERRUPT,
                irq_kind as u64,
                u64::from(first_vector),
                mode,
            ],
            false,
        ))
    }

    /// The terminal round, carrying `endpoints`.
    #[must_use]
    pub fn end(endpoints: &Endpoints) -> Self
    {
        let mut slots = [0u64; END_SLOTS];
        slots[SLOT_SERVICE] = endpoints.service;
        slots[SLOT_DEVMGR_QUERY] = endpoints.devmgr_query;
        slots[SLOT_DMA] = endpoints.dma;
        let packed = ipc::bootstrap::pack_slots(&slots);
        Self::new(packed.caps(), &[kind::END, packed.presence()], true)
    }

    /// The caps the round transfers.
    #[must_use]
    pub fn caps(&self) -> &[u64]
    {
        // `cap_count` is set once, in `new`, to at most `caps.len()`.
        self.caps.get(..self.cap_count).unwrap_or(&[])
    }

    /// The round's data words.
    #[must_use]
    pub fn data(&self) -> &[u64]
    {
        // `data_words` is set once, in `new`, to at most `data.len()`.
        self.data.get(..self.data_words).unwrap_or(&[])
    }

    /// Whether the round is the terminal one.
    #[must_use]
    pub fn done(&self) -> bool
    {
        self.done
    }
}

// ── Decoder (driver) ────────────────────────────────────────────────────────

/// Why a round did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListError
{
    /// A round whose `data[0]` names no round kind.
    UnknownKind(u64),
    /// A round of a known kind whose caps, words, or values do not fit it.
    Malformed(u64),
    /// More than [`MAX_RESOURCES`] resources.
    TooMany,
    /// A round after the end round.
    AfterEnd,
}

/// The resources a driver received, accumulated round by round.
pub struct ResourceList
{
    resources: [Resource; MAX_RESOURCES],
    count: usize,
    endpoints: Option<Endpoints>,
}

impl Default for ResourceList
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl ResourceList
{
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            resources: [Resource::IoPort {
                cap: 0,
                base: 0,
                count: 0,
            }; MAX_RESOURCES],
            count: 0,
            endpoints: None,
        }
    }

    /// Absorb one received round. Returns whether the list is complete (the
    /// round was the end round). On an error nothing is recorded, so the
    /// round's caps are still the caller's.
    ///
    /// # Errors
    /// [`ListError`] for a round that does not decode.
    pub fn absorb(&mut self, round: &BootstrapRound) -> Result<bool, ListError>
    {
        if self.endpoints.is_some()
        {
            return Err(ListError::AfterEnd);
        }
        let (Some(words), Some(caps)) = (
            round.data.get(..round.data_words),
            round.caps.get(..round.cap_count),
        )
        else
        {
            return Err(ListError::Malformed(0));
        };
        let Some(&round_kind) = words.first()
        else
        {
            return Err(ListError::Malformed(0));
        };
        let bad = ListError::Malformed(round_kind);
        if round.done != (round_kind == kind::END)
        {
            return Err(bad);
        }
        match (round_kind, caps, words)
        {
            (kind::END, _, &[_, presence]) =>
            {
                if presence >> END_SLOTS != 0
                {
                    return Err(bad);
                }
                let slots = ipc::bootstrap::spread_slots(caps, presence).map_err(|_| bad)?;
                self.endpoints = Some(Endpoints {
                    service: slots[SLOT_SERVICE],
                    devmgr_query: slots[SLOT_DEVMGR_QUERY],
                    dma: slots[SLOT_DMA],
                });
                Ok(true)
            }
            (kind::MMIO, &[cap], &[_, bar, phys, bytes, offset]) =>
            {
                let bar = match bar
                {
                    NO_BAR => None,
                    b => Some(
                        u8::try_from(b)
                            .ok()
                            .filter(|&b| b < PCI_BAR_COUNT)
                            .ok_or(bad)?,
                    ),
                };
                if bytes == 0
                    || phys.checked_add(bytes).is_none()
                    || offset.checked_add(bytes).is_none()
                    || (bar.is_none() && offset != 0)
                {
                    return Err(bad);
                }
                self.push(&[Resource::Mmio {
                    cap,
                    bar,
                    phys,
                    bytes,
                    offset,
                }])
            }
            (kind::IO_PORT, &[cap], &[_, base, count]) =>
            {
                if count == 0 || base.checked_add(count).is_none_or(|end| end > 0x1_0000)
                {
                    return Err(bad);
                }
                self.push(&[Resource::IoPort { cap, base, count }])
            }
            (kind::INTERRUPT, _, &[_, irq_kind, first, mode]) =>
            {
                let mut batch = [Resource::IoPort {
                    cap: 0,
                    base: 0,
                    count: 0,
                }; MSG_CAP_SLOTS_MAX];
                let decoded = decode_interrupts(caps, irq_kind, first, mode, &mut batch);
                self.push(batch.get(..decoded.ok_or(bad)?).ok_or(bad)?)
            }
            (kind::END | kind::MMIO | kind::IO_PORT | kind::INTERRUPT, _, _) => Err(bad),
            (other, _, _) => Err(ListError::UnknownKind(other)),
        }
    }

    fn push(&mut self, batch: &[Resource]) -> Result<bool, ListError>
    {
        let end = self
            .count
            .checked_add(batch.len())
            .filter(|&end| end <= MAX_RESOURCES)
            .ok_or(ListError::TooMany)?;
        self.resources
            .get_mut(self.count..end)
            .ok_or(ListError::TooMany)?
            .copy_from_slice(batch);
        self.count = end;
        Ok(false)
    }

    /// The resources, in delivery order.
    #[must_use]
    pub fn resources(&self) -> &[Resource]
    {
        // `count` is set only in `new` (0) and `push`, which keeps it within
        // `MAX_RESOURCES`.
        self.resources.get(..self.count).unwrap_or(&[])
    }

    /// The endpoints of the end round; `None` until it is absorbed.
    #[must_use]
    pub fn endpoints(&self) -> Option<Endpoints>
    {
        self.endpoints
    }

    /// Every cap the list holds, resources and present endpoints.
    pub fn caps(&self) -> impl Iterator<Item = u64> + '_
    {
        let eps = self.endpoints.unwrap_or_default();
        self.resources()
            .iter()
            .map(Resource::cap)
            .chain([eps.service, eps.devmgr_query, eps.dma])
            .filter(|&cap| cap != 0)
    }
}

/// What the driver of a platform device record takes from its resource list
/// (docs/driver-binding.md § Device Records): the device's register window,
/// its wired line if one was delivered, and the endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformDelivery
{
    /// The first `Mmio` or `IoPort` resource of the list.
    pub registers: Resource,
    /// The first wired `Interrupt` resource's cap and `SYS_IRQ_REGISTER`
    /// mode; `None` when the list delivers none.
    pub wired: Option<(u64, u64)>,
    /// The end round's endpoints, the service and devmgr query endpoints
    /// both present.
    pub endpoints: Endpoints,
}

impl PlatformDelivery
{
    /// Read a complete resource list. `None` when the list has no end round,
    /// no service or devmgr query endpoint, or no `Mmio` or `IoPort`
    /// resource. Resources past the first register window and the first
    /// wired line are left in the list, unused.
    #[must_use]
    pub fn from_list(list: &ResourceList) -> Option<Self>
    {
        let endpoints = list.endpoints()?;
        if endpoints.service == 0 || endpoints.devmgr_query == 0
        {
            return None;
        }
        let registers = list
            .resources()
            .iter()
            .find(|r| matches!(r, Resource::Mmio { .. } | Resource::IoPort { .. }))
            .copied()?;
        let wired = list.resources().iter().find_map(|r| match *r
        {
            Resource::Interrupt {
                cap,
                kind: InterruptKind::Wired,
                mode,
                ..
            } => Some((cap, mode)),
            _ => None,
        });
        Some(Self {
            registers,
            wired,
            endpoints,
        })
    }
}

/// Request rounds from `creator` until the end round, decoding each into a
/// [`ResourceList`]. The rounds are bounded: each one either adds a resource
/// or ends the list, and the list holds at most [`MAX_RESOURCES`].
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// The `ipc::bootstrap::request_round` error of a failed round, or
/// `ipc::bootstrap_errors::INVALID` for a round that does not decode. On an
/// error every cap received so far is deleted.
pub unsafe fn receive(creator: u64, ipc_buf: *mut u64) -> Result<ResourceList, u64>
{
    let mut list = ResourceList::new();
    loop
    {
        // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
        let round = match unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }
        {
            Ok(round) => round,
            Err(code) =>
            {
                delete(list.caps());
                return Err(code);
            }
        };
        match list.absorb(&round)
        {
            Ok(true) => return Ok(list),
            Ok(false) =>
            {}
            Err(_) =>
            {
                delete(round.caps.iter().take(round.cap_count).copied());
                delete(list.caps());
                return Err(ipc::bootstrap_errors::INVALID);
            }
        }
    }
}

fn delete(caps: impl Iterator<Item = u64>)
{
    for cap in caps
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Decode an `Interrupt` round's `caps` and words into `batch`, one
/// [`Resource::Interrupt`] per cap. Returns how many it wrote, or `None` for
/// an unknown kind, a vector past [`MAX_MSI_VECTORS`], a mode outside the
/// `SYS_IRQ_REGISTER` mask, no caps, or a wired round of more than one cap or
/// a vector other than 0.
fn decode_interrupts(
    caps: &[u64],
    irq_kind: u64,
    first: u64,
    mode: u64,
    batch: &mut [Resource; MSG_CAP_SLOTS_MAX],
) -> Option<usize>
{
    let irq_kind = InterruptKind::from_word(irq_kind)?;
    let first = u8::try_from(first).ok()?;
    // `first` is at most 255, and a `caps` long enough to saturate fails the
    // length check below either way.
    let end = usize::from(first).saturating_add(caps.len());
    let valid = !caps.is_empty()
        && caps.len() <= MSG_CAP_SLOTS_MAX
        && mode & !IRQ_MODE_MASK == 0
        && match irq_kind
        {
            InterruptKind::Wired => caps.len() == 1 && first == 0,
            InterruptKind::Msi | InterruptKind::MsiX => end <= usize::from(MAX_MSI_VECTORS),
        };
    if !valid
    {
        return None;
    }
    for ((slot, &cap), vector) in batch.iter_mut().zip(caps).zip(first..)
    {
        *slot = Resource::Interrupt {
            cap,
            kind: irq_kind,
            vector,
            mode,
        };
    }
    Some(caps.len())
}

#[cfg(test)]
mod tests
{
    use super::*;

    use syscall_abi::{IRQ_MODE_ACTIVE_LOW, IRQ_MODE_LEVEL, MSG_DATA_WORDS_MAX};

    /// The round a driver receives for `sent`, as `request_round` builds it.
    fn received(sent: &Round) -> BootstrapRound
    {
        raw(sent.done(), sent.caps(), sent.data())
    }

    fn raw(done: bool, caps: &[u64], data: &[u64]) -> BootstrapRound
    {
        let mut r = BootstrapRound {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: caps.len(),
            data: [0; MSG_DATA_WORDS_MAX],
            data_words: data.len(),
            done,
        };
        r.caps[..caps.len()].copy_from_slice(caps);
        r.data[..data.len()].copy_from_slice(data);
        r
    }

    #[test]
    fn a_round_with_counts_past_its_arrays_is_malformed()
    {
        let mut list = ResourceList::new();
        let mut round = raw(false, &[1], &[kind::IO_PORT, 0x3F8, 8]);
        round.cap_count = MSG_CAP_SLOTS_MAX + 1;
        assert_eq!(list.absorb(&round), Err(ListError::Malformed(0)));
        let mut round = raw(false, &[1], &[kind::IO_PORT, 0x3F8, 8]);
        round.data_words = MSG_DATA_WORDS_MAX + 1;
        assert_eq!(list.absorb(&round), Err(ListError::Malformed(0)));
        assert!(list.resources().is_empty());
    }

    #[test]
    fn a_round_built_from_too_much_is_cut_to_what_it_holds()
    {
        let caps = [7u64; MSG_CAP_SLOTS_MAX + 2];
        let data = [9u64; MAX_ROUND_WORDS + 2];
        let round = Round::new(&caps, &data, false);
        assert_eq!(round.caps().len(), MSG_CAP_SLOTS_MAX);
        assert_eq!(round.data().len(), MAX_ROUND_WORDS);
    }

    fn decoded(rounds: &[Round]) -> Result<ResourceList, ListError>
    {
        let mut list = ResourceList::new();
        for (i, round) in rounds.iter().enumerate()
        {
            let complete = list.absorb(&received(round))?;
            assert_eq!(
                complete,
                i + 1 == rounds.len(),
                "only the last round ends the list"
            );
        }
        Ok(list)
    }

    #[test]
    fn every_resource_kind_round_trips_in_order()
    {
        let mode = IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW;
        let rounds = [
            Round::mmio(10, Some(4), 0xFE00_0000, 0x4000),
            Round::mmio(11, None, 0x1000_0000, 0x1000),
            Round::io_port(12, 0x3F8, 8),
            Round::interrupts(InterruptKind::Wired, 0, mode, &[13]).expect("one wired cap"),
            Round::mmio_at(14, Some(4), 0xFE00_6000, 0x2000, 0x6000),
            Round::end(&Endpoints {
                service: 20,
                devmgr_query: 21,
                dma: 22,
            }),
        ];
        let list = decoded(&rounds).expect("well-formed list");
        assert_eq!(
            list.resources(),
            &[
                Resource::Mmio {
                    cap: 10,
                    bar: Some(4),
                    phys: 0xFE00_0000,
                    bytes: 0x4000,
                    offset: 0
                },
                Resource::Mmio {
                    cap: 11,
                    bar: None,
                    phys: 0x1000_0000,
                    bytes: 0x1000,
                    offset: 0
                },
                Resource::IoPort {
                    cap: 12,
                    base: 0x3F8,
                    count: 8
                },
                Resource::Interrupt {
                    cap: 13,
                    kind: InterruptKind::Wired,
                    vector: 0,
                    mode
                },
                Resource::Mmio {
                    cap: 14,
                    bar: Some(4),
                    phys: 0xFE00_6000,
                    bytes: 0x2000,
                    offset: 0x6000
                },
            ]
        );
        assert_eq!(
            list.endpoints(),
            Some(Endpoints {
                service: 20,
                devmgr_query: 21,
                dma: 22
            })
        );
        assert_eq!(
            list.caps().collect::<Vec<_>>(),
            [10, 11, 12, 13, 14, 20, 21, 22]
        );
    }

    #[test]
    fn an_absent_endpoint_is_left_off_and_reads_as_zero()
    {
        let list = decoded(&[Round::end(&Endpoints {
            service: 20,
            devmgr_query: 21,
            dma: 0,
        })])
        .expect("end round alone");
        assert!(list.resources().is_empty());
        assert_eq!(list.endpoints().map(|e| e.dma), Some(0));
        assert_eq!(list.caps().collect::<Vec<_>>(), [20, 21]);
    }

    #[test]
    fn message_signaled_vectors_span_rounds_with_their_first_vector()
    {
        let rounds = [
            Round::interrupts(InterruptKind::MsiX, 0, 0, &[30, 31, 32, 33]).expect("4 vectors"),
            Round::interrupts(InterruptKind::MsiX, 4, 0, &[34]).expect("1 vector"),
            Round::end(&Endpoints::default()),
        ];
        let list = decoded(&rounds).expect("well-formed list");
        let vectors: Vec<(u64, u8)> = list
            .resources()
            .iter()
            .map(|r| match *r
            {
                Resource::Interrupt { cap, vector, .. } => (cap, vector),
                _ => panic!("only interrupts"),
            })
            .collect();
        assert_eq!(vectors, [(30, 0), (31, 1), (32, 2), (33, 3), (34, 4)]);
    }

    #[test]
    fn the_encoder_refuses_an_empty_or_oversized_interrupt_round()
    {
        assert!(Round::interrupts(InterruptKind::Msi, 0, 0, &[]).is_none());
        assert!(Round::interrupts(InterruptKind::Msi, 0, 0, &[1; MSG_CAP_SLOTS_MAX + 1]).is_none());
    }

    #[test]
    fn a_malformed_round_is_refused_and_records_nothing()
    {
        let m = kind::MMIO;
        let p = kind::IO_PORT;
        let i = kind::INTERRUPT;
        let e = kind::END;
        let cases: &[(bool, &[u64], &[u64], ListError)] = &[
            // No kind word.
            (false, &[1], &[], ListError::Malformed(0)),
            (false, &[1], &[99, 0, 0, 1], ListError::UnknownKind(99)),
            // MMIO: two caps, a word short, BAR 6, no bytes, wrapping range,
            // wrapping offset, an offset into no BAR, terminal.
            (false, &[1, 2], &[m, 0, 0, 1, 0], ListError::Malformed(m)),
            (false, &[1], &[m, 0, 0, 1], ListError::Malformed(m)),
            (false, &[1], &[m, 6, 0, 1, 0], ListError::Malformed(m)),
            (false, &[1], &[m, 0, 0, 0, 0], ListError::Malformed(m)),
            (
                false,
                &[1],
                &[m, 0, u64::MAX, 2, 0],
                ListError::Malformed(m),
            ),
            (
                false,
                &[1],
                &[m, 0, 0, 2, u64::MAX],
                ListError::Malformed(m),
            ),
            (
                false,
                &[1],
                &[m, NO_BAR, 0, 1, 0x1000],
                ListError::Malformed(m),
            ),
            (true, &[1], &[m, 0, 0, 1, 0], ListError::Malformed(m)),
            // IoPort: no ports, past port 0xFFFF.
            (false, &[1], &[p, 0x3F8, 0], ListError::Malformed(p)),
            (false, &[1], &[p, 0xFFFF, 2], ListError::Malformed(p)),
            // Interrupt: no cap, unknown kind, mode bit outside the mask, a
            // wired round of two caps or vector 1, vectors past the bound.
            (false, &[], &[i, 1, 0, 0], ListError::Malformed(i)),
            (false, &[1], &[i, 4, 0, 0], ListError::Malformed(i)),
            (
                false,
                &[1],
                &[i, 1, 0, IRQ_MODE_MASK + 1],
                ListError::Malformed(i),
            ),
            (false, &[1, 2], &[i, 1, 0, 0], ListError::Malformed(i)),
            (false, &[1], &[i, 1, 1, 0], ListError::Malformed(i)),
            (
                false,
                &[1],
                &[i, 2, u64::from(MAX_MSI_VECTORS), 0],
                ListError::Malformed(i),
            ),
            // End: not terminal, presence disagreeing with the caps, a slot
            // past END_SLOTS, a word short.
            (false, &[1], &[e, 0b1], ListError::Malformed(e)),
            (true, &[1], &[e, 0b11], ListError::Malformed(e)),
            (true, &[1], &[e, 0b1000], ListError::Malformed(e)),
            (true, &[], &[e], ListError::Malformed(e)),
        ];
        for &(done, caps, data, err) in cases
        {
            let mut list = ResourceList::new();
            assert_eq!(
                list.absorb(&raw(done, caps, data)),
                Err(err),
                "done {done} caps {caps:?} data {data:?}"
            );
            assert_eq!(list.caps().count(), 0);
            assert_eq!(list.endpoints(), None);
        }
    }

    #[test]
    fn a_round_after_the_end_is_refused()
    {
        let mut list = ResourceList::new();
        let end = Round::end(&Endpoints::default());
        assert_eq!(list.absorb(&received(&end)), Ok(true));
        assert_eq!(list.absorb(&received(&end)), Err(ListError::AfterEnd));
        let mmio = Round::mmio(1, None, 0, 1);
        assert_eq!(list.absorb(&received(&mmio)), Err(ListError::AfterEnd));
    }

    #[test]
    fn resources_past_the_bound_are_refused()
    {
        let mut list = ResourceList::new();
        let mmio = Round::mmio(1, None, 0, 1);
        for _ in 0..MAX_RESOURCES
        {
            assert_eq!(list.absorb(&received(&mmio)), Ok(false));
        }
        assert_eq!(list.absorb(&received(&mmio)), Err(ListError::TooMany));
        assert_eq!(list.resources().len(), MAX_RESOURCES);
    }

    fn ends(service: u64, devmgr_query: u64) -> Round
    {
        Round::end(&Endpoints {
            service,
            devmgr_query,
            dma: 0,
        })
    }

    #[test]
    fn platform_delivery_takes_the_first_window_and_wired_line()
    {
        let mode = IRQ_MODE_LEVEL;
        let rounds = [
            Round::interrupts(InterruptKind::Msi, 0, 0, &[9]).expect("one MSI cap"),
            Round::io_port(10, 0x70, 8),
            Round::mmio(11, None, 0x1000_0000, 0x100),
            Round::interrupts(InterruptKind::Wired, 0, mode, &[12]).expect("one wired cap"),
            Round::interrupts(InterruptKind::Wired, 0, 0, &[13]).expect("one wired cap"),
            ends(20, 21),
        ];
        let list = decoded(&rounds).expect("well-formed list");
        let got = PlatformDelivery::from_list(&list).expect("a platform delivery");
        assert_eq!(
            got.registers,
            Resource::IoPort {
                cap: 10,
                base: 0x70,
                count: 8
            }
        );
        assert_eq!(got.wired, Some((12, mode)));
        assert_eq!(got.endpoints.service, 20);
        assert_eq!(got.endpoints.devmgr_query, 21);
    }

    #[test]
    fn platform_delivery_without_a_line_has_none()
    {
        let rounds = [Round::mmio(11, None, 0x101000, 0x1000), ends(20, 21)];
        let list = decoded(&rounds).expect("well-formed list");
        let got = PlatformDelivery::from_list(&list).expect("a platform delivery");
        assert_eq!(got.wired, None);
        assert!(matches!(got.registers, Resource::Mmio { cap: 11, .. }));
    }

    #[test]
    fn platform_delivery_refuses_an_incomplete_list()
    {
        let wired = Round::interrupts(InterruptKind::Wired, 0, 0, &[12]).expect("one wired cap");
        // No register window.
        let list = decoded(&[wired, ends(20, 21)]).expect("well-formed list");
        assert_eq!(PlatformDelivery::from_list(&list), None);
        // No service endpoint, then no devmgr query endpoint.
        for (service, query) in [(0, 21), (20, 0)]
        {
            let list = decoded(&[Round::io_port(10, 0x3F8, 8), ends(service, query)])
                .expect("well-formed list");
            assert_eq!(PlatformDelivery::from_list(&list), None);
        }
        // No end round yet.
        let mut list = ResourceList::new();
        assert_eq!(
            list.absorb(&received(&Round::io_port(10, 0x3F8, 8))),
            Ok(false)
        );
        assert_eq!(PlatformDelivery::from_list(&list), None);
    }
}
