// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/headroom.rs

//! The requests devmgr refuses while its own `CSpace` is short of its slot
//! headroom and a top-up was refused
//! (`services/devmgr/docs/responsibilities.md` § `CSpace` headroom).
//!
//! A refused request keeps none of the capabilities it carried, so the slots
//! left, and the IPC receive reserve the next top-up's reply needs, stay
//! free. Only the requests whose kept capabilities grow with requests are
//! refused; the others keep none, or a fixed number that a repeat does not
//! add to.

use ipc::{devmgr_dma_errors, devmgr_dma_labels, devmgr_errors, devmgr_labels};

/// The error devmgr's registry refuses `label` with while its `CSpace` is
/// short: `OUT_OF_RESOURCES` for `WATCH_CLASS`, each of which keeps a
/// Notification; `None` for every other label. `SET_DRIVERS_DIR` keeps two
/// directory caps at most, the drivers directory's and the platform tables',
/// once per boot, `BIND_DRIVERS` one while its pass is pending, and the rest
/// keep nothing past the reply.
#[must_use]
pub fn registry_refusal(label: u64) -> Option<u64>
{
    (label == devmgr_labels::WATCH_CLASS).then_some(devmgr_errors::OUT_OF_RESOURCES)
}

/// The error devmgr's DMA thread refuses `label` with while its `CSpace` is
/// short: `OUT_OF_RESOURCES` for `DMA_MAP`, which keeps the mapped Memory
/// cap; `None` for `DMA_UNMAP`, `DMA_FAULTS` and every other label, which
/// keep nothing.
#[must_use]
pub fn dma_refusal(label: u64) -> Option<u64>
{
    (label == devmgr_dma_labels::DMA_MAP).then_some(devmgr_dma_errors::OUT_OF_RESOURCES)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_registry_refuses_only_a_class_watch()
    {
        assert_eq!(
            registry_refusal(devmgr_labels::WATCH_CLASS),
            Some(devmgr_errors::OUT_OF_RESOURCES)
        );
        for label in (0..=64).chain([devmgr_errors::UNKNOWN_OPCODE])
        {
            if label != devmgr_labels::WATCH_CLASS
            {
                assert_eq!(registry_refusal(label), None, "label {label}");
            }
        }
    }

    #[test]
    fn the_dma_thread_refuses_only_a_map()
    {
        assert_eq!(
            dma_refusal(devmgr_dma_labels::DMA_MAP),
            Some(devmgr_dma_errors::OUT_OF_RESOURCES)
        );
        for label in 0..=64
        {
            if label != devmgr_dma_labels::DMA_MAP
            {
                assert_eq!(dma_refusal(label), None, "label {label}");
            }
        }
    }
}
