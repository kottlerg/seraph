// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/table.rs

//! Where a table devmgr serves (`QUERY_ACPI_TABLE`) sits in a read-only
//! mapping of the region its Memory capability covers.

/// The page size of every mapping.
const PAGE_SIZE: u64 = 0x1000;

/// The mapping of a served table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window
{
    /// The pages to map, from the page holding the region's base.
    pub pages: u64,
    /// The offset of the table's first byte in the mapping.
    pub offset: u64,
    /// The bytes mapped from the table's first byte to the mapping's end.
    pub len: u64,
}

/// The mapping of the region `[region_base, region_base + region_size)`
/// that holds a table at `table_phys`: from the page holding the region's
/// base to the end of the region's last page, at least one page. `None`
/// when the arithmetic overflows or the table does not start inside the
/// mapping.
#[must_use]
pub fn window(region_base: u64, region_size: u64, table_phys: u64) -> Option<Window>
{
    let start = region_base.saturating_sub(region_base % PAGE_SIZE);
    let pages = (region_base % PAGE_SIZE)
        .checked_add(region_size)?
        .div_ceil(PAGE_SIZE)
        .max(1);
    let mapped = pages.checked_mul(PAGE_SIZE)?;
    let offset = table_phys.checked_sub(start)?;
    let len = mapped.checked_sub(offset).filter(|&l| l > 0)?;
    Some(Window { pages, offset, len })
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_table_inside_an_unaligned_region_maps_from_the_region_page_to_its_end()
    {
        // Region 0x7FE1_2340 + 0x2000 spans three pages from 0x7FE1_2000.
        assert_eq!(
            window(0x7FE1_2340, 0x2000, 0x7FE1_3000),
            Some(Window {
                pages: 3,
                offset: 0x1000,
                len: 0x2000
            })
        );
        // An empty region still maps its page.
        assert_eq!(
            window(0x1000, 0, 0x1010).map(|w| (w.pages, w.len)),
            Some((1, 0xFF0))
        );
    }

    #[test]
    fn a_table_outside_the_mapping_or_an_overflowing_region_has_no_window()
    {
        assert_eq!(window(0x2000, 0x1000, 0x1FFF), None);
        assert_eq!(window(0x2000, 0x1000, 0x3000), None);
        assert_eq!(window(0x2001, u64::MAX, 0x2001), None);
    }
}
