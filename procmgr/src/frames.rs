// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/frames.rs

//! Frame allocator with free list for process page allocation.
//!
//! Manages a pool of frame capabilities delegated by init. Frames are split
//! from large initial caps via `frame_split`, and freed pages are tracked in
//! a fixed-size free list for reuse.

pub use va_layout::PAGE_SIZE;

const MAX_FREE_PAGES: usize = 64;

/// Frame allocator over initial caps delegated by init, with a free list.
///
/// init copies memory frame caps into procmgr's `CSpace` at
/// `initial_caps_base..+initial_caps_count`. This allocator splits pages from
/// those frames using `frame_split`. Freed pages go to a free list and are
/// reused before allocating fresh pages.
pub struct FramePool
{
    current_cap: u32,
    next_idx: u32,
    base: u32,
    count: u32,
    pub allocated_pages: u32,
    free_list: [u32; MAX_FREE_PAGES],
    free_count: usize,
}

impl FramePool
{
    pub fn new(base: u32, count: u32) -> Self
    {
        Self {
            current_cap: 0,
            next_idx: 0,
            base,
            count,
            allocated_pages: 0,
            free_list: [0; MAX_FREE_PAGES],
            free_count: 0,
        }
    }

    pub fn alloc_page(&mut self) -> Option<u32>
    {
        if self.free_count > 0
        {
            self.free_count -= 1;
            let cap = self.free_list[self.free_count];
            self.allocated_pages += 1;
            return Some(cap);
        }

        loop
        {
            if self.current_cap != 0
            {
                if let Ok((page, rest)) = syscall::frame_split(self.current_cap, PAGE_SIZE)
                {
                    self.current_cap = rest;
                    self.allocated_pages += 1;
                    return Some(page);
                }
                // Split failed — current frame is one page or less. Use it directly.
                let cap = self.current_cap;
                self.current_cap = 0;
                self.allocated_pages += 1;
                return Some(cap);
            }

            if self.next_idx >= self.count
            {
                return None;
            }
            self.current_cap = self.base + self.next_idx;
            self.next_idx += 1;
        }
    }

    /// Return a single-page frame cap to the free list for reuse.
    pub fn free_page(&mut self, cap: u32)
    {
        if self.free_count < MAX_FREE_PAGES
        {
            self.free_list[self.free_count] = cap;
            self.free_count += 1;
            if self.allocated_pages > 0
            {
                self.allocated_pages -= 1;
            }
        }
        // If free list is full, the cap is leaked. Acceptable for now.
    }
}
