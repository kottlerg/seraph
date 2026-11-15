// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/tests/qemu.rs

//! The captured QEMU tables' code evaluated on the simulated machine: the
//! interrupt routing, `_OSC`, the sleep state, the host bridge's windows,
//! PCI and CPU hotplug, the HPET and the VM generation id.

use std::path::Path;

use super::sim::{CPUHP, LPC, PCIHP, Sim, Space, path_text};
use super::*;
use crate::Fault;
use crate::eval::Evaluator;
use crate::value::{Base, Data};

fn fixture(name: &str) -> Namespace
{
    load_fixture(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name),
    )
}

/// Evaluate `path` with `args` on `sim`.
fn run(ns: &mut Namespace, sim: &mut Sim, path: &str, args: Vec<Data>) -> Result<Data, Fault>
{
    Evaluator::new(ns, sim).evaluate_path(path, args)
}

/// The path of the node a whole-object reference names.
fn ref_path(ns: &Namespace, d: &Data) -> String
{
    match d
    {
        Data::Ref(r) =>
        {
            assert!(r.path.is_empty(), "{r:?}");
            let Base::Node { node, .. } = r.base
            else
            {
                panic!("{r:?}");
            };
            path_text(&ns.path(node).unwrap())
        }
        Data::Uninitialized
        | Data::Integer(_)
        | Data::String(_)
        | Data::Buffer(_)
        | Data::Package(_)
        | Data::Name(_) => panic!("not a reference: {d:?}"),
    }
}

fn package(d: Data) -> Vec<Data>
{
    let Data::Package(p) = d
    else
    {
        panic!("not a package: {d:?}");
    };
    p
}

fn int(d: &Data) -> u64
{
    let Data::Integer(v) = d
    else
    {
        panic!("not an integer: {d:?}");
    };
    *v
}

/// Check the 128 routes of a host bridge's `_PRT`: one per slot and pin,
/// each through the link device whose name starts with `link`, source index
/// 0.
fn check_prt(ns: &Namespace, prt: Data, link: &str)
{
    let prt = package(prt);
    assert_eq!(prt.len(), 128);
    for (i, route) in prt.into_iter().enumerate()
    {
        let route = package(route);
        assert_eq!(route.len(), 4);
        assert_eq!(int(&route[0]), ((i as u64 / 4) << 16) | 0xFFFF, "route {i}");
        assert_eq!(int(&route[1]), i as u64 % 4, "route {i}");
        let source = ref_path(ns, &route[2]);
        assert!(
            source.starts_with(&format!("\\_SB_.{link}")),
            "route {i}: {source}"
        );
        assert_eq!(int(&route[3]), 0);
    }
}

#[test]
fn prt_routes_every_slot_and_pin_through_the_mode_pic_selects()
{
    let mut ns = fixture("x86-default");
    let mut sim = Sim::new();
    // _PIC(1), the APIC mode: the GSI link devices.
    run(&mut ns, &mut sim, "\\_PIC", vec![Data::Integer(1)]).unwrap();
    let prt = run(&mut ns, &mut sim, "\\_SB.PCI0._PRT", vec![]).unwrap();
    check_prt(&ns, prt, "GSI");
    // _PIC(0), the PIC mode: the PIRQ link devices.
    run(&mut ns, &mut sim, "\\_PIC", vec![Data::Integer(0)]).unwrap();
    let prt = run(&mut ns, &mut sim, "\\_SB.PCI0._PRT", vec![]).unwrap();
    check_prt(&ns, prt, "LNK");
    // riscv64's _PRT is a package naming its four link devices.
    let mut ns = fixture("riscv64-rootport");
    let prt = run(&mut ns, &mut sim, "\\_SB.PCI0._PRT", vec![]).unwrap();
    check_prt(&ns, prt, "L00");
    assert_eq!(sim.log.len(), 0);
}

/// `_OSC` of the PCI host bridge with the PCI Express UUID, every control
/// requested; the control dword and the status dword it returns.
fn osc(name: &str) -> (u32, u32)
{
    let mut ns = fixture(name);
    let mut sim = Sim::new();
    let uuid = vec![
        0x5B, 0x4D, 0xDB, 0x33, 0xF7, 0x1F, 0x1C, 0x40, 0x96, 0x57, 0x74, 0x41, 0xC0, 0x3D, 0xD7,
        0x66,
    ];
    let mut caps = Vec::new();
    for dword in [0u32, 0x1F, 0x1F]
    {
        caps.extend(dword.to_le_bytes());
    }
    let args = vec![
        Data::Buffer(uuid),
        Data::Integer(1),
        Data::Integer(3),
        Data::Buffer(caps),
    ];
    let Data::Buffer(out) = run(&mut ns, &mut sim, "\\_SB.PCI0._OSC", args).unwrap()
    else
    {
        panic!("_OSC returned no buffer");
    };
    assert_eq!(out.len(), 12);
    let dword = |i: usize| u32::from_le_bytes(out[i..i + 4].try_into().unwrap());
    assert_eq!(dword(4), 0x1F, "the support dword is unchanged");
    (dword(8), dword(0))
}

#[test]
fn osc_grants_native_hotplug_only_without_acpi_hotplug()
{
    // ACPI PCI hotplug on: native hotplug control (bit 0) withheld, and
    // the status reports the capabilities masked.
    assert_eq!(osc("x86-default"), (0x1E, 0x10));
    assert_eq!(osc("x86-rootport"), (0x1E, 0x10));
    assert_eq!(osc("riscv64-rootport"), (0x1E, 0x10));
    // ACPI PCI hotplug off: every control granted.
    assert_eq!(osc("x86-rootport-native"), (0x1F, 0));
}

#[test]
fn s5_and_host_bridge_windows()
{
    for name in ["x86-default", "riscv64-rootport"]
    {
        let mut ns = fixture(name);
        let mut sim = Sim::new();
        let s5 = run(&mut ns, &mut sim, "\\_S5", vec![]);
        if name.starts_with("x86")
        {
            let s5 = package(s5.unwrap());
            assert_eq!((int(&s5[0]), int(&s5[1])), (0, 0), "{name}");
        }
        else
        {
            // The riscv64 virt machine's tables declare no sleep state.
            assert_eq!(s5.unwrap_err().kind, FaultKind::NotFound);
        }
        let Data::Buffer(crs) = run(&mut ns, &mut sim, "\\_SB.PCI0._CRS", vec![]).unwrap()
        else
        {
            panic!("{name}: _CRS is not a buffer");
        };
        let windows: Vec<(u8, u64, u64)> = resource::descriptors(&crs)
            .map(|r| r.unwrap())
            .filter_map(|r| {
                if let Resource::Address(a) = r
                {
                    Some((a.space, a.min, a.max))
                }
                else
                {
                    None
                }
            })
            .collect();
        assert_eq!(windows[0], (resource::SPACE_BUS, 0, 0xFF), "{name}");
        assert!(
            windows.iter().any(|w| w.0 == resource::SPACE_MEMORY),
            "{name}: {windows:x?}"
        );
        if name.starts_with("x86")
        {
            // The I/O windows below and above the configuration ports; the
            // VGA window, the 32-bit window from the top of the 512 MiB of
            // RAM to the MMCONFIG area, the one above it to the I/O APIC,
            // and the 64-bit window.
            let mut expected = vec![
                (resource::SPACE_BUS, 0, 0xFF),
                (resource::SPACE_IO, 0, 0xCF7),
                (resource::SPACE_IO, 0xD00, 0xFFFF),
                (resource::SPACE_MEMORY, 0xA_0000, 0xB_FFFF),
                (resource::SPACE_MEMORY, 0x2000_0000, 0xDFFF_FFFF),
                (resource::SPACE_MEMORY, 0xF000_0000, 0xFEBF_FFFF),
            ];
            let high = windows
                .iter()
                .find(|w| w.0 == resource::SPACE_MEMORY && w.1 == 0x3800_0000_0000)
                .copied();
            expected.extend(high);
            let mut found = windows.clone();
            found.sort_unstable();
            expected.sort_unstable();
            assert_eq!(found.len(), 7, "{windows:x?}");
            assert_eq!(found, expected, "{windows:x?}");
        }
    }
}

#[test]
fn pci_hotplug_notifies_the_slot_and_ejects_it()
{
    let mut ns = fixture("x86-rootport");
    let mut sim = Sim::new();
    let bsel = int(&run(&mut ns, &mut sim, "\\_SB.PCI0.SE0_.BSEL", vec![]).unwrap());
    let bsel = u32::try_from(bsel).unwrap();
    // A card added in slot 0 of the root port's bus.
    sim.up.insert(bsel, 1);
    run(&mut ns, &mut sim, "\\_GPE._E01", vec![]).unwrap();
    assert_eq!(sim.notes, vec![("\\_SB_.PCI0.SE0_.S00_".to_string(), 1)]);
    assert_eq!(
        sim.up[&bsel], 0,
        "PCIU was read with the root port's bus selected"
    );
    // The same slot to be removed.
    sim.notes.clear();
    sim.down.insert(bsel, 1);
    run(&mut ns, &mut sim, "\\_GPE._E01", vec![]).unwrap();
    assert_eq!(sim.notes, vec![("\\_SB_.PCI0.SE0_.S00_".to_string(), 3)]);
    // The OS ejects it: the bus selected, then the slot's bit.
    sim.log.clear();
    let r = run(
        &mut ns,
        &mut sim,
        "\\_SB.PCI0.SE0_.S00_._EJ0",
        vec![Data::Integer(1)],
    )
    .unwrap();
    assert_eq!(r, Data::Uninitialized);
    assert_eq!(
        sim.io_writes(),
        vec![(PCIHP + 0x10, u64::from(bsel)), (PCIHP + 8, 1)]
    );
    assert_eq!(sim.ejected, vec![(bsel, 1)]);
    // Nothing pending: no notification.
    sim.notes.clear();
    sim.down.clear();
    run(&mut ns, &mut sim, "\\_GPE._E01", vec![]).unwrap();
    assert_eq!(sim.notes, []);
    // Without a hotplug bridge the event's method is empty.
    let mut ns = fixture("x86-default");
    sim.log.clear();
    run(&mut ns, &mut sim, "\\_GPE._E01", vec![]).unwrap();
    assert!(sim.notes.is_empty() && sim.log.is_empty());
}

#[test]
fn cpu_hotplug_scan_notifies_the_inserted_cpu()
{
    for name in ["x86-default", "x86-rootport"]
    {
        let mut ns = fixture(name);
        let mut sim = Sim::new();
        sim.inserting[1] = true;
        run(&mut ns, &mut sim, "\\_GPE._E02", vec![]).unwrap();
        assert_eq!(
            sim.notes,
            vec![("\\_SB_.CPUS.C001".to_string(), 1)],
            "{name}"
        );
        assert!(
            !sim.inserting[1],
            "{name}: the insert event was acknowledged"
        );
        // A removal request.
        sim.notes.clear();
        sim.removing[3] = true;
        run(&mut ns, &mut sim, "\\_GPE._E02", vec![]).unwrap();
        assert_eq!(
            sim.notes,
            vec![("\\_SB_.CPUS.C003".to_string(), 3)],
            "{name}"
        );
        assert!(!sim.removing[3]);
        // No event: a scan selects each CPU in turn and notifies nothing.
        sim.notes.clear();
        run(&mut ns, &mut sim, "\\_GPE._E02", vec![]).unwrap();
        assert_eq!(sim.notes, []);
        assert!(
            sim.log
                .iter()
                .all(|a| a.space == Space::Io && (CPUHP..CPUHP + 12).contains(&a.addr))
        );
    }
}

#[test]
fn hpet_status_reads_its_registers_under_the_global_lock()
{
    let mut ns = fixture("x86-default");
    let mut sim = Sim::new();
    let sta = run(&mut ns, &mut sim, "\\_SB.HPET._STA", vec![]).unwrap();
    assert_eq!(sta, Data::Integer(0xF));
    // Two field reads, each holding the lock.
    assert_eq!(
        (sim.gl_acquires, sim.gl_releases, sim.gl_held),
        (2, 2, false)
    );
    let reads: Vec<u64> = sim.log.iter().map(|a| a.addr).collect();
    assert_eq!(reads, vec![0xFED0_0000, 0xFED0_0004]);
    // No HPET: the vendor id reads as all ones.
    sim.put_mem(0xFED0_0000, 4, 0xFFFF_FFFF);
    let sta = run(&mut ns, &mut sim, "\\_SB.HPET._STA", vec![]).unwrap();
    assert_eq!(sta, Data::Integer(0));
    // The lock refused: the access fails rather than run unlocked.
    sim.gl_refuse = true;
    let f = run(&mut ns, &mut sim, "\\_SB.HPET._STA", vec![]).unwrap_err();
    assert_eq!(f.kind, FaultKind::Host(crate::HostError::Failed));
}

#[test]
fn vmgenid_address_is_the_guid_in_its_buffer()
{
    let mut ns = fixture("x86-default");
    let mut sim = Sim::new();
    let vgia = int(&run(&mut ns, &mut sim, "\\VGIA", vec![]).unwrap());
    assert_ne!(vgia, 0);
    let addr = package(run(&mut ns, &mut sim, "\\_SB.VGEN.ADDR", vec![]).unwrap());
    assert_eq!(addr, vec![Data::Integer(vgia + 0x28), Data::Integer(0)]);
}

#[test]
fn pirq_links_read_the_lpc_routing_registers()
{
    let mut ns = fixture("x86-default");
    let mut sim = Sim::new();
    let sta = run(&mut ns, &mut sim, "\\_SB.LNKA._STA", vec![]).unwrap();
    assert_eq!(sta, Data::Integer(0xB));
    let Data::Buffer(crs) = run(&mut ns, &mut sim, "\\_SB.LNKC._CRS", vec![]).unwrap()
    else
    {
        panic!("_CRS is not a buffer");
    };
    // An extended interrupt descriptor of IRQ 11.
    assert_eq!(u32::from_le_bytes(crs[5..9].try_into().unwrap()), 11);
    // Every read is of the LPC bridge's configuration space.
    assert_ne!(sim.log.len(), 0);
    for a in &sim.log
    {
        assert_eq!(a.space, Space::Pci(LPC));
        assert!((0x60..0x6C).contains(&a.addr), "{a:?}");
    }
    // A routing disabled: the link is present but off.
    sim.put_pci(LPC, 0x60, 0x80);
    assert_eq!(
        run(&mut ns, &mut sim, "\\_SB.LNKA._STA", vec![]).unwrap(),
        Data::Integer(9)
    );
}

#[test]
fn every_fixture_method_evaluates_to_a_result_on_the_simulated_machine()
{
    for dir in fixture_dirs()
    {
        let mut ns = load_fixture(&dir);
        let methods: Vec<(NodeId, u8)> = ns
            .nodes()
            .filter_map(|id| match ns.object(id)
            {
                Some(Object::Method(m)) => Some((id, m.args)),
                _ => None,
            })
            .collect();
        let mut sim = Sim::new();
        let mut faults = Vec::new();
        for (id, args) in methods
        {
            let args = vec![Data::Integer(0); usize::from(args)];
            if let Err(f) = Evaluator::new(&mut ns, &mut sim).evaluate(id, args)
            {
                faults.push((path_text(&ns.path(id).unwrap()), f));
            }
            assert!(!sim.gl_held, "the global lock left held");
        }
        // Integer arguments where a method wants a buffer (_OSC's
        // capabilities) or a resource template (_SRS) are type errors.
        for (path, f) in &faults
        {
            assert!(
                path.ends_with("._OSC") || path.ends_with("._SRS"),
                "{}: {path}: {f:?}",
                dir.display()
            );
        }
    }
}
