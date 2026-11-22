// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/drivers_dir.rs

//! The order of svcmgr's `SET_DRIVERS_DIR` step and the liveness reads
//! between its calls: svcmgr walks its namespace root, served by vfsd, for
//! the drivers directory and the platform description tables' directory, and
//! sends both caps to devmgr (`ipc::devmgr_labels::SET_DRIVERS_DIR`).
//!
//! Once a dead server's process is torn down, no capability with the Receive
//! right on its endpoints is left, so the kernel fails a call to it, queued
//! or new, with `NoReceiver`. A failed call does not itself say that the
//! server died, so svcmgr reads a server's liveness before the step and after
//! every call to it that fails, and a dead server ends the step
//! (`services/svcmgr/docs/restart-protocol.md` § Death detection). [`run`]
//! makes that order through [`Calls`], which svcmgr implements with the
//! walks, the request and the liveness reads, so the order is host-tested
//! here and the calls stay in svcmgr.

/// A server the step calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Server
{
    /// vfsd, which serves svcmgr's namespace root and so every walk.
    Vfsd,
    /// devmgr, which takes `SET_DRIVERS_DIR`.
    Devmgr,
}

/// devmgr's answer to the request, or why it was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent
{
    /// devmgr took both caps.
    Accepted,
    /// devmgr answered with an error; the caps moved with the request and
    /// devmgr released them.
    Rejected,
    /// The request was not made, or the call failed before devmgr received
    /// it, so the kernel did not move the caps, which svcmgr still holds;
    /// names why.
    NotSent(&'static str),
    /// The call failed after devmgr received the request (`Interrupted`: its
    /// receiving thread was torn down, or received again, without a
    /// reply). The caps moved to devmgr when it received the request, so
    /// svcmgr holds neither.
    Lost,
}

/// The calls the step makes, which svcmgr implements.
pub trait Calls
{
    /// A directory cap svcmgr holds.
    type Cap: Copy;
    /// Why a walk failed.
    type Error;

    /// Whether `server` is dead, read from its substrate registration.
    fn dead(&mut self, server: Server) -> bool;

    /// Walk `path` from the namespace root, through vfsd.
    ///
    /// # Errors
    ///
    /// Why the walk failed: no such directory, or vfsd's call failed.
    fn walk(&mut self, path: &str) -> Result<Self::Cap, Self::Error>;

    /// Send `SET_DRIVERS_DIR` to devmgr with `drivers`, and `tables` when
    /// the walk found it.
    fn send(&mut self, drivers: Self::Cap, tables: Option<Self::Cap>) -> Sent;

    /// Delete a cap the step still holds.
    fn release(&mut self, cap: Self::Cap);
}

/// How the step ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<E>
{
    /// devmgr took the drivers directory, and the tables' directory when
    /// `tables` is set.
    Installed
    {
        /// Whether the tables' directory went with it.
        tables: bool,
    },
    /// devmgr refused the request.
    Rejected,
    /// The server was dead, before the step or after a call to it failed;
    /// every cap the step held is released and no later call made.
    Dead(Server),
    /// The walk of the drivers directory failed with vfsd alive.
    NoDriversDir(E),
    /// The request was not made, or failed before devmgr received it, with
    /// devmgr alive; the caps are released.
    NotSent(&'static str),
    /// devmgr received the request and did not answer it, with devmgr
    /// alive; the caps went with the request, so the step releases none.
    Lost,
}

/// Run the step: read both servers' liveness, walk `drivers_path` and then
/// `tables_path` through vfsd, and send both caps to devmgr. A failed walk
/// of `tables_path` with vfsd alive sends the drivers directory alone, since
/// an architecture that installs no platform description table has no such
/// directory. Every failed call is followed by a read of its server's
/// liveness, and a dead server ends the step with the caps it holds
/// released; a request devmgr received took both caps with it, and is
/// never followed by a release.
pub fn run<C: Calls>(calls: &mut C, drivers_path: &str, tables_path: &str) -> Outcome<C::Error>
{
    for server in [Server::Vfsd, Server::Devmgr]
    {
        if calls.dead(server)
        {
            return Outcome::Dead(server);
        }
    }
    let drivers = match calls.walk(drivers_path)
    {
        Ok(cap) => cap,
        Err(e) =>
        {
            if calls.dead(Server::Vfsd)
            {
                return Outcome::Dead(Server::Vfsd);
            }
            return Outcome::NoDriversDir(e);
        }
    };
    let tables = if let Ok(cap) = calls.walk(tables_path)
    {
        Some(cap)
    }
    else
    {
        if calls.dead(Server::Vfsd)
        {
            calls.release(drivers);
            return Outcome::Dead(Server::Vfsd);
        }
        None
    };
    match calls.send(drivers, tables)
    {
        Sent::Accepted => Outcome::Installed {
            tables: tables.is_some(),
        },
        Sent::Rejected => Outcome::Rejected,
        Sent::Lost =>
        {
            if calls.dead(Server::Devmgr)
            {
                return Outcome::Dead(Server::Devmgr);
            }
            Outcome::Lost
        }
        Sent::NotSent(why) =>
        {
            calls.release(drivers);
            if let Some(cap) = tables
            {
                calls.release(cap);
            }
            if calls.dead(Server::Devmgr)
            {
                return Outcome::Dead(Server::Devmgr);
            }
            Outcome::NotSent(why)
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::{Calls, Outcome, Sent, Server, run};

    const DRIVERS: &str = "/services/drivers";
    const TABLES: &str = "/config/devmgr/platform";

    /// One call the step made.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call
    {
        Dead(Server),
        Walk(&'static str),
        Send(u64, Option<u64>),
        Release(u64),
    }

    /// A scripted world: which servers read dead, from which liveness read
    /// on; which walks fail; devmgr's answer.
    struct World
    {
        calls: Vec<Call>,
        /// The server and the number of its liveness reads after which it
        /// reads dead.
        dies: Option<(Server, usize)>,
        reads: [usize; 2],
        drivers_found: bool,
        tables_found: bool,
        answer: Sent,
    }

    impl World
    {
        fn new() -> Self
        {
            Self {
                calls: Vec::new(),
                dies: None,
                reads: [0; 2],
                drivers_found: true,
                tables_found: true,
                answer: Sent::Accepted,
            }
        }
    }

    impl Calls for World
    {
        type Cap = u64;
        type Error = &'static str;

        fn dead(&mut self, server: Server) -> bool
        {
            self.calls.push(Call::Dead(server));
            let slot = match server
            {
                Server::Vfsd => &mut self.reads[0],
                Server::Devmgr => &mut self.reads[1],
            };
            *slot += 1;
            matches!(self.dies, Some((s, after)) if s == server && *slot > after)
        }

        fn walk(&mut self, path: &str) -> Result<u64, &'static str>
        {
            let (name, found, cap) = if path == DRIVERS
            {
                (DRIVERS, self.drivers_found, 1)
            }
            else
            {
                (TABLES, self.tables_found, 2)
            };
            self.calls.push(Call::Walk(name));
            if found { Ok(cap) } else { Err("walk failed") }
        }

        fn send(&mut self, drivers: u64, tables: Option<u64>) -> Sent
        {
            self.calls.push(Call::Send(drivers, tables));
            self.answer
        }

        fn release(&mut self, cap: u64)
        {
            self.calls.push(Call::Release(cap));
        }
    }

    const BOTH_ALIVE: [Call; 2] = [Call::Dead(Server::Vfsd), Call::Dead(Server::Devmgr)];

    #[test]
    fn both_directories_go_to_devmgr()
    {
        let mut w = World::new();
        assert_eq!(
            run(&mut w, DRIVERS, TABLES),
            Outcome::Installed { tables: true }
        );
        let mut want = BOTH_ALIVE.to_vec();
        want.extend([
            Call::Walk(DRIVERS),
            Call::Walk(TABLES),
            Call::Send(1, Some(2)),
        ]);
        assert_eq!(w.calls, want);
    }

    #[test]
    fn no_tables_directory_with_vfsd_alive_sends_the_drivers_directory_alone()
    {
        let mut w = World::new();
        w.tables_found = false;
        assert_eq!(
            run(&mut w, DRIVERS, TABLES),
            Outcome::Installed { tables: false }
        );
        let mut want = BOTH_ALIVE.to_vec();
        want.extend([
            Call::Walk(DRIVERS),
            Call::Walk(TABLES),
            Call::Dead(Server::Vfsd),
            Call::Send(1, None),
        ]);
        assert_eq!(w.calls, want);
    }

    #[test]
    fn vfsd_dead_after_the_tables_walk_failed_ends_the_step_before_devmgr()
    {
        let mut w = World::new();
        w.tables_found = false;
        w.dies = Some((Server::Vfsd, 1));
        assert_eq!(run(&mut w, DRIVERS, TABLES), Outcome::Dead(Server::Vfsd));
        let mut want = BOTH_ALIVE.to_vec();
        want.extend([
            Call::Walk(DRIVERS),
            Call::Walk(TABLES),
            Call::Dead(Server::Vfsd),
            Call::Release(1),
        ]);
        assert_eq!(w.calls, want);
    }

    #[test]
    fn vfsd_dead_after_the_drivers_walk_failed_ends_the_step()
    {
        let mut w = World::new();
        w.drivers_found = false;
        w.dies = Some((Server::Vfsd, 1));
        assert_eq!(run(&mut w, DRIVERS, TABLES), Outcome::Dead(Server::Vfsd));
        let mut want = BOTH_ALIVE.to_vec();
        want.extend([Call::Walk(DRIVERS), Call::Dead(Server::Vfsd)]);
        assert_eq!(w.calls, want);
    }

    #[test]
    fn no_drivers_directory_with_vfsd_alive_ends_the_step_unsent()
    {
        let mut w = World::new();
        w.drivers_found = false;
        assert_eq!(
            run(&mut w, DRIVERS, TABLES),
            Outcome::NoDriversDir("walk failed")
        );
        let mut want = BOTH_ALIVE.to_vec();
        want.extend([Call::Walk(DRIVERS), Call::Dead(Server::Vfsd)]);
        assert_eq!(w.calls, want);
    }

    #[test]
    fn a_dead_server_before_the_step_makes_no_call()
    {
        for server in [Server::Vfsd, Server::Devmgr]
        {
            let mut w = World::new();
            w.dies = Some((server, 0));
            assert_eq!(run(&mut w, DRIVERS, TABLES), Outcome::Dead(server));
            assert!(
                w.calls.iter().all(|c| matches!(c, Call::Dead(_))),
                "{server:?}: {:?}",
                w.calls
            );
        }
    }

    #[test]
    fn a_request_not_sent_releases_both_caps_and_reads_devmgr()
    {
        for (dies, outcome) in [
            (None, Outcome::NotSent("ipc error")),
            (Some((Server::Devmgr, 1)), Outcome::Dead(Server::Devmgr)),
        ]
        {
            let mut w = World::new();
            w.answer = Sent::NotSent("ipc error");
            w.dies = dies;
            assert_eq!(run(&mut w, DRIVERS, TABLES), outcome);
            let mut want = BOTH_ALIVE.to_vec();
            want.extend([
                Call::Walk(DRIVERS),
                Call::Walk(TABLES),
                Call::Send(1, Some(2)),
                Call::Release(1),
                Call::Release(2),
                Call::Dead(Server::Devmgr),
            ]);
            assert_eq!(w.calls, want);
        }
    }

    #[test]
    fn a_request_devmgr_received_unanswered_releases_nothing_and_reads_devmgr()
    {
        for (dies, outcome) in [
            (None, Outcome::Lost),
            (Some((Server::Devmgr, 1)), Outcome::Dead(Server::Devmgr)),
        ]
        {
            let mut w = World::new();
            w.answer = Sent::Lost;
            w.dies = dies;
            assert_eq!(run(&mut w, DRIVERS, TABLES), outcome);
            let mut want = BOTH_ALIVE.to_vec();
            want.extend([
                Call::Walk(DRIVERS),
                Call::Walk(TABLES),
                Call::Send(1, Some(2)),
                Call::Dead(Server::Devmgr),
            ]);
            assert_eq!(w.calls, want);
        }
    }

    #[test]
    fn a_refused_request_releases_nothing()
    {
        let mut w = World::new();
        w.answer = Sent::Rejected;
        assert_eq!(run(&mut w, DRIVERS, TABLES), Outcome::Rejected);
        assert!(
            !w.calls.iter().any(|c| matches!(c, Call::Release(_))),
            "{:?}",
            w.calls
        );
    }
}
