# netd

Network stack daemon. Manages network interfaces via driver IPC (receiving network
device endpoints from devmgr), implements the protocol stack, and exposes
socket-like endpoints to applications.

All network I/O is mediated through IPC: netd talks to NIC drivers for packet
send/receive and to applications for socket operations. No kernel networking code
exists; the kernel's only role is delivering IPC messages.

---

## Summarized By

None
