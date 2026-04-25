# logd

Logging daemon. Receives structured log messages via IPC from the kernel and all
userspace components, and writes them to configured sinks (serial, file, etc.).

## Role

logd is started during bootstrap as a core service. All components send log
messages to logd's IPC endpoint rather than writing to hardware directly.

The kernel retains a direct serial logger for pre-logd output (early boot
messages, panic reports). Once logd is running, the kernel transitions
structured log output to IPC.

## Status

Not yet implemented.

---

## Summarized By

None
