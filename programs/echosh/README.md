# echosh

Minimal placeholder child for [`programs/terminal`](../terminal/README.md)
(v0.0.1, #111). Reads a line from stdin and writes it back to stdout prefixed
with `[echosh] `, looping until end of input.

It exists only to give the terminal a real child process whose stdio exercises
the keyboard → terminal → child → display loop. The `[echosh] ` prefix lets the
terminal test tell child output apart from the terminal's local echo on the
shared serial stream.

This is a stand-in for the real interactive shell, which lands as
`programs/shell` under #112; at that point the terminal retargets its child by
editing the `argv` line of `terminal.svc`, and `echosh` can be removed.

No capabilities, no IPC — `std::io` over the stdio pipes the terminal provides.

---

## Summarized By

None
