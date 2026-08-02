"""M7: qemu-user coverage tracing.

Run one firmware binary under qemu-user inside its extracted rootfs
(chroot, no full-system emulation), collect executed translation blocks via
`-d exec`, map PCs to symbols.json functions, and diff a baseline run
against a triggered run to recover the request-handling path.
"""
