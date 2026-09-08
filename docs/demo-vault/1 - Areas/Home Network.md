---
title: Home Network
tags: [infra, area]
updated: 2026-02-14
---

# Home Network

Everything sits behind one router. Nothing is port-forwarded, and that is the whole security model.

| Host | Address | Runs |
| --- | --- | --- |
| router | 192.168.1.1 | DHCP, DNS |
| attic | 192.168.1.20 | backups, `restic` |
| desk | 192.168.1.31 | workstation |

Static leases are set by MAC on the router rather than configured on each machine — one place to look when something moves.

```bash
restic -r /mnt/attic/backups backup ~/Documents --exclude-caches
```
