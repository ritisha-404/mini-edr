# mini-edr (in development)

A minimal host-based endpoint detection sensor for Linux, modeled loosely on
the telemetry-and-detection loop used by **CrowdStrike Falcon** and
**SentinelOne**: continuously observe process creation and filesystem
activity, score events against detection heuristics, emit structured alerts.

## What it does right now

- Polls `/proc` every 2s and diffs the PID set to find new processes
- Reads each new process's `cmdline` and resolved `exe` path
- Flags command lines matching known-bad patterns (reverse shell primitives,
  `curl | sh`, `LD_PRELOAD` injection, etc.)
- Flags binaries executing out of world-writable temp directories
- Watches `/tmp` and `/dev/shm` via `inotify` for new files and files that
  become executable after creation (classic drop-then-chmod-then-exec
  pattern)
- Emits JSON-lines alerts to stdout and `alerts.log`

## Build

```bash
mkdir build && cd build
cmake ..
make
./mini-edr
```


