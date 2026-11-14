# blockdev-forensics

A read-only Linux block-device inspection and storage-forensics command-line utility written in Python 3.

**Version:** 0.1.0  
**License:** GPL-3.0  
**Platform:** Linux (developed with Fedora 45 in mind)

## Overview

`blockdev-forensics` inventories kernel-visible block devices, reconstructs storage dependencies, examines device attributes and I/O counters, flags selected configuration concerns, and captures snapshots for later comparison. It is useful on physical Linux machines and KVM guests, including systems using virtio disks, device mapper, and loop devices.

The tool performs read-only inspection of the system. The `snapshot` and `csv` commands write report files to paths you choose; they do not change disk configuration.

## Requirements

- Python 3
- Linux with `/sys` and `/proc` mounted
- No third-party Python packages required

Some kernel data may be unavailable to unprivileged users. Run with elevated privileges only when necessary and when you trust the source code.

## Installation

```bash
unzip blockdev-forensics.zip
cd blockdev-forensics
python3 main.py --help
```

Alternatively, clone the repository once published and run `python3 main.py` from the checkout.

## Commands

| Command | Purpose |
| --- | --- |
| `scan` | Summarize discovered block devices |
| `tree` | Display storage dependency topology |
| `details` | Display detailed device attributes |
| `diagnose` | Report selected storage configuration findings |
| `sample` | Calculate I/O activity over a sampling interval |
| `snapshot` | Save a JSON snapshot |
| `compare` | Compare a saved snapshot with the current state or another snapshot |
| `csv` | Export device inventory as CSV |

Without a subcommand, the tool runs `scan`.

## Examples

Inspect all devices:

```bash
python3 main.py scan
python3 main.py tree
python3 main.py details
python3 main.py diagnose
```

Inspect a specific device or matching device names:

```bash
python3 main.py scan --device vda
python3 main.py details --device '^(vd|sd|nvme)'
python3 main.py diagnose --device vda
```

The `--device` argument accepts an exact block-device name or a regular expression. Use names such as `vda` or `nvme0n1`, rather than `/dev/vda`.

Sample I/O over five seconds:

```bash
python3 main.py sample --interval 5
python3 main.py sample --interval 10 --json
```

Save a baseline and compare it with the current state:

```bash
python3 main.py snapshot baseline.json
python3 main.py compare baseline.json
```

Compare two saved snapshots:

```bash
python3 main.py snapshot after.json
python3 main.py compare baseline.json after.json
```

Export reports:

```bash
python3 main.py scan --json > inventory.json
python3 main.py details --json > details.json
python3 main.py csv --output inventory.csv
```

Disable terminal colors by placing the global option **before** the subcommand:

```bash
python3 main.py --no-color scan
```

## Data sources and interpretation

The utility primarily reads Linux kernel interfaces in `/sys` and `/proc`. Reported I/O rates are calculated from counter differences during the requested interval. They represent activity visible inside the running Linux system, not necessarily physical-drive throughput.

On KVM guests, virtual disks and their reported characteristics may not reflect the underlying host storage hardware. Configuration diagnostics are heuristics, not definitive indications of disk failure.

## Limitations

- No direct SMART or NVMe health-log integration in v0.1.0
- No destructive tests, repair operations, or filesystem modifications
- No promise of complete visibility into host-side storage from a virtual machine
- Device information depends on available kernel interfaces and access permissions
- Snapshot comparison reports changes in the captured data; transient counters may change normally

## Development direction

Planned areas for future expansion include SMART and NVMe health integration, richer device-mapper and LVM analysis, longitudinal I/O baselines, improved anomaly detection, and more comprehensive diagnostic output.

## License

Licensed under the GNU General Public License version 3. See [LICENSE](LICENSE).
