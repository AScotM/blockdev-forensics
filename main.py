#!/usr/bin/env python3
import argparse
import collections
import csv
import dataclasses
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import sys
import time
from typing import Any

VERSION = '0.1.0'
SYS = pathlib.Path('/sys')
PROC = pathlib.Path('/proc')

class Palette:
    def __init__(self, enabled=True):
        self.enabled = enabled
    def apply(self, code, value):
        return f'\033[{code}m{value}\033[0m' if self.enabled else str(value)
    def bold(self, value): return self.apply('1', value)
    def cyan(self, value): return self.apply('36', value)
    def green(self, value): return self.apply('32', value)
    def yellow(self, value): return self.apply('33', value)
    def red(self, value): return self.apply('31', value)
    def dim(self, value): return self.apply('2', value)

C = Palette()

def read(path, default=None):
    try:
        return pathlib.Path(path).read_text(errors='replace').strip()
    except (OSError, UnicodeError):
        return default

def integer(value, default=None):
    try: return int(value)
    except (ValueError, TypeError, OverflowError): return default

def sysread(path, default=None): return read(SYS / path, default)

def command(argv, timeout=4):
    if not shutil.which(argv[0]): return None
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired): return None

def utcnow(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def human_bytes(n):
    if n is None: return '?'
    n = float(n)
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']:
        if abs(n) < 1024 or unit == 'PiB': return f'{n:.1f} {unit}'
        n /= 1024

def safe_float(n, default=None):
    try:
        f = float(n)
        return f if math.isfinite(f) else default
    except (ValueError, TypeError): return default

def identity(name):
    path = SYS / 'class/block' / name
    try:
        return {'major_minor': read(path / 'dev'), 'realpath': str(path.resolve())}
    except OSError:
        return {'major_minor': None, 'realpath': None}

def devname(path):
    try: return pathlib.Path(path).name
    except (OSError, TypeError): return None

def blocknames():
    base = SYS / 'class/block'
    try: return sorted(p.name for p in base.iterdir() if (p / 'dev').exists())
    except OSError: return []

def syslinks(path):
    try: return sorted(p.name for p in path.iterdir())
    except OSError: return []

def diskstats():
    result = {}
    text = read(PROC / 'diskstats', '')
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 14: continue
        name = parts[2]
        nums = [integer(x, 0) for x in parts[3:]]
        keys = ['reads','reads_merged','sectors_read','read_ms','writes','writes_merged','sectors_written','write_ms','in_flight','io_ms','weighted_io_ms','discards','discards_merged','sectors_discarded','discard_ms','flushes','flush_ms']
        result[name] = dict(zip(keys, nums))
    return result

def mount_unescape(s):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), s)

def mounts():
    entries = []
    for line in read(PROC / 'self/mountinfo', '').splitlines():
        left, sep, right = line.partition(' - ')
        if not sep: continue
        a, b = left.split(), right.split()
        if len(a) < 6 or len(b) < 3: continue
        entries.append({'mount_id':a[0], 'parent_id':a[1], 'major_minor':a[2], 'root':mount_unescape(a[3]), 'target':mount_unescape(a[4]), 'options':a[5], 'filesystem':b[0], 'source':mount_unescape(b[1]), 'super_options':b[2]})
    return entries

def udev_properties(name):
    value = identity(name)['major_minor']
    if not value: return {}
    path = pathlib.Path('/run/udev/data/b' + value)
    props = {}
    for line in read(path, '').splitlines():
        if line.startswith('E:') and '=' in line:
            k, v = line[2:].split('=', 1)
            if k.startswith(('ID_FS_', 'ID_MODEL', 'ID_SERIAL', 'ID_BUS', 'ID_WWN', 'ID_PART_', 'DM_')): props[k] = v
    return props

def device_type(name, path):
    if (path / 'partition').exists(): return 'partition'
    if name.startswith('dm-'): return 'device-mapper'
    if name.startswith('md'): return 'mdraid'
    if name.startswith('loop'): return 'loop'
    if name.startswith('zram'): return 'zram'
    if name.startswith('nvme'): return 'nvme'
    if name.startswith('vd'): return 'virtio'
    if name.startswith('xvd'): return 'xen'
    if name.startswith('sd'): return 'scsi'
    if name.startswith('sr'): return 'optical'
    return 'other'

def queue_data(path):
    q = path / 'queue'
    fields = ['scheduler','rotational','logical_block_size','physical_block_size','minimum_io_size','optimal_io_size','read_ahead_kb','nr_requests','max_sectors_kb','max_hw_sectors_kb','discard_granularity','discard_max_bytes','discard_max_hw_bytes','write_cache','io_poll','io_poll_delay','nomerges','rq_affinity','add_random','dax','zoned','chunk_sectors','max_segments','max_segment_size','stable_writes','fua','virt_boundary_mask']
    return {field: read(q / field) for field in fields if (q / field).exists()}

def discover():
    names = blocknames()
    stats = diskstats()
    mnts = mounts()
    devices = {}
    for name in names:
        p = SYS / 'class/block' / name
        ident = identity(name)
        props = udev_properties(name)
        size = integer(read(p / 'size'), 0) * 512
        typ = device_type(name, p)
        holders = syslinks(p / 'holders')
        slaves = syslinks(p / 'slaves')
        dm_name = read(p / 'dm/name')
        partition = integer(read(p / 'partition'))
        entry = {'name':name, 'path':'/dev/' + name, 'type':typ, 'major_minor':ident['major_minor'], 'sysfs':ident['realpath'], 'size_bytes':size, 'partition_number':partition, 'holders':holders, 'slaves':slaves, 'queue':queue_data(p), 'stats':stats.get(name, {}), 'udev':props, 'dm_name':dm_name, 'dm_uuid':read(p / 'dm/uuid'), 'model':read(p / 'device/model'), 'vendor':read(p / 'device/vendor'), 'serial':read(p / 'device/serial'), 'wwid':read(p / 'device/wwid'), 'removable':integer(read(p / 'removable')), 'readonly':integer(read(p / 'ro')), 'alignment_offset':integer(read(p / 'alignment_offset')), 'discard_alignment':integer(read(p / 'discard_alignment')), 'start_sector':integer(read(p / 'start')), 'mounts':[m for m in mnts if m['major_minor'] == ident['major_minor']]}
        if typ == 'loop': entry['backing_file'] = read(p / 'loop/backing_file')
        if typ == 'mdraid': entry['md'] = {k:read(p / 'md' / k) for k in ['level','raid_disks','array_state','degraded','sync_action','sync_completed']}
        if typ == 'zram': entry['zram'] = {k:read(p / k) for k in ['comp_algorithm','disksize','orig_data_size','compr_data_size','mem_used_total','mem_limit','max_comp_streams']}
        devices[name] = entry
    return {'schema':1, 'version':VERSION, 'timestamp':utcnow(), 'hostname':os.uname().nodename, 'kernel':os.uname().release, 'devices':devices, 'mounts':mnts, 'environment':{'uid':os.geteuid(), 'virtualization':command(['systemd-detect-virt'])}}

def parents(name, devices):
    target = devices.get(name)
    if not target: return []
    result = []
    if target['type'] == 'partition':
        try:
            parent = pathlib.Path(target['sysfs']).parent.name
            if parent in devices: result.append(parent)
        except (OSError, TypeError): pass
    result.extend(x for x in target['slaves'] if x in devices)
    return sorted(set(result))

def ancestors(name, devices, seen=None):
    seen = set() if seen is None else seen
    if name in seen: return []
    seen.add(name)
    found = []
    for p in parents(name, devices):
        found.append(p)
        found.extend(ancestors(p, devices, seen))
    return list(dict.fromkeys(found))

def children(name, devices):
    return sorted(n for n in devices if name in parents(n, devices))

def roots(devices): return sorted(n for n in devices if not parents(n, devices))

def tree_lines(devices, start=None):
    lines = []
    starts = [start] if start else roots(devices)
    def walk(name, prefix='', last=True, stack=None):
        stack = set() if stack is None else stack
        if name not in devices: return
        d = devices[name]
        marker = '└─ ' if last else '├─ '
        label = d['dm_name'] or name
        suffix = f' [{name}]' if d['dm_name'] else ''
        mnt = ','.join(m['target'] for m in d['mounts'][:3])
        lines.append(f'{prefix}{marker}{label}{suffix}  {human_bytes(d["size_bytes"])}  {d["type"]}' + (f'  mounted:{mnt}' if mnt else ''))
        if name in stack:
            lines.append(prefix + '   [cycle detected]')
            return
        kids = children(name, devices)
        for i, child in enumerate(kids): walk(child, prefix + ('   ' if last else '│  '), i == len(kids)-1, stack | {name})
    for i, n in enumerate(starts): walk(n, '', i == len(starts)-1)
    return lines

def diagnostics(snapshot):
    findings = []
    devices = snapshot['devices']
    def add(severity, code, name, message, evidence=None):
        findings.append({'severity':severity, 'code':code, 'device':name, 'message':message, 'evidence':evidence})
    for name, d in devices.items():
        q = d['queue']
        if d['readonly'] == 1: add('info','READ_ONLY',name,'Device is read-only')
        if d['type'] == 'mdraid' and integer(d.get('md',{}).get('degraded'),0) > 0: add('critical','RAID_DEGRADED',name,'MD RAID reports degraded members',d['md'])
        if d['alignment_offset'] not in (None, 0): add('warning','ALIGNMENT_OFFSET',name,'Non-zero block alignment offset',d['alignment_offset'])
        if d['discard_alignment'] not in (None, 0): add('info','DISCARD_ALIGNMENT',name,'Non-zero discard alignment',d['discard_alignment'])
        if d['type'] == 'partition' and d['start_sector'] is not None and d['start_sector'] % 2048 != 0:
            add('info','PARTITION_ALIGNMENT',name,'Partition start is not aligned to a 1 MiB boundary',d['start_sector'])
        logical = integer(q.get('logical_block_size'))
        physical = integer(q.get('physical_block_size'))
        if logical and physical and physical > logical: add('info','EMULATED_SECTOR',name,'Physical sectors are larger than logical sectors',{'logical':logical,'physical':physical})
        if d['type'] not in ('partition','loop','zram') and integer(q.get('rotational')) == 1: add('info','ROTATIONAL',name,'Device reports rotational media')
        if d['type'] in ('virtio','xen','device-mapper'): add('info','VIRTUAL_LAYER',name,'Device may not expose underlying physical drive health')
        if d['type'] == 'loop' and d.get('backing_file'): add('info','LOOP_BACKING',name,'Loop device has a backing file',d['backing_file'])
        if d['type'] == 'zram':
            z = d.get('zram',{})
            original = integer(z.get('orig_data_size'),0)
            compressed = integer(z.get('compr_data_size'),0)
            if original and compressed: add('info','ZRAM_RATIO',name,f'ZRAM compression ratio {original/compressed:.2f}x')
        if d['size_bytes'] == 0 and d['type'] not in ('loop','optical','zram'):
            add('warning','ZERO_CAPACITY',name,'Device reports zero capacity')
    return sorted(findings, key=lambda f:({'critical':0,'warning':1,'info':2}[f['severity']], f['device'],f['code']))

def delta(a,b,elapsed):
    keys = ['reads','reads_merged','sectors_read','read_ms','writes','writes_merged','sectors_written','write_ms','io_ms','weighted_io_ms','discards','sectors_discarded','flushes']
    result = {}
    for name, d in b['devices'].items():
        old = a['devices'].get(name)
        if not old or old['major_minor'] != d['major_minor']: continue
        x, y = old['stats'], d['stats']
        if not x or not y: continue
        diff = {k:y[k]-x[k] for k in keys if k in x and k in y}
        if any(v < 0 for v in diff.values()): continue
        r, w = diff.get('reads',0), diff.get('writes',0)
        io = r+w
        result[name] = {'seconds':elapsed, 'read_iops':r/elapsed, 'write_iops':w/elapsed, 'read_bytes_per_sec':diff.get('sectors_read',0)*512/elapsed, 'write_bytes_per_sec':diff.get('sectors_written',0)*512/elapsed, 'read_latency_ms_estimate':diff.get('read_ms',0)/r if r else None, 'write_latency_ms_estimate':diff.get('write_ms',0)/w if w else None, 'utilization_pct_estimate':diff.get('io_ms',0)/(elapsed*10), 'average_queue_depth_estimate':diff.get('weighted_io_ms',0)/(elapsed*1000), 'total_iops':io/elapsed, 'raw_delta':diff}
    return result

def compare(a,b):
    old, new = a['devices'], b['devices']
    changes = []
    for name in sorted(set(old)|set(new)):
        if name not in old:
            changes.append({'device':name,'kind':'added','after':new[name]['major_minor']})
        elif name not in new:
            changes.append({'device':name,'kind':'removed','before':old[name]['major_minor']})
        else:
            for field in ['major_minor','size_bytes','readonly','removable','holders','slaves','queue','mounts','dm_name','dm_uuid']:
                if old[name].get(field) != new[name].get(field):
                    changes.append({'device':name,'kind':'changed','field':field,'before':old[name].get(field),'after':new[name].get(field)})
    return changes

def dump(obj, filename=None):
    payload = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    if filename:
        path = pathlib.Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + f'.{os.getpid()}.tmp')
        with tmp.open('w') as f:
            f.write(payload+'\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,path)
    else: print(payload)

def load(filename):
    with open(filename) as f: data=json.load(f)
    if not isinstance(data,dict) or data.get('schema') != 1 or not isinstance(data.get('devices'),dict): raise ValueError('Unsupported snapshot schema')
    return data

def table(headers, rows):
    rows = [[str(v) if v is not None else '-' for v in row] for row in rows]
    widths = [max(len(str(h)),*(len(row[i]) for row in rows)) for i,h in enumerate(headers)]
    print('  '.join(C.bold(str(h).ljust(widths[i])) for i,h in enumerate(headers)))
    print('  '.join('─'*w for w in widths))
    for row in rows: print('  '.join(v.ljust(widths[i]) for i,v in enumerate(row)))

def heading(text): print('\n'+C.cyan(C.bold(text))+'\n'+'─'*min(90,len(text)+10))

def select(snapshot,pattern=None):
    devices=snapshot['devices']
    if not pattern: return devices
    if pattern in devices: return {pattern:devices[pattern]}
    try: regex=re.compile(pattern)
    except re.error as e: raise ValueError(f'Invalid device pattern: {e}')
    return {n:d for n,d in devices.items() if regex.search(n) or regex.search(d.get('dm_name') or '')}

def show_overview(snapshot,pattern=None):
    heading(f'BLOCKDEV FORENSICS  {VERSION}')
    print(f'Host: {snapshot["hostname"]}    Kernel: {snapshot["kernel"]}')
    print(f'Timestamp: {snapshot["timestamp"]}    Virtualization: {snapshot["environment"].get("virtualization") or "unknown"}')
    devices=select(snapshot,pattern)
    heading(f'DEVICES ({len(devices)})')
    table(['DEVICE','TYPE','CAPACITY','RO','MOUNTS'],[(d['dm_name'] or n,d['type'],human_bytes(d['size_bytes']),d['readonly'],','.join(m['target'] for m in d['mounts']) or '-') for n,d in devices.items()])
    heading('TOPOLOGY')
    if pattern:
        for n in devices: print('\n'.join(tree_lines(snapshot['devices'],n)))
    else: print('\n'.join(tree_lines(snapshot['devices'])))
    findings=[f for f in diagnostics(snapshot) if f['device'] in devices]
    heading(f'DIAGNOSTICS ({len(findings)})')
    for f in findings:
        label=f['severity'].upper()
        color={'critical':C.red,'warning':C.yellow,'info':C.dim}[f['severity']]
        print(f'{color(label):<18} {f["device"]:<12} {f["code"]:<24} {f["message"]}')

def show_details(snapshot,pattern):
    devices=select(snapshot,pattern)
    for name,d in devices.items():
        heading(name + (f' ({d["dm_name"]})' if d['dm_name'] else ''))
        for key in ['path','type','major_minor','sysfs','size_bytes','partition_number','start_sector','alignment_offset','discard_alignment','readonly','removable','model','vendor','serial','wwid','dm_uuid','holders','slaves','mounts','udev','queue','stats','md','zram','backing_file']:
            if key in d and d[key] not in (None,{},[]):
                value=d[key]
                if isinstance(value,(dict,list)): value=json.dumps(value,ensure_ascii=False,sort_keys=True)
                print(f'{key:24} {value}')

def show_sample(data,pattern=None):
    heading('LIVE I/O SAMPLE')
    names=select({'devices':{n:{} for n in data}},pattern)
    table(['DEVICE','READ IOPS','WRITE IOPS','READ/s','WRITE/s','R LAT ms*','W LAT ms*','BUSY %*','QUEUE*'],[(n,f'{d["read_iops"]:.1f}',f'{d["write_iops"]:.1f}',human_bytes(d['read_bytes_per_sec']),human_bytes(d['write_bytes_per_sec']),f'{d["read_latency_ms_estimate"]:.2f}' if d['read_latency_ms_estimate'] is not None else '-',f'{d["write_latency_ms_estimate"]:.2f}' if d['write_latency_ms_estimate'] is not None else '-',f'{d["utilization_pct_estimate"]:.1f}',f'{d["average_queue_depth_estimate"]:.2f}') for n,d in data.items() if n in names])
    print('\n* Kernel counter-derived estimates; not physical latency, device saturation, or end-to-end application latency.')

def csv_output(snapshot,output):
    columns=['name','type','major_minor','size_bytes','readonly','removable','model','vendor','dm_name','holders','slaves','mountpoints','scheduler','rotational','logical_block_size','physical_block_size','discard_max_bytes','reads','writes','sectors_read','sectors_written']
    with (open(output,'w',newline='') if output else os.fdopen(os.dup(sys.stdout.fileno()),'w',newline='')) as f:
        writer=csv.DictWriter(f,fieldnames=columns)
        writer.writeheader()
        for n,d in snapshot['devices'].items():
            row={k:d.get(k) for k in columns}
            row['holders']=';'.join(d['holders']);row['slaves']=';'.join(d['slaves'])
            row['mountpoints']=';'.join(m['target'] for m in d['mounts'])
            for k in ['scheduler','rotational','logical_block_size','physical_block_size','discard_max_bytes']: row[k]=d['queue'].get(k)
            for k in ['reads','writes','sectors_read','sectors_written']: row[k]=d['stats'].get(k)
            writer.writerow(row)

def main():
    parser=argparse.ArgumentParser(prog='blockdev-forensics',description='Read-only Linux block device topology, diagnostics and I/O forensics')
    parser.add_argument('--version',action='version',version=VERSION)
    sub=parser.add_subparsers(dest='action')
    for action in ['scan','tree','details','diagnose','snapshot','compare','sample','csv']:
        p=sub.add_parser(action)
        if action in ('scan','tree','details','diagnose','sample'): p.add_argument('--device',help='Exact block device name or regex')
        if action == 'snapshot': p.add_argument('file')
        if action == 'compare': p.add_argument('old');p.add_argument('new',nargs='?')
        if action == 'sample': p.add_argument('--interval',type=float,default=2.0)
        if action == 'csv': p.add_argument('--output')
        if action in ('scan','details','diagnose','sample','compare'): p.add_argument('--json',action='store_true')
    parser.add_argument('--no-color',action='store_true')
    args=parser.parse_args()
    global C
    C=Palette(sys.stdout.isatty() and not args.no_color and not os.getenv('NO_COLOR'))
    action=args.action or 'scan'
    if action == 'compare':
        a=load(args.old);b=load(args.new) if args.new else discover()
        changes=compare(a,b)
        if args.json: dump({'old':a['timestamp'],'new':b['timestamp'],'changes':changes})
        else:
            heading(f'SNAPSHOT DRIFT ({len(changes)} changes)')
            for ch in changes: print(json.dumps(ch,ensure_ascii=False,sort_keys=True))
        return 0
    if action == 'sample':
        if args.interval <= 0 or not math.isfinite(args.interval): parser.error('interval must be a positive finite number')
        start=time.monotonic();a=discover();time.sleep(args.interval);b=discover();elapsed=time.monotonic()-start
        result=delta(a,b,elapsed)
        if args.json: dump({'timestamp':b['timestamp'],'elapsed_seconds':elapsed,'devices':result})
        else: show_sample(result,args.device)
        return 0
    snapshot=discover()
    if action == 'snapshot': dump(snapshot,args.file)
    elif action == 'scan':
        if args.json: dump(snapshot if not args.device else {**snapshot,'devices':select(snapshot,args.device)})
        else: show_overview(snapshot,args.device)
    elif action == 'tree': print('\n'.join(tree_lines(snapshot['devices'],args.device)))
    elif action == 'details':
        if args.json: dump(select(snapshot,args.device))
        else: show_details(snapshot,args.device)
    elif action == 'diagnose':
        findings=[f for f in diagnostics(snapshot) if not args.device or f['device'] in select(snapshot,args.device)]
        if args.json: dump(findings)
        else:
            heading(f'DIAGNOSTICS ({len(findings)})')
            for f in findings: print(f'{f["severity"].upper():8} {f["device"]:12} {f["code"]:24} {f["message"]}')
    elif action == 'csv': csv_output(snapshot,args.output)
    return 0

if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError,ValueError,KeyboardInterrupt) as exc:
        print(f'blockdev-forensics: {exc}',file=sys.stderr)
        sys.exit(130 if isinstance(exc,KeyboardInterrupt) else 1)
