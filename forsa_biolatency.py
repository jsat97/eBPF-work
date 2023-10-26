#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# biolatency    Summarize block device I/O latency as a histogram.
#       For Linux, uses BCC, eBPF.
#
# USAGE: biolatency [-h] [-T] [-m] [-D] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# Modified by Jai (June 2021) for I/O latency of a PMEM device with a block device interface

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    forsa_biolatency.py			# summarize block I/O latency as a histogram
    forsa_biolatency.py 1 10		# print 1 second summaries, 10 times
    forsa_biolatency.py -mT 1		# 1s summaries, milliseconds, and timestamps
    forsa_biolatency.py -D		# show each disk device separately
    forsa_biolatency.py -F		# show I/O flags separately
"""
parser = argparse.ArgumentParser(
    description="Summarize block device I/O latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-n", "--nanoseconds", action="store_true",
    help="nanosecond histogram")
parser.add_argument("-D", "--disks", action="store_true",
    help="print a histogram per disk device")
parser.add_argument("-F", "--flags", action="store_true",
    help="print a histogram per set of I/O flags")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0
if args.flags and args.disks:
    print("ERROR: can only use -D or -F. Exiting.")
    exit()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

typedef struct disk_key {
    char disk[DISK_NAME_LEN];
    u64 slot;
} disk_key_t;

typedef struct flag_key {
    u64 flags;
    u64 slot;
} flag_key_t;

BPF_HASH(start, struct bio *);
STORAGE

// time block I/O
TRACEPOINT_PROBE(fnbd, fnbd_make_request_entry)
{
    struct bio *bio = (struct bio*)args->bio_addr;
    //bpf_trace_printk("fnbd_make_request_entry: bio %lx", (long)bio);
    u64 ts = bpf_ktime_get_ns();
    int ret = start.update(&bio, &ts);
    //bpf_trace_printk("fnbd_make_request_entry: update returns %d. key %lx", ret, (long)bio);
    return 0;
}

TRACEPOINT_PROBE(fnbd, fnbd_make_request_exit)
{
    u64 *tsp, ts_now, delta;
    struct bio *bio = (struct bio*)args->bio_addr;
    //bpf_trace_printk("fnbd_make_request_exit: bio %lx", (long)bio);

    // fetch timestamp and calculate delta
    tsp = start.lookup(&bio);
    if (tsp == 0) {
        bpf_trace_printk("fnbd_make_request_exit: missed issue. key %lx", (long)bio);
        return 0;   // missed issue
    }
    ts_now = bpf_ktime_get_ns();
    if (ts_now <= *tsp)
	    return 0;
    delta = ts_now - *tsp;
    //bpf_trace_printk("fnbd_make_request_exit: delta %llu", delta);
    FACTOR

    // store as histogram
    STORE

    start.delete(&bio);
    return 0;
}
"""

# code substitutions
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
elif args.nanoseconds:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "nsecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
if args.disks:
    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HISTOGRAM(dist, disk_key_t);')
    bpf_text = bpf_text.replace('STORE',
        'disk_key_t key = {.slot = bpf_log2l(delta)}; ' +
	'\n' +
'#ifdef bio_dev' +
	'\n' +
     'struct gendisk *bi_disk = bio->bi_disk;' +
	'\n' +
'#else' +
	'\n' +
      'struct gendisk *bi_disk = bio->bi_bdev->bd_disk; ' +
	'\n' +
'#endif' +
	'\n' +
        'void *__tmp = (void *)bi_disk->disk_name; ' +
        'bpf_probe_read(&key.disk, sizeof(key.disk), __tmp); ' +
        'dist.increment(key);')
elif args.flags:
    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HISTOGRAM(dist, flag_key_t);')
    bpf_text = bpf_text.replace('STORE',
        'flag_key_t key = {.slot = bpf_log2l(delta)}; ' +
        'key.flags = bio->bi_flags; ' +
        'dist.increment(key);')
else:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('STORE',
        'dist.increment(bpf_log2l(delta));')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
#b.trace_print()

print("Tracing block device I/O... Hit Ctrl-C to end.")

# see blk_fill_rwbs():
req_opf = {
    0: "Read",
    1: "Write",
    2: "Flush",
    3: "Discard",
    5: "SecureErase",
    6: "ZoneReset",
    7: "WriteSame",
    9: "WriteZeros"
}
REQ_OP_BITS = 8
REQ_OP_MASK = ((1 << REQ_OP_BITS) - 1)
REQ_SYNC = 1 << (REQ_OP_BITS + 3)
REQ_META = 1 << (REQ_OP_BITS + 4)
REQ_PRIO = 1 << (REQ_OP_BITS + 5)
REQ_NOMERGE = 1 << (REQ_OP_BITS + 6)
REQ_IDLE = 1 << (REQ_OP_BITS + 7)
REQ_FUA = 1 << (REQ_OP_BITS + 9)
REQ_RAHEAD = 1 << (REQ_OP_BITS + 11)
REQ_BACKGROUND = 1 << (REQ_OP_BITS + 12)
REQ_NOWAIT = 1 << (REQ_OP_BITS + 13)
def flags_print(flags):
    desc = ""
    # operation
    if flags & REQ_OP_MASK in req_opf:
        desc = req_opf[flags & REQ_OP_MASK]
    else:
        desc = "Unknown"
    # flags
    if flags & REQ_SYNC:
        desc = "Sync-" + desc
    if flags & REQ_META:
        desc = "Metadata-" + desc
    if flags & REQ_FUA:
        desc = "ForcedUnitAccess-" + desc
    if flags & REQ_PRIO:
        desc = "Priority-" + desc
    if flags & REQ_NOMERGE:
        desc = "NoMerge-" + desc
    if flags & REQ_IDLE:
        desc = "Idle-" + desc
    if flags & REQ_RAHEAD:
        desc = "ReadAhead-" + desc
    if flags & REQ_BACKGROUND:
        desc = "Background-" + desc
    if flags & REQ_NOWAIT:
        desc = "NoWait-" + desc
    return desc

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    if args.flags:
        dist.print_log2_hist(label, "flags", flags_print)
    else:
        dist.print_log2_hist(label, "disk")
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
