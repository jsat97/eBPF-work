#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# biosnoop  Trace block device I/O and print details including issuing PID.
#           For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Sep-2015   Brendan Gregg   Created this.
# 11-Feb-2016   Allan McAleavy  updated for BPF_PERF_OUTPUT
# Modified by Jai for a pmem device  that uses nbd (Jun 2021)
#
from __future__ import print_function
from bcc import BPF
import re
import argparse
from time import sleep, strftime

# arguments
examples = """examples:
     forsa_biosnoop.py           trace every IO to /dev/nbdX
     forsa_biosnoop.py 1 10      print average of all IO so far to /dev/nbdX every 1 sec, 10 times

     TIME	Actual time from the start of the first event
     COMM	command
     PID	pid of command
     CPU	cpu
     DISK	disk name
     T		IO event is for read or write
     SECTOR	sector to which IO was done
     BYTES	bytes transferred
     LAT	latency (start to end time for each IO)
     READY	time for IO to get ready
     WAIT	time taken for IO to process by the SPDK engine

     Averages are cumululative averages over the actual time for the IO as reported (not clock time).
     and are reinitialized each time script is run. Reported every <interval> seconds.
     R		Total # of reads so far
     W		Total # of writes so far
     R/s	avg # of reads/s
     W/s	avg # of writes/s
     MB_rd/s	avg MB read/s
     MB_wr/s	avg MB write/s
     MB_rd	avg MB read so far
     MB_wr	avg MB written so far
     R lat	avg read latency (start of IO to end for read)
     W lat	avg write latency (start of IO to end for write)
     Ready	avg time taken for IO to get ready
     Wait	avg time taken for IO to process by the SPDK engine
     Errors	avg # of errors (IO returned without completion) - averaged over # of IOs

"""
parser = argparse.ArgumentParser(
    description="Trace block I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("interval", nargs="?", default=0,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/bio.h>

struct data_t {
    u32 pid;
    u32 cpu;
    u64 rwflag;
    u64 delta_total;
    u64 delta_ready;
    u64 delta_wait;
    u64 sector;
    u64 len;
    u64 ts_start;
    u64 ts_ready;
    u64 ts_end;
    u64 error;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};

BPF_HASH(info, struct bio*, struct data_t);
BPF_PERF_OUTPUT(events);

// cache PID and comm by-req
TRACEPOINT_PROBE(fnbd, fnbd_make_request_entry)
{
    struct data_t data = {};
    u64 ts;
    struct bio *bio = (struct bio*)args->bio_addr;

    if (bpf_get_current_comm(&data.name, sizeof(data.name)) == 0) {
        data.pid = bpf_get_current_pid_tgid() >> 32;
    }
    data.cpu = bpf_get_smp_processor_id();
    ts = bpf_ktime_get_ns();
    data.ts_start = ts;
    info.update(&bio, &data);
    return 0;
}

TRACEPOINT_PROBE(fnbd, fnbd_make_request_ready)
{
    u64 ts;
    struct bio *bio = (struct bio*)args->bio_addr;
    struct data_t *datap;

    datap = info.lookup(&bio);
    if (datap == 0) {
        // missed tracing issue
	bpf_trace_printk("fnbd_make_request_ready missed");
        return 0;
    }
    ts = bpf_ktime_get_ns();
    datap->ts_ready = ts;
    info.update(&bio, datap);
    return 0;
}


TRACEPOINT_PROBE(fnbd, fnbd_make_request_error)
{
    struct bio *bio = (struct bio*)args->bio_addr;

    struct data_t *datap;
    datap = info.lookup(&bio);
    if (datap == 0) {
        // missed tracing issue
	bpf_trace_printk("fnbd_make_request_error missed");
        return 0;
    }
    datap->error++;
    info.update(&bio, datap);
    return 0;
}

TRACEPOINT_PROBE(fnbd, fnbd_make_request_exit)
{
    u64 ts_end;
    struct data_t *datap;
    struct bio *bio = (struct bio*)args->bio_addr;

    // fetch timestamp and calculate delta
    datap = info.lookup(&bio);
    if (datap == 0) {
        // missed tracing issue
	bpf_trace_printk("fnbd_make_request_exit missed");
        return 0;
    }

    datap->ts_end = bpf_ktime_get_ns();
    // strangely we hit this often - reject these traces
    if ( (datap->ts_end <= datap->ts_start) ||  (datap->ts_ready <= datap->ts_start)
	    || (datap->ts_end <= datap->ts_ready) ) {
	    return 0;
    }
    datap->delta_total = datap->ts_end - datap->ts_start;
    datap->delta_ready = datap->ts_ready - datap->ts_start;
    // wait after IO is submitted to spdk
    datap->delta_wait = datap->ts_end - datap->ts_ready;
#ifdef bio_dev
    struct gendisk *bi_disk = bio->bi_disk;
#else
    struct gendisk *bi_disk = bio->bi_bdev->bd_disk;
#endif
    //struct gendisk *rq_disk = bio->bi_disk;
    //struct gendisk *rq_disk = bio->bi_bdev->bd_disk;
    bpf_probe_read(&datap->len, sizeof(datap->len), &bio->bi_size);
    bpf_probe_read(&datap->sector, sizeof(datap->sector), &bio->bi_sector);
    bpf_probe_read(&datap->name, sizeof(datap->name), datap->name);
    bpf_probe_read(&datap->disk_name, sizeof(datap->disk_name), bi_disk->disk_name);

/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    datap->rwflag = !!(bio->bi_rw & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    datap->rwflag = !!((bio->rw >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    datap->rwflag = !!((bio->rw & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    events.perf_submit(args, datap, sizeof(struct data_t));
    info.delete(&bio);

    return 0;
}
"""
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

# header
def print_event_header():
    print("\n%-11s %-14s %-6s %-6s %-7s %-1s %-10s %-7s" % ("TIME(s)", "COMM", "PID", "CPU", "DISK", "T", "SECTOR", "BYTES"),end="")
    print("%-10s %-10s %-10s %-10s" % ("LAT(ns)", "READY(ns)", "WAIT(ns)", "#ERROR"))
    print("-"*120)

def print_averages_header():
    print("\n%-8s %-8s %-10s %-10s %-10s %-10s %-8s %-8s %-9s %-9s %-9s %-9s %-9s" % ("R", "W", "R/s", "W/s", "MB_rd/s", "MB_wr/s", "MB_rd", "MB_wr", "R lat(ns)", "W lat(ns)", "Ready(ns)", "Wait(ns)", "Errors"))
    print("-"*120)

rwflg = ""
start_ts = 0
delta = 0
read_tot = 0
write_tot = 0
read_bytes_tot = 0
write_bytes_tot = 0
read_latency_tot = 0
write_latency_tot = 0
wait_latency_tot = 0
ready_latency_tot = 0
error_tot = 0
event_tot = 0
event_avg_tot = 0
EVENTS_PER_HEADER = 100
NSEC_PER_SEC=1000000000
USEC_PER_SEC=1000000
MB=1024*1024
KB=1024

#calculate averages
def calc_totals(event):
    global read_tot, write_tot, read_bytes_tot, write_bytes_tot, read_latency_tot, write_latency_tot, event_tot
    global wait_latency_tot, ready_latency_tot, error_tot
    if event.rwflag == 1:
        write_tot += 1
        write_bytes_tot += event.len
        write_latency_tot += event.delta_total
    else:
        read_tot += 1
        read_bytes_tot += event.len
        read_latency_tot += event.delta_total
    event_tot += 1
    wait_latency_tot += event.delta_wait
    ready_latency_tot += event.delta_ready
    error_tot += event.error


def print_averages():
    global event_avg_tot

    if not event_avg_tot % EVENTS_PER_HEADER : print_averages_header()

    reads_per_sec = float(read_tot)/read_latency_tot * NSEC_PER_SEC  if read_latency_tot else 0.0
    writes_per_sec = float(write_tot)/write_latency_tot * NSEC_PER_SEC if write_latency_tot else 0.0
    mb_read_per_sec = float(read_bytes_tot)/MB/read_latency_tot * NSEC_PER_SEC if read_latency_tot  else 0.0
    mb_write_per_sec = float(write_bytes_tot)/MB/write_latency_tot * NSEC_PER_SEC if write_latency_tot else 0.0
    mb_read = float(read_bytes_tot)/MB
    mb_write = float(write_bytes_tot)/MB
    read_lat = float(read_latency_tot)/read_tot if read_tot else 0.0
    write_lat = float(write_latency_tot)/write_tot if write_tot else 0.0
    #ready and wait latency are just averaged over all events (R and W)
    ready_lat = float(ready_latency_tot)/event_tot if event_tot else 0.0
    wait_lat = float(wait_latency_tot)/event_tot if event_tot else 0.0
    error_avg = float(error_tot)/event_tot if event_tot else 0.0

    print("%-8.2f %-8.2f %-10.2f %-10.2f %-10.2f %-10.2f %-8.2f %-8.2f %-9.2f %-9.2f %-9.2f %-9.2f %-9.2f" % (
    read_tot, write_tot, reads_per_sec, writes_per_sec, mb_read_per_sec, mb_write_per_sec, mb_read, mb_write, read_lat, write_lat, ready_lat, wait_lat, error_avg) )
    event_avg_tot += 1

# process event
def print_event_callback(cpu, data, size):
    event = b["events"].event(data)

    #calc totals on every event
    calc_totals(event)
    if (int(args.interval) == 0):
        print_event(event)

def print_event(event):
    global start_ts

    if start_ts == 0:
        start_ts = event.ts_start

    if event.rwflag == 1:
        rwflg = "W"
    else:
        rwflg = "R"

    delta = float(event.ts_start) - start_ts
    if (event_tot == 1)  or not (event_tot % EVENTS_PER_HEADER) : print_event_header()
    print("%-11.6f %-14.14s %-6s %-6s %-7s %-1s %-10s %-7s" % (
        delta/NSEC_PER_SEC, event.name.decode('utf-8', 'replace'), event.pid, event.cpu,
        event.disk_name.decode('utf-8', 'replace'), rwflg, event.sector,
        event.len), end="")
    #latency as measured in the tracepoints
    print("%-10u %-10u %-10u %-6u" % (event.delta_total, event.delta_ready, event.delta_wait, event.error))

#when events are lost, this is called -we have this so that lost events dont get printed to stdout and clutter output
def dummy_lost_cb(event):
    pass

# loop with callback to print_event
b["events"].open_perf_buffer(print_event_callback, page_cnt=64, lost_cb=dummy_lost_cb)
exiting = 0
do_sleep = 1 if args.interval else 0
while 1:
    try:
        b.perf_buffer_poll()
        if do_sleep:
            sleep(int(args.interval))
            print_averages()
    except KeyboardInterrupt:
        exiting = 1
    countdown -= 1
    if exiting or countdown == 0:
        exit()
