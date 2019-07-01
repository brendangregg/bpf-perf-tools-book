#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# shellsnoop   Watch another shell session.
#              For Linux, uses BCC, eBPF. Embedded C.
#
# This traces writes to STDOUT and STDERR for the specified PID and its
# children, and prints them out. This lets you watch another shell live. Due
# to a limited buffer size, some commands (eg, a vim session) are likely to
# be printed a little messed up.
#
# Copyright (c) 2016 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Idea: from ttywatcher.
#
# 15-Oct-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import ctypes as ct
from subprocess import call
import argparse
from sys import argv
import sys

def usage():
    print("USAGE: %s PID" % argv[0])
    exit()

# arguments
examples = """examples:
    ./shellsnoop 181      # snoop on shell with PID 181
"""
parser = argparse.ArgumentParser(
    description="Snoop output from another shell",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-s", "--shellonly", action="store_true",
    help="shell output only (no sub-commands)")
parser.add_argument("-r", "--replay", action="store_true",
    help="emit a replay shell script")
parser.add_argument("pid", nargs="?", default=0,
    help="PID to trace")
args = parser.parse_args()
debug = 0

if args.pid == 0:
    print("USAGE: %s [-hs] PID" % argv[0])
    exit()
if args.replay:
    args.noclear = True

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

#define BUFSIZE 256
struct data_t {
    u64 ts;
    int count;
    char buf[BUFSIZE];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(children, u32, int);

TRACEPOINT_PROBE(sched, sched_process_fork)
{
    if (NOCHILDREN)
        return 0;
    u32 pid = args->parent_pid;
    u32 newpid = args->child_pid;
    u32 *cp = children.lookup(&pid);
    if (cp == NULL && pid != PID)
        return 0;
    int one = 1;

    children.update(&newpid, &one);
    return 0;
}

static void emit(void *ctx, const char *buf, u32 *offset, u64 ts, size_t count)
{
    struct data_t data = {.ts = ts};
    bpf_probe_read(&data.buf, BUFSIZE, (void *)buf + *offset);
    data.count = count - *offset > BUFSIZE ? BUFSIZE : count - *offset;
    *offset += BUFSIZE;
    events.perf_submit(ctx, &data, sizeof(data));
}

// switch to a tracepoint when #748 is fixed
TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    if (args->fd != 1 && args->fd != 2)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    u32 *cp = children.lookup(&pid);
    if (cp == NULL && pid != PID)
        return 0;

    // bpf_probe_read() can only use a fixed size, so truncate to count
    // in user space:
    u32 offset = 0;

    // unrolled loop to workaround stack size limit.
    // TODO: switch to use BPF map storage and a single perf_submit().
    u64 ts = bpf_ktime_get_ns();
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }
    if (offset < args->count) { emit(args, args->buf, &offset, ts, args->count); }

    return 0;
};
"""

bpf_text = bpf_text.replace('PID', str(args.pid))
bpf_text = bpf_text.replace('NOCHILDREN', str(int(args.shellonly)))
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)

BUFSIZE = 256
last_ts = 0

if not args.noclear:
    call("clear")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global last_ts
    if last_ts == 0:
        last_ts = event.ts
    if args.replay:
        delay_ms = (event.ts - last_ts) / 1000000
        if delay_ms:
            print("sleep %.2f" % (float(delay_ms) / 1000))
        printable = event.buf[0:event.count]
        printable = printable.replace('\\', '\\\\')
        printable = printable.replace('\'', '\\047')
        print("echo -e '%s\\c'" % printable)
        last_ts = event.ts
    else:
        print("%s" % event.buf[0:event.count], end="")
    sys.stdout.flush()

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.kprobe_poll()
