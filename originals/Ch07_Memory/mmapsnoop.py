#!/usr/bin/python
#
# mmapsnoop - Trace mmap(2) calls.
#
# See BPF Performance Tools, Chapter 15, for an explanation of this tool.
#
# Copyright (c) 2019 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License").
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# 03-Feb-2019   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from struct import pack
import ctypes as ct
from time import strftime, time

# arguments
examples = """examples:
    ./mmap           # trace all mmap calls
    ./mmap -T        # include time column (HH:MM:SS)
"""
parser = argparse.ArgumentParser(
    description="Trace mmap() calls system-wide",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
    help="include time column on output (HH:MM:SS)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>

struct mmap_data_t {
    u64 len;
    u64 prot;
    u64 flags;
    u64 off;
    u64 pid;
    char comm[TASK_COMM_LEN];
    char path[DNAME_INLINE_LEN];
};
BPF_PERF_OUTPUT(mmap_events);

struct fdkey_t {
    int pid;
    int fd;
};

BPF_HASH(fd2file, struct fdkey_t, struct file *);

// cache pid+FD -> file for later lookup
// TODO: use a task->files->fdt->fd[] lookup in the mmap tracepoint instead.
int kprobe__fd_install(struct pt_regs *ctx, int fd, struct file *file)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fdkey_t key = {.fd = fd, .pid = pid};
    fd2file.update(&key, &file);
    return 0;
}

// assume this and other events are in PID context
int kprobe____close_fd(struct pt_regs *ctx, struct files_struct *files, int fd)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fdkey_t key = {.fd = fd, .pid = pid};
    fd2file.delete(&key);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    struct task_struct *task;
    struct file **fpp, *file;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fdkey_t key = {.fd = args->fd, .pid = pid};

    fpp = fd2file.lookup(&key);
    if (fpp == 0)
        return 0;
    file = *fpp;

    struct mmap_data_t data = {
        .len = args->len,
        .prot = args->prot,
        .flags = args->flags,
        .off = args->off,
        .pid = pid
    };
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = {};
    bpf_probe_read(&d_name, sizeof(d_name), (void *)&de->d_name);
    bpf_probe_read(&data.path, sizeof(data.path), d_name.name);
    mmap_events.perf_submit(args, &data, sizeof(data));

    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# event data
TASK_COMM_LEN = 16      # linux/sched.h
DNAME_INLINE_LEN = 32   # linux/dcache.h

class Data(ct.Structure):
    _fields_ = [
        ("len", ct.c_ulonglong),
        ("prot", ct.c_ulonglong),
        ("flags", ct.c_ulonglong),
        ("off", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("path", ct.c_char * DNAME_INLINE_LEN)
    ]

# from uapi/asm-generic/mman-common.h:
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_SHARED = 0x1
MAP_PRIVATE = 0x2
MAP_FIXED = 0x10
MAP_ANON = 0x20

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    # protection flags
    r = "R" if event.prot & PROT_READ else "-"
    w = "W" if event.prot & PROT_WRITE else "-"
    x = "E" if event.prot & PROT_EXEC else "-"
    prot = r + w + x

    # map flags
    s = "S" if event.flags & MAP_SHARED else "-"
    p = "P" if event.flags & MAP_PRIVATE else "-"
    f = "F" if event.flags & MAP_FIXED else "-"
    a = "A" if event.flags & MAP_ANON else "-"
    flags = s + p + f + a

    if args.time:
        print("%-8s " % strftime("%H:%M:%S"), end="")
    print("%-6d %-14.14s %-4s %-5s %-8d %-8d %s" % (event.pid,
        event.comm, prot, flags, event.off / 1024, event.len / 1024,
        event.path))

# initialize BPF
b = BPF(text=bpf_text)

# header
if args.time:
    print("%-8s " % ("TIME"), end="")
print("%-6s %-14.14s %-4s %-5s %-8s %-8s %s" % ("PID", "COMM", "PROT", "MAP",
    "OFFS(KB)", "SIZE(KB)", "FILE"));

# read events
b["mmap_events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
