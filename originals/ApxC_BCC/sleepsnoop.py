#!/usr/bin/python
#
# sleepsnoop - Trace application sleeps.
#
# See BPF Performance Tools, Appendix C, for an explanation of this tool.
#
# Copyright (c) 2019 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License").
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-iiiii
# When copying or porting, include this comment.
#
# 19-Jun-2019   Brendan Gregg   Created this.

from bcc import BPF

# BPF program
b = BPF(text="""
struct data_t {
    u64 ts;
    u32 pid;
};

BPF_PERF_OUTPUT(events);

int kprobe__do_nanosleep(void *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns() / 1000;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};
""")

# header
print("%-18s %-6s %s" % ("TIME(s)", "PID", "CALL"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-18.9f %-6d Hello, World!" % ((float(event.ts) / 1000000),
        event.pid))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
