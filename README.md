# BPF Performance Tools

This is the official repository of BPF (eBPF) tools from the book [BPF Performance Tools: Linux and Application Observability](http://www.brendangregg.com/bpfperftools.html). The directories are:

- [originals](originals): The original published version of the tools.
- [updated](updated): Updated versions of the tools.

These tools are documented in the book.

## Updated tools

You may contribute updated versions of the tools to the updated/ directory as you find they need fixes for newer kernels or other distributions (which can change CONFIG options or library paths, changing the probes). Please avoid ifdef's where possible, and create separate tools as they can be tested and maintained independently. Filename examples:

- opensnoop_5.4.bt: opensnoop.bt for Linux 5.4 onwards
- opensnoop_redfrog.bt: opensnoop for the RedFrog Linux distribution (I made that up).
- opensnoop_redfrog11.bt: opensnoop for RedFrog release 11 onwards.
- opensnoop_redfrog11_5.4.bt: opensnoop for RedFrog release 11 onwards, with Linux 5.4 onwards.

By contributing updates to this repository, you agree that the publisher has the necessary permissions to include your updates in possible later editions of the book. Attribution will be given: make it clear in the PR what your name is. Note that the tools are deliberately short to serve as textbook examples and to simplify maintenance, and updates should not add functionality. It would be straightforward to add to these tools per-interval output, PID or latency filters, different modes of operation, etc, but it would no longer be suited for the book or this repository.
