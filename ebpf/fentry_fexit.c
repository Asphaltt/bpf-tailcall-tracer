/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} socks SEC(".maps");

static __noinline void
__fn(struct pt_regs *regs, u32 index)
{
    // This is the actual function that will be called by kernel module.

    bpf_printk("tcpconn, __fn, regs: %p, index: %u\n", regs, index);

    __u32 key = 0;
    struct sock **skp = bpf_map_lookup_elem(&socks, &key);
    if (!skp)
        return;

    struct sock *sk = *skp;
    __handle_new_connection(regs, sk, PROBE_TYPE_FENTRY, index);
}

SEC("kprobe/tailcall")
int fentry_tailcall(struct pt_regs *regs)
{
    bpf_printk("tcpconn, fentry_tailcall, regs: %p\n", regs);

    __fn(regs, 2);

    /* This is to avoid clang optimization.
     * Or, the index in __fn() will be optimized to 2.
     */
    __fn(regs, 3);

    return 0;
}
