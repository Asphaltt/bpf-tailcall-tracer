/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */
//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
    __uint(max_entries, 10);
} progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} socks SEC(".maps");

SEC("kprobe/hanle_new_connection")
int handle_new_connection(struct pt_regs *ctx)
{
    bpf_printk("tcpconn, handle_new_connection, regs: %p\n", ctx);

    __u32 key = 0;
    struct sock **skp = bpf_map_lookup_and_delete(&socks, &key);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    __handle_new_connection(ctx, sk, PROBE_TYPE_DEFAULT, 0);

    return 0;
}

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(ctx);

    __u32 key = 0;
    bpf_map_update_elem(&socks, &key, &sk, BPF_ANY);

    bpf_printk("tcpconn, k_tcp_connect, regs: %p\n", ctx);

    bpf_tail_call_static(ctx, &progs, 2);

    return 0;
}

SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM2(ctx);

    __u32 key = 0;
    bpf_map_update_elem(&socks, &key, &sk, BPF_ANY);

    bpf_printk("tcpconn, k_icsk_complete_hashdance, regs: %p\n", ctx);

    bpf_tail_call_static(ctx, &progs, 3);

    return 0;
}