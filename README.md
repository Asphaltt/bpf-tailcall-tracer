# bpf-tailcall-tracer

This is an experiment to trace tailcalls in BPF programs.

In this experiment, it's to trace static-tailcalls in kprobe programs:

```bash
# ./bpf-tailcall-tracer
2023/08/27 04:14:59 Attached kprobe(tcp_connect)
2023/08/27 04:14:59 Attached kprobe(inet_csk_complete_hashdance)
2023/08/27 04:14:59 Listening events...
2023/08/27 04:15:20 new tcp connection: 192.168.64.11:33232 -> 142.251.10.113:80 (fentry on index: 2)
2023/08/27 04:15:20 new tcp connection: 192.168.64.11:33232 -> 142.251.10.113:80 (kprobe)
2023/08/27 04:15:22 new tcp connection: 192.168.64.11:46202 -> 74.125.24.139:80 (fentry on index: 2)
2023/08/27 04:15:22 new tcp connection: 192.168.64.11:46202 -> 74.125.24.139:80 (kprobe)
2023/08/27 04:15:24 new tcp connection: 192.168.64.11:22 -> 192.168.64.1:63660 (fentry on index: 3)
2023/08/27 04:15:24 new tcp connection: 192.168.64.11:22 -> 192.168.64.1:63660 (kprobe)
```
