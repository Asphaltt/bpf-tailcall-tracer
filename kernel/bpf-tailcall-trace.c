/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: GPL-2.0
 */

#include <uapi/linux/bpf.h> // BPF_REG_*
#include <linux/bpf.h> // bpf_prog_get_type_dev bpf_prog_get_type_path
#include <linux/filter.h>
#include <linux/container_of.h> // container_of
#include <linux/init.h> // included for __init and __exit macros
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/kprobes.h> // kprobe
#include <linux/list.h> // list_for_each_entry
#include <linux/module.h> // included for all kernel modules
#include <linux/mutex.h> // mutex_lock

#define X86_PATCH_SIZE      5
#define SUB_INSN_SIZE       7

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Hwang <le0nhwan9@gmail.com>");
MODULE_DESCRIPTION("A module for tracing bpf tailcall");

struct prog_poke_elem {
	struct list_head list;
	struct bpf_prog_aux *aux;
};

static int bpf_prog_id = 0;
static int bpf_map_id = 0;

module_param(bpf_prog_id, int, 0);
module_param(bpf_map_id, int, 0);



typedef struct bpf_prog *(* bpf_prog_get_curr_or_next_fn_t)(u32 *id);
typedef struct bpf_map *(* bpf_map_get_curr_or_next_fn_t)(u32 *id);
typedef int (* bpf_arch_text_poke_fn_t)(void *ip, enum bpf_text_poke_type t,
	void *addr1, void *addr2);
typedef void *(* bpf_jit_alloc_exec_fn_t)(unsigned int size);
typedef void (* bpf_jit_free_exec_fn_t)(void *addr);
typedef int (* set_memory_rox_fn_t)(unsigned long addr, int numpages);

static bpf_prog_get_curr_or_next_fn_t bpf_prog_get_curr_or_next_fn;
static bpf_map_get_curr_or_next_fn_t bpf_map_get_curr_or_next_fn;
static bpf_arch_text_poke_fn_t bpf_arch_text_poke_fn;
static bpf_jit_alloc_exec_fn_t bpf_jit_alloc_exec_fn;
static bpf_jit_free_exec_fn_t bpf_jit_free_exec_fn;
static set_memory_rox_fn_t set_memory_rox_fn;

static int __kp_prehandler(struct kprobe *p, struct pt_regs *ctx) { return 0; }

#define BPF_GET_FN(fn, fn_t, fn_name)                                    \
	({                                                                   \
		static struct kprobe kp = {                                      \
			.symbol_name = fn_name,                                      \
			.pre_handler = __kp_prehandler,                              \
		};                                                               \
																		 \
		int ret = register_kprobe(&kp);                                  \
		if (ret < 0) {                                                   \
			pr_err("[X] register_kprobe %s failed: %d\n", fn_name, ret); \
			return ret;                                                  \
		}                                                                \
																		 \
		fn = (fn_t)kp.addr;                                              \
																		 \
		unregister_kprobe(&kp);                                          \
																		 \
		pr_info("[i] %s: %p\n", fn_name, fn);                            \
																		 \
		0;                                                               \
	})

static int __bpf_get_prog_fn(void)
{
	return BPF_GET_FN(bpf_prog_get_curr_or_next_fn,
		bpf_prog_get_curr_or_next_fn_t,
		"bpf_prog_get_curr_or_next");
}

static int __bpf_get_map_fn(void)
{
	return BPF_GET_FN(bpf_map_get_curr_or_next_fn,
		bpf_map_get_curr_or_next_fn_t,
		"bpf_map_get_curr_or_next");
}

static int __bpf_get_arch_text_poke_fn(void)
{
	return BPF_GET_FN(bpf_arch_text_poke_fn,
		bpf_arch_text_poke_fn_t,
		"bpf_arch_text_poke");
}

static int __bpf_get_jit_alloc_exec_fn(void)
{
	return BPF_GET_FN(bpf_jit_alloc_exec_fn,
		bpf_jit_alloc_exec_fn_t,
		"bpf_jit_alloc_exec");
}

static int __bpf_get_jit_free_exec_fn(void)
{
	return BPF_GET_FN(bpf_jit_free_exec_fn,
		bpf_jit_free_exec_fn_t,
		"bpf_jit_free_exec");
}

static int __set_memory_rox_fn(void)
{
	return BPF_GET_FN(set_memory_rox_fn,
		set_memory_rox_fn_t,
		"set_memory_rox");
}

static int __bpf_get_funcs(void)
{
	int ret;

	ret = __bpf_get_prog_fn();
	if (unlikely(ret < 0))
		return ret;

	ret = __bpf_get_map_fn();
	if (unlikely(ret < 0))
		return ret;

	ret = __bpf_get_arch_text_poke_fn();
	if (unlikely(ret < 0))
		return ret;

	ret = __bpf_get_jit_alloc_exec_fn();
	if (unlikely(ret < 0))
		return ret;

	ret = __bpf_get_jit_free_exec_fn();
	if (unlikely(ret < 0))
		return ret;

	ret = __set_memory_rox_fn();
	if (unlikely(ret < 0))
		return ret;

	return 0;
}

static const int reg2hex[] = {
	[BPF_REG_0] = 0,  /* RAX */
	[BPF_REG_1] = 7,  /* RDI */
	[BPF_REG_2] = 6,  /* RSI */
	[BPF_REG_3] = 2,  /* RDX */
	[BPF_REG_4] = 1,  /* RCX */
	[BPF_REG_5] = 0,  /* R8  */
	[BPF_REG_6] = 3,  /* RBX callee saved */
	[BPF_REG_7] = 5,  /* R13 callee saved */
	[BPF_REG_8] = 6,  /* R14 callee saved */
	[BPF_REG_9] = 7,  /* R15 callee saved */
	[BPF_REG_FP] = 5, /* RBP readonly */
	[BPF_REG_AX] = 2, /* R10 temp register */
	// [AUX_REG] = 3,    /* R11 temp register */
	// [X86_REG_R9] = 1, /* R9 register, 6th function argument */
};

static u8 *emit_code(u8 *ptr, u32 bytes, unsigned int len)
{
	if (len == 1)
		*ptr = bytes;
	else if (len == 2)
		*(u16 *)ptr = bytes;
	else {
		*(u32 *)ptr = bytes;
		barrier();
	}
	return ptr + len;
}

#define EMIT(bytes, len) \
	do { prog = emit_code(prog, bytes, len); } while (0)

#define EMIT1(b1)		EMIT(b1, 1)
#define EMIT2(b1, b2)		EMIT((b1) + ((b2) << 8), 2)
#define EMIT3(b1, b2, b3)	EMIT((b1) + ((b2) << 8) + ((b3) << 16), 3)
#define EMIT4(b1, b2, b3, b4)   EMIT((b1) + ((b2) << 8) + ((b3) << 16) + ((b4) << 24), 4)

#define EMIT1_off32(b1, off) \
	do { EMIT1(b1); EMIT(off, 4); } while (0)
#define EMIT2_off32(b1, b2, off) \
	do { EMIT2(b1, b2); EMIT(off, 4); } while (0)
#define EMIT3_off32(b1, b2, b3, off) \
	do { EMIT3(b1, b2, b3); EMIT(off, 4); } while (0)
#define EMIT4_off32(b1, b2, b3, b4, off) \
	do { EMIT4(b1, b2, b3, b4); EMIT(off, 4); } while (0)

static bool is_simm32(s64 value)
{
	return value == (s64)(s32)value;
}

static int emit_patch(u8 **pprog, void *func, void *ip, u8 opcode)
{
	u8 *prog = *pprog;
	s64 offset;

	offset = func - (ip + X86_PATCH_SIZE);
	// if (!is_simm32(offset)) {
	// 	pr_err("Target call %p is out of range\n", func);
	// 	return -ERANGE;
	// }
	EMIT1_off32(opcode, offset);
	*pprog = prog;
	return 0;
}

static int emit_call(u8 **pprog, void *func, void *ip)
{
	return emit_patch(pprog, func, ip, 0xE8);
}

static int emit_jump(u8 **pprog, void *func, void *ip)
{
	return emit_patch(pprog, func, ip, 0xE9);
}

/* Encode 'dst_reg' register into x86-64 opcode 'byte' */
static u8 add_1reg(u8 byte, u32 dst_reg)
{
	return byte + reg2hex[dst_reg];
}

static void emit_mov_imm32(u8 **pprog, u32 dst_reg, const u32 imm32)
{
	u8 *prog = *pprog;

	EMIT1_off32(add_1reg(0xB8, dst_reg), imm32);

	*pprog = prog;
}

static void __fill_hole(void *area, unsigned int size)
{
	/* Fill whole space with INT3 instructions */
	memset(area, 0xcc, size);
}

/*
 * trampoline image:
 * 0: push %rdi                     // 1 byte
 * 1: mov ${index}, %rsi            // 5 bytes
 * 2: call ${fentry_tailcall}       // 5 bytes
 * 3: pop %rdi                      // 1 byte
 * 4: sub ${SUB_INSN_SIZE}, %rsp    // copied original sub insn, 7 bytes
 * 5: jmp ${orig_prog + 7}          // 5 bytes
 * 6: int3                          // 1 byte
 */

static void *bpf_tailcall_tramp_image = NULL;
#define BPF_TAILCALL_TRAMP_SIZE (1 + 5 + 5 + 1 + SUB_INSN_SIZE + 5 + 1)

static int
__alloc_tramp_image(void)
{
	bpf_tailcall_tramp_image = bpf_jit_alloc_exec_fn(PAGE_SIZE);
	if (unlikely(!bpf_tailcall_tramp_image)) {
		pr_err("[X] bpf_jit_alloc_exec failed\n");
		return -ENOMEM;
	}

	pr_info("[i] bpf_tailcall_tramp_image: %p\n", bpf_tailcall_tramp_image);

	// set_memory_rox((long)im->image, 1); // set exec later

	return 0;
}

static void
__free_tramp_image(void)
{
	if (bpf_tailcall_tramp_image)
		bpf_jit_free_exec_fn(bpf_tailcall_tramp_image);
}

static int
__construct_tramp_image(void *tailcall_prog,
						struct bpf_prog *fentry_prog, u32 index)
{
	u8 *prog = bpf_tailcall_tramp_image;
	u8 *fentry = (void *) fentry_prog->bpf_func;
	u8 *tailcall_entry;
	u8 *tailcall_back;
	int ret;

	tailcall_entry = tailcall_prog + X86_PATCH_SIZE;
	tailcall_back = tailcall_entry + SUB_INSN_SIZE;

	/* push %rdi */
	EMIT1(0x52);

	/* mov ${index}, %rsi */
	emit_mov_imm32(&prog, BPF_REG_2, index);

	/* call ${fentry_tailcall} */
	ret = emit_call(&prog, fentry, prog);
	if (unlikely(ret < 0)) {
		pr_err("[X] emit_call failed: %d\n", ret);
		return ret;
	}

	/* pop %rdi */
	EMIT1(0x5A); /* pop rdx */

	/* sub ${SUB_INSN_SIZE}, %rsp */
	memcpy(prog, tailcall_entry, SUB_INSN_SIZE);
	prog += SUB_INSN_SIZE;

	/* jmp ${orig_prog + 7} */
	ret = emit_jump(&prog, tailcall_back, prog);
	if (unlikely(ret < 0)) {
		pr_err("[X] emit_jump failed: %d\n", ret);
		return ret;
	}

	/* int3 */
	__fill_hole(prog, PAGE_SIZE - BPF_TAILCALL_TRAMP_SIZE);

	return 0;
}

static struct bpf_prog *prog = NULL;
static struct bpf_map *map = NULL;

static int __bpf_get_prog_by_id(u32 id)
{
	prog = bpf_prog_get_curr_or_next_fn(&id);
	return PTR_ERR_OR_ZERO(prog);
}

static int __bpf_get_map_by_id(u32 id)
{
	map = bpf_map_get_curr_or_next_fn(&id);
	return PTR_ERR_OR_ZERO(map);
}

static int __bpf_check_prog(void)
{
	if (!prog->jited) {
		pr_err("[X] bpf_prog is not jited\n");
		return -EINVAL;
	}

	if (prog->type != BPF_PROG_TYPE_KPROBE) {
		pr_err("[X] bpf_prog is not BPF_PROG_TYPE_KPROBE\n");
		return -EINVAL;
	}

	pr_info("[i] bpf_prog->bpf_func: %p\n", prog->bpf_func);
	pr_info("[i] bpf_prog->aux->jit_data: %p\n", prog->aux->jit_data);

	return 0;
}

static int __bpf_check_map(void)
{
	if (map->map_type != BPF_MAP_TYPE_PROG_ARRAY) {
		pr_err("[X] bpf_map is not BPF_MAP_TYPE_PROG_ARRAY\n");
		return -EINVAL;
	}

	return 0;
}

static int
__bpf_poke_tailcall(bool is_hack)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct bpf_array_aux *aux = array->aux;
	u8 *p, *pp = bpf_tailcall_tramp_image;
	u32 key = 0;
	void *ptr;
	int ret;

	mutex_lock(&aux->poke_mutex);

	ptr = array->ptrs + key;
	p = ptr + X86_PATCH_SIZE;
	if (is_hack)
		ret = bpf_arch_text_poke_fn(p, BPF_MOD_JUMP, NULL, pp);
	else
		ret = bpf_arch_text_poke_fn(p, BPF_MOD_CALL, pp, NULL);

	mutex_unlock(&aux->poke_mutex);

	return ret;
}

static int
__bpf_hack_tailcall_trace(void)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *ptr = array->ptrs + 0;
	int ret;

	ret = __alloc_tramp_image();
	if (unlikely(ret)) {
		pr_err("[X] __alloc_tramp_image failed: %d\n", ret);
		return ret;
	}

	ret = __construct_tramp_image(ptr, prog, 0);
	if (unlikely(ret)) {
		pr_err("[X] __construct_tramp_image failed: %d\n", ret);
		return ret;
	}

	ret = set_memory_rox_fn((unsigned long) bpf_tailcall_tramp_image, 1); // set exec now
	if (unlikely(ret)) {
		pr_err("[X] set_memory_rox failed: %d\n", ret);
		return ret;
	}

	ret = __bpf_poke_tailcall(true);
	if (unlikely(ret)) {
		pr_err("[X] __bpf_poke_tailcall failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void
__bpf_unhack_tailcall_trace(void)
{
	int ret = __bpf_poke_tailcall(false);
	if (unlikely(ret))
		pr_err("[X] __bpf_poke_tailcall failed: %d\n", ret);
}

static int __init tailcall_trace_init(void)
{
	int ret;

	ret = __bpf_get_funcs();
	if (unlikely(ret)) {
		pr_err("[X] __bpf_get_funcs failed: %d\n", ret);
		return ret;
	}

	pr_info("[i] bpf_prog_id: %d, bpf_map_id: %d\n", bpf_prog_id, bpf_map_id);

	ret = __bpf_get_prog_by_id((u32)bpf_prog_id);
	if (unlikely(ret)) {
		pr_err("[X] bpf_prog_get_curr_or_next failed: %d\n", ret);
		return ret;
	}

	ret = __bpf_get_map_by_id((u32)bpf_map_id);
	if (unlikely(ret)) {
		pr_err("[X] bpf_map_get_curr_or_next failed: %d\n", ret);
		goto err_out;
	}

	if (__bpf_check_prog() || __bpf_check_map()) {
		ret = -EINVAL;
		pr_err("[X] bpf_check failed\n");
		goto err_out;
	}

	ret = __bpf_hack_tailcall_trace();
	if (unlikely(ret)) {
		pr_err("[X] __bpf_hack_tailcall_trace failed: %d\n", ret);
		goto err_out;
	}

	pr_info("[+] bpf_prog: %p, bpf_map: %p\n", prog, map);

	return 0;

err_out:
	if (prog)
		bpf_prog_put(prog);
	if (map)
		bpf_map_put(map);

	return ret;
}

static void __exit tailcall_trace_exit(void)
{
	__bpf_unhack_tailcall_trace();

	__free_tramp_image();

	pr_info("[-] bpf_prog: %p, bpf_map: %p\n", prog, map);
	bpf_prog_put(prog);
	bpf_map_put(map);
}

module_init(tailcall_trace_init);
module_exit(tailcall_trace_exit);
