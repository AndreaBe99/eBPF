
#ifndef _HIKE_VM_H
#define _HIKE_VM_H

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* compiler and low level machinery */

#ifndef ___constant_swab16
#define ___constant_swab16(x) ((__u16)(		\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |	\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#endif

#ifndef ___constant_swab32
#define ___constant_swab32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |	\
	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |	\
	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |	\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))
#endif

#ifndef ___constant_swab64
#define ___constant_swab64(x) ((__u64)(				\
	(((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |	\
	(((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |	\
	(((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |	\
	(((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |	\
	(((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |	\
	(((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |	\
	(((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |	\
	(((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define __hike_cpu_to_be16(x)	((__u16)(__be16)(x))
#define __hike_cpu_to_be32(x)	((__u32)(__be32)(x))
#define __hike_cpu_to_be64(x)	((__u64)(__be64)(x))

#define __hike_cpu_to_le16(x)	___constant_swab16(x)
#define __hike_cpu_to_le32(x)	___constant_swab32(x)
#define __hike_cpu_to_le64(x)	___constant_swab64(x)

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define __hike_cpu_to_be16(x)	___constant_swab16(x)
#define __hike_cpu_to_be32(x)	___constant_swab32(x)
#define __hike_cpu_to_be64(x)	___constant_swab64(x)

#define __hike_cpu_to_le16(x)	((__u16)(__le16)(x))
#define __hike_cpu_to_le32(x)	((__u32)(__le32)(x))
#define __hike_cpu_to_le64(x)	((__u64)(__le64)(x))

#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define cpu_to_be16(x)	__hike_cpu_to_be16(x)
#define cpu_to_be32(x)	__hike_cpu_to_be32(x)
#define cpu_to_be64(x)	__hike_cpu_to_be64(x)

#define cpu_to_le16(x)	__hike_cpu_to_le16(x)
#define cpu_to_le32(x)	__hike_cpu_to_le32(x)
#define cpu_to_le64(x)	__hike_cpu_to_le64(x)

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#ifndef bpf_htonll
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htonll(x) (x)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
__be64 __always_inline bpf_htonll(__u64 val)
{
	__be64 low, hi;
	__be64 ret;

	hi = ((__be64)bpf_htonl((__u32)(val & 0xffffffff))) << (32ul);
	low = bpf_htonl((__be32)(val >> (32ul)));

	ret = hi | low;
	return ret;
}
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#endif

#ifndef bpf_printk
#define bpf_printk(fmt, ...)						\
({									\
	char ____fmt[] = fmt;						\
	bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);	\
})
#endif

#ifndef __stringify
#define __stringify(X)		#X
#endif

#ifndef __section
#define __section(NAME)							\
	__attribute__((section(NAME), used))
#endif

/* TODO: to be remove when passing to libbpf loader */
#ifndef __section_tail
#define __section_tail(ID, KEY)						\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef barrier
#define barrier()	__asm__ __volatile__("": : :"memory")
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

/* we define the same structure used by ip/tc which differs * from the one
 * used by libppf.
 */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};

/* PIN ID for iproute2 (persistence of maps) */
#ifndef PIN_GEN_NS
#define PIN_GEN_NS			4
#endif

/* ID of the map used for storing the generic ebpf programs */
#ifndef GEN_PROG_MAP_ID
#define GEN_PROG_MAP_ID			1
#endif

/* the total number of different programs that can be used */
#define GEN_PROG_TABLE_SIZE		256

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#ifndef HIKE_DEBUG
#define HIKE_DEBUG 0
#endif

#if HIKE_DEBUG == 1
#define DEBUG_PRINT(...)					\
do{								\
		bpf_printk(__VA_ARGS__);			\
} while (0)
#else
#define DEBUG_PRINT(...) do {} while (0)
#endif

/* jmp table for hosting all the HIKe programs */
struct bpf_elf_map SEC("maps") gen_jmp_table = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= GEN_PROG_MAP_ID,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GEN_NS,
	.max_elem	= GEN_PROG_TABLE_SIZE,
};

/* New ID specs:
 * an elem_ID (uprog ID/chain ID) is structured as follows:
 *
 *	k2 k1 k0 m5 m4 m3 m2 m1 m0
 *
 *  - A valid UPROG ID MUST set to 0 every k_j bits j in [0..2].
 *    Therefore, we can have a total of 2^6 possibile UPROG IDs, i.e.:
 *
 *		b000 000110 = 0x06 is a valid UPROG ID;
 *		b011 000110 = 0x36 is NOT a valid UPROG ID;
 *
 *  - A valid CHAIN ID MUST set at least one of the k2 k1 k0 bits to 1.
 *    No restrictions for m5, m4, ..., m0 for a CHAIN ID.
 *
 *	b001 001010 = 0x4a is a valid CHAIN ID;
 *	b000 001010 = 0x0a is NOT a valid CHAIN ID.
 */
#define UPROG_MASK_BITS		6
#define CHAIN_MASK_BITS		9

/* XXX: note those values depend on the UPROG_MASK_BITS and CHAIN_MASK_BITS */
#define CHAIN_DEFAULT_ID	0x7defc1c0

typedef __u8	bool;
#define true	((__u8)1)
#define false	((__u8)0)

#ifndef BIT
#define BIT(x)							\
	((__u32)(((__u32)1) << ((__u32)(x))))
#endif

/* XXX: for better performance these masks should be PRECOMPILED ... */
#define ELEM_ID_GEN_MASK_U32(__nbits)				\
		((__u32)(BIT(__nbits) - ((__u32)1)))

#define UPROG_MASK	ELEM_ID_GEN_MASK_U32(UPROG_MASK_BITS)
#define CHAIN_MASK	ELEM_ID_GEN_MASK_U32(CHAIN_MASK_BITS)

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/* Structure of an hike_insn
 *
 * ~~~~~~~~~~~~~~~
 *  opcode layout
 * ~~~~~~~~~~~~~~~
 * Last 3 bits of the opcode field identify the "instruction class".
 *
 * ALU/ALU64/JMP opcode structure:
 * MSB      LSB
 * +----+-+---+
 * |op  |s|cls|
 * +----+-+---+
 *
 * if the s bit is zero, then the source operand is imm. If s is one, then the
 * source operand is src. The op field specifies which ALU or branch operation
 * is to be performed.
 *
 * MSB									    LSB
 * +--------------+-----------------+------------+------------+---------------+
 * | imm (32 bit) | offset (16 bit) | src (4bit) | dst (4bit) | opcode (8bit) |
 * +--------------+-----------------+------------+------------+---------------+
 *
 *
 *  extended instruction only for JUMP_TAIL_CALL to HIKe program/chain
 *
 * MSB									    LSB
 * +--------------------------------+-------------------------+---------------+
 * |           arg (32 bit)         |      id (24 bit)        | opcode (8bit) |
 * +--------------------------------+-------------------------+---------------+
 *
 * dst and src are index of registers:
 *	A = 0x0
 *	B = 0x1
 *	W = 0x2
 *
 * Opcode examples:
 *
 *  Mnemonic			 opcode      | Pseudocode
 *  tail_call id, arg		 opcode 0xf5 | tail_call id:arg
 *  jeq  dst, imm, +off		 opcode 0x15 | PC += off, if dst == imm
 *
 */

struct hike_insn_core {
	__u8	code;
	__u8	dst_reg:	4;
	__u8	src_reg:	4;
	__s16	off;
};

struct hike_insn_ext_core {
	__u32	code:		8;
	__u32	off:		24;
};

struct hike_insn {
	union {
		struct hike_insn_core c;
		struct hike_insn_ext_core ec;
	} u;
#define hic_code	u.c.code
#define hic_dst		u.c.dst_reg
#define hic_src		u.c.src_reg
#define hic_off		u.c.off

#define hiec_code	u.ec.code
#define hiec_off	u.ec.off

	__s32 imm;
};

enum {
	/* program/chain return value */
	HIKE_REG_0 = 0,
	/* program/chain arguments */
	HIKE_REG_1,
	HIKE_REG_2,
	HIKE_REG_3,
	HIKE_REG_4,
	HIKE_REG_5,
	/* non volatile registers */
	HIKE_REG_6,
	HIKE_REG_7,
	HIKE_REG_8,
	HIKE_REG_9,
	/* frame pointer */
	HIKE_REG_10,
	HIKE_REG_FP = HIKE_REG_10, /* alias */

	__HIKE_REG_MAX,
};

#define HIKE_REG_MAX (__HIKE_REG_MAX - 1)


/* instruction classes */
#define HIKE_CLASS(code)		((code) & 0x07)
#define	HIKE_LD				0x00 /* load immediate */
#define HIKE_LDX			0x01 /* dst = *(type)(src_reg + off) */
#define	HIKE_ST				0x02 /* like STX but with 32-bit imm */
#define HIKE_STX			0x03 /* *(type *)(dst + off) = src */
#define	HIKE_ALU			0x04 /* ALU mode in 32 bit */
#define	HIKE_JMP64			0x05 /* 64 bit between DST imm32/SRC */
#define HIKE_ALU64			0x07 /* ALU mode in 64 bit */

/* operations */
#define HIKE_OP(code)			((code) & 0xf0)
/* jmp fields */
#define HIKE_JA				0x00
#define	HIKE_JEQ			0x10	/* == */
#define	HIKE_JGT			0x20	/* >  */
#define	HIKE_JGE			0x30	/* >= */
#define	HIKE_JNE			0x50	/* != */
#define HIKE_JLT			0xa0	/* <  */
#define HIKE_JLE			0xb0	/* <= */
#define HIKE_CALL			0x80
#define HIKE_TAIL_CALL			0xf0	/* XXX: deprecated; not used */
#define HIKE_EXIT			0x90

/* alu fields */
#define HIKE_ADD			0x00
#define HIKE_AND			0x50
#define HIKE_MOV			0xb0

/* source modifiers */
#define HIKE_SRC(code)			((code) & 0x08)
#define HIKE_K				0x00
#define	HIKE_X				0x08

/* change endianess of a register */
#define HIKE_END			0xd0
#define HIKE_TO_LE			0x00	/* convert to little-endian */
#define HIKE_TO_BE			0x08	/* convert to big-endian */
#define HIKE_FROM_LE			HIKE_TO_LE
#define HIKE_FROM_BE			HIKE_TO_BE

/* access mode */
#define HIKE_MODE(code)			((code) & 0xe0)
#define	HIKE_IMM			0x00
#define	HIKE_MEM			0x60

#define		HIKE_SIZE(code)		((code) & 0x18)
#define		HIKE_DW			0x18 /* 64-bit */
#define		HIKE_W			0x00 /* 32-bit */
#define		HIKE_H			0x08 /* 16-bit */
#define		HIKE_B			0x10 /*  8-bit */

/* raw helper macros to set the hike_insn structure */
#define HIKE_RAW_INSN(CODE, DST, SRC, OFF, IMM)				\
	((struct hike_insn) {						\
		.u = {							\
			.c = {						\
				.code = CODE,				\
				.dst_reg = DST,				\
				.src_reg = SRC,				\
				.off = OFF,				\
			}						\
		},							\
		.imm = IMM,						\
	})

#define HIKE_RAW_EXT_INSN(CODE, OFF, IMM)				\
	((struct hike_insn) {						\
		.u = {							\
			.ec = {						\
				.code = CODE,				\
				.off = OFF,				\
			}						\
		},							\
		.imm = IMM,						\
	})

#define HIKE_LD64_IMM_RAW_INSN(DST, SRC, IMM)				\
	HIKE_RAW_INSN(HIKE_LD | HIKE_MODE(HIKE_IMM) | HIKE_DW,		\
		      DST, SRC, 0, ((__u32)(IMM))),			\
	HIKE_RAW_INSN(0, /* reserved code */				\
		      0, 0, 0, ((__u64)(IMM)) >> 32)			\

/* helper macros for defining instructions */
#define HIKE_JMP64_IMM_INSN(OP, DST, OFF, IMM)				\
	HIKE_RAW_INSN(HIKE_JMP64 | HIKE_OP(OP) | HIKE_K, DST,		\
		      0, OFF, IMM)

#define HIKE_JEQ64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_JMP64_IMM_INSN(HIKE_JEQ, DST, OFF, IMM)

#define HIKE_JNE64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_JMP64_IMM_INSN(HIKE_JNE, DST, OFF, IMM)

#define HIKE_JGT64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_JMP64_IMM_INSN(HIKE_JGT, DST, OFF, IMM)

#define HIKE_JGE64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_JMP64_IMM_INSN(HIKE_JGE, DST, OFF, IMM)

#define HIKE_JLT64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_JMP64_IMM_INSN(HIKE_JLT, DST, OFF, IMM)

#define HIKE_JLE64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_JMP64_IMM_INSN(HIKE_JLE, DST, OFF, IMM)

#define HIKE_JNE64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_JMP64_IMM_INSN(HIKE_JNE, DST, OFF, IMM)

#define HIKE_JA64_IMM_INSN(OFF)						\
	HIKE_JMP64_IMM_INSN(HIKE_JA, 0, OFF, 0)

#define HIKE_ALU64_IMM_INSN(OP, DST, IMM)				\
	HIKE_RAW_INSN(HIKE_ALU64 | HIKE_OP(OP) | HIKE_K, DST,		\
		      0, 0, IMM)					\

#define HIKE_ADDS64_IMM_INSN(DST, IMM)					\
	HIKE_ALU64_IMM_INSN(HIKE_ADD, DST, IMM)

#define HIKE_AND64_IMM_INSN(DST, IMM)					\
	HIKE_ALU64_IMM_INSN(HIKE_ADD, DST, IMM)

#define HIKE_MOV64_IMM_INSN(DST, IMM)					\
	HIKE_ALU64_IMM_INSN(HIKE_MOV, DST, IMM)

#define HIKE_ALU64_REG_INSN(OP, DST, SRC)				\
	HIKE_RAW_INSN(HIKE_ALU64 | HIKE_OP(OP) | HIKE_X, DST,		\
		      SRC, 0, 0)

#define HIKE_MOV64_REG_INSN(DST, SRC)					\
	HIKE_ALU64_REG_INSN(HIKE_MOV, DST, SRC)

#define HIKE_TAIL_CALL_ELEM_INSN(OFF, IMM)				\
	HIKE_RAW_EXT_INSN(HIKE_JMP64 | HIKE_OP(HIKE_TAIL_CALL),		\
			  OFF, IMM)					\

#define HIKE_ENDSS_RAW_INSN(END, DST, IMM)				\
	HIKE_RAW_INSN(HIKE_ALU | HIKE_OP(HIKE_END) | HIKE_TO_##END,	\
				  DST, 0, 0, IMM)

#define HIKE_BE_RAW_INSN(DST, IMM)					\
	HIKE_ENDSS_RAW_INSN(BE, DST, IMM)

#define HIKE_BE16_INSN(DST)	HIKE_BE_RAW_INSN(DST, 16)
#define HIKE_BE32_INSN(DST)	HIKE_BE_RAW_INSN(DST, 32)
#define HIKE_BE64_INSN(DST)	HIKE_BE_RAW_INSN(DST, 64)

#define HIKE_LE_RAW_INSN(DST, IMM)					\
	HIKE_ENDSS_RAW_INSN(LE, DST, IMM)

#define HIKE_LE16_INSN(DST)	HIKE_LE_RAW_INSN(DST, 16)
#define HIKE_LE32_INSN(DST)	HIKE_LE_RAW_INSN(DST, 32)
#define HIKE_LE64_INSN(DST)	HIKE_LE_RAW_INSN(DST, 64)

#define HIKE_EXIT_INSN()						\
	HIKE_RAW_INSN(HIKE_JMP64 | HIKE_EXIT, 0, 0, 0, 0)

#define HIKE_RAW_CALL_INSN(IMM)						\
	HIKE_RAW_INSN(HIKE_JMP64 | HIKE_OP(HIKE_CALL),			\
		      0, 0, 0, IMM)

#define HIKE_CALL_ELEM_NARGS_2_INSN()					\
	HIKE_RAW_CALL_INSN(HIKE_HPFUNC_ADDR(__HIKE_HPFUNC_CALL_ELEM_NARGS_2_ID))

/* encode single load 64-bit immediate in two instructions */
#define HIKE_LD64_IMM_INSN(DST, IMM)					\
	HIKE_LD64_IMM_RAW_INSN(DST, 0, IMM)

#define HIKE_LD_RAW_REG_INSN(SIZE, DST, SRC, OFF)			\
	HIKE_RAW_INSN(HIKE_LDX | HIKE_SIZE(SIZE) | HIKE_MEM,		\
		      DST, SRC, OFF, 0)

/* dst = *((u8 *)(src + off)) */
#define HIKE_LD8_REG_INSN(DST, SRC, OFF)				\
	HIKE_LD_RAW_REG_INSN(HIKE_B, DST, SRC, OFF)

/* 16 bit */
#define HIKE_LD16_REG_INSN(DST, SRC, OFF)				\
	HIKE_LD_RAW_REG_INSN(HIKE_H, DST, SRC, OFF)

/* 32 bit */
#define HIKE_LD32_REG_INSN(DST, SRC, OFF)				\
	HIKE_LD_RAW_REG_INSN(HIKE_W, DST, SRC, OFF)

/* 64 bit */
#define HIKE_LD64_REG_INSN(DST, SRC, OFF)				\
	HIKE_LD_RAW_REG_INSN(HIKE_DW, DST, SRC, OFF)

#define HIKE_ST_RAW_INSN(CLASS, SIZE, DST, SRC, OFF, IMM)		\
	HIKE_RAW_INSN(HIKE_CLASS(CLASS) | HIKE_SIZE(SIZE) | HIKE_MEM,	\
				  DST, SRC, OFF, IMM)

#define HIKE_ST_RAW_REG_INSN(SIZE, DST, SRC, OFF)			\
	HIKE_ST_RAW_INSN(HIKE_STX, SIZE, DST, SRC, OFF, 0)

/* *(u8 *)(dst + off) = src */
#define HIKE_ST8_REG_INSN(DST, SRC, OFF)				\
	HIKE_ST_RAW_REG_INSN(HIKE_B, DST, SRC, OFF)

/* *(u16 *)(dst + off) = src */
#define HIKE_ST16_REG_INSN(DST, SRC, OFF)				\
	HIKE_ST_RAW_REG_INSN(HIKE_H, DST, SRC, OFF)

/* *(u32 *)(dst + off) = src */
#define HIKE_ST32_REG_INSN(DST, SRC, OFF)				\
	HIKE_ST_RAW_REG_INSN(HIKE_W, DST, SRC, OFF)

/* *(u64 *)(dst + off) = src */
#define HIKE_ST64_REG_INSN(DST, SRC, OFF)				\
	HIKE_ST_RAW_REG_INSN(HIKE_DW, DST, SRC, OFF)

#define HIKE_ST_RAW_IMM_INSN(SIZE, DST, OFF, IMM)			\
	HIKE_ST_RAW_INSN(HIKE_ST, SIZE, DST, 0, OFF, IMM)

/* *(u8 *)(dst + off) = imm32 */
#define HIKE_ST8_IMM_INSN(DST, OFF, IMM)				\
	HIKE_ST_RAW_IMM_INSN(HIKE_B, DST, OFF, IMM)

/* *(u16 *)(dst + off) = imm32 */
#define HIKE_ST16_IMM_INSN(DST, OFF, IMM)				\
	HIKE_ST_RAW_IMM_INSN(HIKE_H, DST, OFF, IMM)

/* *(u32 *)(dst + off) = imm32 */
#define HIKE_ST32_IMM_INSN(DST, OFF, IMM)				\
	HIKE_ST_RAW_IMM_INSN(HIKE_W, DST, OFF, IMM)

/* *(u64 *)(dst + off) = imm32 */
#define HIKE_ST64_IMM_INSN(DST, OFF, IMM)				\
	HIKE_ST_RAW_IMM_INSN(HIKE_DW, DST, OFF, IMM)

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/* MUST BE POWER OF 2 */
#define HIKE_CHAIN_REGMEM_STACK_SIZE	128

struct hike_chain_regmem {
	union {
		struct  {
			/* users must access to registers using their names */
			__u64	reg_0;		/* A register */
			__u64	reg_1;		/* B register */
			__u64	reg_2;		/* old W register */
			__u64	reg_3;
			__u64	reg_4;
			__u64	reg_5;
			__u64	reg_6;
			__u64	reg_7;
			__u64	reg_8;
			__u64	reg_9;
			__u64	reg_10;		/* fp register */
#define	reg_fp	reg_10				/* alias for reg_10 */
		};
		__u64 reg_n[HIKE_REG_MAX + 1];
	};

	/* padding here takes into account the 8 bytes of chain_id, ninsn and
	 * upc in the hike_chain.
	 */
	__u64 __pad[15 - HIKE_REG_MAX - 1];

	__u8 stack[HIKE_CHAIN_REGMEM_STACK_SIZE];
};

#define ACCESS_REGMEM(regmem, X)	(regmem)->reg_##X
#define ACCESS_REF_REGMEM(regmem, X)    (&ACCESS_REGMEM(regmem, X))

#define __ACCESS_REGMEM_N(regmem, N)	(regmem)->reg_n[N]

#define __ACCESS_REGMEM_STACK(regmem)	((void *)&(regmem)->stack[0])

/* number of HIKe VM instructions contained in a single HIKe chain */
#define HIKE_CHAIN_NINSN_MAX			32

struct hike_chain {
	__s32 chain_id;
	__u16 ninsn;
	__u16 upc;

	/* registers and private memory for an HIKe Microprogram/Chain */
	struct hike_chain_regmem regmem;

	/* TODO: This is only TEMPORARY: indeed, the insns should be moved into
	 * another table/map.
	 */
	struct hike_insn insns[HIKE_CHAIN_NINSN_MAX];
};

#define ACCESS_HIKE_CHAIN_REG(chain, X)	ACCESS_REGMEM(&(chain)->regmem, X)
#define __UNSAFE_ACCESS_HIKE_CHAIN_REG_N(chain, N)			\
	__ACCESS_REGMEM_N(&(chain)->regmem, N)

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/* total number of instructions that can be processed in a chain. Note
 * This value is NOT related to the total number of instructions per chain.
 */
#define HIKE_CHAIN_EXEC_NINSN_MAX		64

/* it *MUST* be a power of 2 */
#define HIKE_CHAIN_STACK_DEPTH_MAX		8

struct hike_chain_data {
	__u16 active_chain;
	__u16 __pad0[3];
	__u64 __pad1;
	/* chains starts at +16 using padding defined above */
	struct hike_chain chains[HIKE_CHAIN_STACK_DEPTH_MAX];
};

struct hike_chain_done_insn_bottom {
	__u8 opcode;
	__u32 prog_id;
	__u32 arg;
};

enum hike_xdp_action {
	HIKE_XDP_ABORTED	= XDP_ABORTED,
	HIKE_XDP_DROP		= XDP_DROP,
	HIKE_XDP_PASS		= XDP_PASS,
	HIKE_XDP_TX		= XDP_TX,
	HIKE_XDP_REDIRECT	= XDP_REDIRECT,

	/* hike_extension */
	HIKE_XDP_VM = HIKE_XDP_REDIRECT + 0x64,
};

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/* HIKe VM memory management
 *
 * FIXME: to update with the new virtual address memory layout
 *
 * The HIKe VM allows the user to access different memory "banks".
 * Such "banks" are accessed through virtual addresses which have to be
 * always translated by the simple HIKe VM MMU.
 *
 * Each memory "bank" can address up to 2^16 bytes.
 * The total number of possibly banks is 2^8.
 *
 * Therefore, a virtual HIKe Memmory address is defined as follows:
 *
 * MSB							 LSB
 * +----------------------+--------------------------------+
 * |    bank id (8 bit)   |          offset (24 bit)       |
 * +----------------------+--------------------------------+
 *
 * Due to the very simple HIKe VM Memory Management design, no additional
 * data is used to encode a virtual HIKe Memory address (from now on we will
 * refer to it only as "virtual address").
 * Therefore, any virtual address is stored within a 32 bit data type.
 *
 */

/* vaddr_info can be encoded within 32 bits */
struct vaddr_info {
	__u32 off	:24;		/* little endian LSB */
	__u32 bank_id	:8;		/* little endian MSB */
};

#define HIKE_MEM_BID_ZERO		0x00 /* reserved */
#define HIKE_MEM_BID_PACKET		0x01
#define HIKE_MEM_BID_PRIVATE		0x02
#define HIKE_MEM_BID_SHARED		0x03
#define HIKE_MEM_BID_STACK		0x04 /* per chain reserved stack */

#define HIKE_MEM_BANK_PACKET_DATA_SIZE	0x3fff /* off in packet 16KB */
struct hike_mem_packet_layout {
	__u64 len;
	__u8  data[0];
};

#define HIKE_MEM_BANK_STACK_DATA_SIZE	(HIKE_CHAIN_REGMEM_STACK_SIZE)
struct hike_chain_stack_layout {
	__u8 data[0];
};

#define __to_u64(v)	((__u64)(v))
#define __to_u32(v)	((__u32)(v))

#define PTR_VADDR_TO_U32(vainfo)					\
	__to_u32(*((__u64 *)((struct vaddr_info *)(vainfo))))

#define	PTR_U32_TO_PTR_VADDR(vainfo)					\
	((struct vaddr_info *)((__u32 *)(vainfo)))

#define	PTR_U32_TO_VADDR(vainfo)					\
	(*(PTR_U32_TO_PTR_VADDR(vainfo)))

#define HIKE_MEM_BANK_RAW_FULL(BID, LAYOUT, MEMBER, OFF)		\
	((struct vaddr_info) {						\
		.bank_id = BID,						\
		.off = offsetof(LAYOUT, MEMBER) + OFF,  		\
	})

#define HIKE_MEM_BANK_RAW(BID, LAYOUT, MEMBER) 				\
	HIKE_MEM_BANK_RAW_FULL(BID, LAYOUT, MEMBER, 0)

#define HIKE_MEM_RAW_ADDR(vainfo)					\
({									\
	struct vaddr_info __tmp = vainfo;				\
	__u32 __ret = PTR_VADDR_TO_U32(&__tmp);				\
									\
	__ret;								\
})

#define HIKE_MEM_RAW_ADJUST_OFF(VAL, LAYOUT, MEMBER)			\
	((VAL) - offsetof(LAYOUT, MEMBER))

/* hike packet */
#define HIKE_MEM_BANK_PACKET_LEN					\
	HIKE_MEM_BANK_RAW(HIKE_MEM_BID_PACKET,				\
			  struct hike_mem_packet_layout, len)

#define HIKE_MEM_BANK_PACKET_DATA					\
	HIKE_MEM_BANK_RAW(HIKE_MEM_BID_PACKET,				\
			  struct hike_mem_packet_layout, data)

#define HIKE_MEM_BANK_PACKET_ADJUST_OFF(VAL, MEMBER)			\
	HIKE_MEM_RAW_ADJUST_OFF(VAL, struct hike_mem_packet_layout,	\
				MEMBER)

#define HIKE_MEM_PACKET_OFF_LEN						\
	offsetof(struct hike_mem_packet_layout, len)

#define HIKE_MEM_PACKET_OFF_DATA_START					\
	offsetof(struct hike_mem_packet_layout, data)

#define HIKE_MEM_PACKET_ADDR_LEN					\
	HIKE_MEM_RAW_ADDR(HIKE_MEM_BANK_PACKET_LEN)

#define HIKE_MEM_PACKET_ADDR_DATA					\
	HIKE_MEM_RAW_ADDR(HIKE_MEM_BANK_PACKET_DATA)

/* hike chain stack */
#define HIKE_MEM_CHAIN_STACK_DATA_END					\
	HIKE_MEM_RAW_ADDR(						\
	   HIKE_MEM_BANK_RAW_FULL(HIKE_MEM_BID_STACK,			\
				  struct hike_chain_stack_layout, 	\
				  data,	HIKE_MEM_BANK_STACK_DATA_SIZE)	\
	)

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define HIKE_HPFUNC_SHIFT				8

#define HIKE_HPFUNC_ADDR(HPFUNC_ID)					\
	__to_u32((__to_u32(HPFUNC_ID) << __to_u32(HIKE_HPFUNC_SHIFT)))

#define HIKE_HPFUNC_ID(HPFUNC_ADDR)					\
	__to_u32((__to_u32(HPFUNC_ADDR) >> __to_u32(HIKE_HPFUNC_SHIFT)))


#define __HIKE_ELEM_CALL_NARGS_MAX			5

/* XXX: HELPER FUNCTION IDs MUST be 16 bits long */

#define __HIKE_HPFUNC_CALL_ELEM_NARGS_1_ID		0x11
static int (* hike_elem_call_1) (__u32 id) =
	(void *)HIKE_HPFUNC_ADDR(__HIKE_HPFUNC_CALL_ELEM_NARGS_1_ID);

#define __HIKE_HPFUNC_CALL_ELEM_NARGS_2_ID		0x12
static int (* hike_elem_call_2) (__u32 id, __u64 arg1) =
	(void *)HIKE_HPFUNC_ADDR(__HIKE_HPFUNC_CALL_ELEM_NARGS_2_ID);

#define __HIKE_HPFUNC_CALL_ELEM_NARGS_3_ID		0x13
static int (* hike_elem_call_3) (__u32 id,__u64 arg1, __u64 arg2) =
	(void *)HIKE_HPFUNC_ADDR(__HIKE_HPFUNC_CALL_ELEM_NARGS_3_ID);

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ MAP DEFINITIONS ~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/* HIKe VM execution context */
struct bpf_elf_map SEC("maps") pcpu_hike_chain_data_map = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct hike_chain_data),
	/* avoid the map to be overwitten when other progs are loaded */
	.pinning	= PIN_GEN_NS,
	.max_elem	= 1,
};

/* HIKe Chain Map which contains all the local HIKe chains in the node */
#define HIKE_CHAIN_MAP_NELEM_MAX	128

struct bpf_elf_map SEC("maps") hike_chain_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct hike_chain),
	.pinning	= PIN_GEN_NS,
	.max_elem	= HIKE_CHAIN_MAP_NELEM_MAX,
};

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

static __always_inline int
__hike_chain_store_reg(struct hike_chain *cur_chain, __s32 index,
		       const __u64 *val)
{
	barrier();
	if (index > HIKE_REG_MAX)
		return -EINVAL;

	__UNSAFE_ACCESS_HIKE_CHAIN_REG_N(cur_chain, index) = *val;
	barrier();

	return 0;
}

static __always_inline int
__hike_chain_load_reg(struct hike_chain *cur_chain, __s32 index,
		      __u64 *const val)
{
	barrier();
	if (index > HIKE_REG_MAX)
		return -EINVAL;

	*val = __UNSAFE_ACCESS_HIKE_CHAIN_REG_N(cur_chain, index);
	barrier();

	return 0;
}

static __always_inline int
__hike_chain_ref_reg(struct hike_chain *cur_chain, __s32 index, __u64 ** reg)
{
	barrier();
	if (index > HIKE_REG_MAX)
		return -EINVAL;

	*reg = &__UNSAFE_ACCESS_HIKE_CHAIN_REG_N(cur_chain, index);
	barrier();

	return 0;
}

static __always_inline struct hike_chain *hike_chain_lookup(const __s32 *id)
{
	struct hike_chain *hc;

	if (unlikely(*id < 0 || *id >= HIKE_CHAIN_MAP_NELEM_MAX))
		return NULL;

	hc = bpf_map_lookup_elem(&hike_chain_map, id);
	if (unlikely(!hc))
		return NULL;

	return hc;
}

static __always_inline struct hike_chain_data *get_hike_chain_data()
{
	struct hike_chain_data *hcd;
	const __u32 id = 0;

	hcd = bpf_map_lookup_elem(&pcpu_hike_chain_data_map, &id);
	if (unlikely(!hcd))
		return NULL;

	return hcd;
}

static __always_inline struct hike_chain
*__hike_get_active_chain(struct hike_chain_data *chain_data)
{
	struct hike_chain *active_chain;
	__u16 ac_index;

	/* optimizer does its own wizardry here... let's do in this way to
	 * make the verifier happy...
	 */
	barrier();

	ac_index = chain_data->active_chain;
	if (unlikely(ac_index >= HIKE_CHAIN_STACK_DEPTH_MAX))
		return NULL;

	barrier();

	active_chain = &chain_data->chains[ac_index];
	if (unlikely(!active_chain))
		return NULL;

	return active_chain;
}

static __always_inline void
__hike_copy_chain(struct hike_chain *const dst, const struct hike_chain *src)
{
	union __u {
		struct hike_insn insns[HIKE_CHAIN_NINSN_MAX];
		/* each hike_insns is 64 bit long */
		__u64 raw_insns[HIKE_CHAIN_NINSN_MAX];
	};
	const struct hike_insn *src_insns = &src->insns[0];
	struct hike_insn *dst_insns = &dst->insns[0];
	const union __u *s = (void *)src_insns;
	union __u *d = (void *)dst_insns;

	/* copy the head of chain */
	dst->chain_id = src->chain_id;
	dst->ninsn = src->ninsn;
	/* TODO: make a smart copy which copies only non-zero instructions */
	dst->upc = src->upc;

	/* memcpy is not very efficient here; it emits 8-bit move instructions
	 * rather than 64-bit ones. This trick forces the struct copy using
	 * 64-bit moves.
	 */
	*d = *s;
}

static __always_inline int
__hike_chain_upc_add(struct hike_chain *chain, __s16 off)
{
	__u16 *upc = &chain->upc;

	*upc += off;
	if (unlikely(*upc > chain->ninsn || *upc > HIKE_CHAIN_NINSN_MAX))
		return -ENOBUFS;

	barrier();

	return (int)(*upc & 0xffff);
}

static __always_inline int __hike_chain_upc_inc(struct hike_chain *chain)
{
	return __hike_chain_upc_add(chain, 1);
}

static __always_inline int
__hike_active_chain_up(struct hike_chain_data *chain_data)
{
	if (unlikely(chain_data->active_chain >= HIKE_CHAIN_STACK_DEPTH_MAX))
		/* no more room for a new "chain" */
		return -ENOBUFS;

	++chain_data->active_chain;

	return 0;
}

static __always_inline int
__hike_active_chain_down(struct hike_chain_data *chain_data)
{
	if (unlikely(chain_data->active_chain == 0))
		return -ENOBUFS;

	--chain_data->active_chain;

	return 0;
}

static __always_inline int __hike_push_chain(struct hike_chain_data *chain_data,
					     struct hike_chain *new_chain,
					     __u8 nargs)
{
	struct hike_chain *active_chain, *old_chain;
	__u64 reg_val;
	int rc, i;

	old_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!old_chain))
		return -ENOBUFS;

	/* Note: when a new chain R is pushed on top of the current S, we do not
	 * change the program counter of the S chain. It will be handled by the
	 * program which will schedule the execution of the next program/chain
	 * taking care of the S chain as soon as it will turn out to be the
	 * active one.
	 */

	DEBUG_PRINT("HIKe VM debug: active chain ID=0x%x (will no longer be active)",
		    old_chain->chain_id);

	rc = __hike_active_chain_up(chain_data);
	if (unlikely(rc < 0))
		return rc;

	/* now the hike_chain_data has a new top of the stack and we have to
	 * copy the new_chain on it.
	 */
	active_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!active_chain))
		return -ENOBUFS;

	/* XXX: copy the given chain into the per-cpu chain memory area; maybe
	 * inefficient but we keep it for the moment.
	 */
	__hike_copy_chain((struct hike_chain *const)active_chain,
			  (const struct hike_chain *)new_chain);

	/* make available registers r0, r1-r5 following eBPF calling conv */
	for (i = 0; i < __HIKE_ELEM_CALL_NARGS_MAX; ++i) {
		rc = __hike_chain_load_reg(old_chain, i, &reg_val);
		if (rc < 0)
			return rc;

		rc = __hike_chain_store_reg(active_chain, i, &reg_val);
		if (rc < 0)
			return rc;

		if (i >= nargs)
			break;
	}

	/* initialize the fp register; each chain has its own private stack */
	ACCESS_HIKE_CHAIN_REG(active_chain, fp) = HIKE_MEM_CHAIN_STACK_DATA_END;

	DEBUG_PRINT("HIKe VM debug: push chain ID=0x%x (active), passing nargs=%d + REG_0",
		    active_chain->chain_id, nargs);

	return 0;
}

static __always_inline bool hike_is_valid_elem_id(__s32 elem_id)
{
	return elem_id >= 0;
}

static __always_inline bool hike_is_valid_prog_id(__s32 uprog_id)
{
	if (!hike_is_valid_elem_id(uprog_id))
		return false;

	return !(((__u32)uprog_id) & (CHAIN_MASK & ~UPROG_MASK));
}

static __always_inline bool hike_is_valid_chain_id(__s32 chain_id)
{
	return !hike_is_valid_prog_id(chain_id);
}

static __always_inline
int __hike_chain_push_by_id(struct hike_chain_data *chain_data, __u32 chain_id,
			    __u8 nargs)
{
	struct hike_chain *new_chain;

	DEBUG_PRINT("HIKe VM debug: chain call for chain ID=0x%x, nargs=%d",
		    chain_id, nargs);

	new_chain = hike_chain_lookup(&chain_id);
	if (unlikely(!new_chain))
		return -ENOBUFS;

	return __hike_push_chain(chain_data, new_chain, nargs);
}

static __always_inline int __hike_pop_chain(struct hike_chain_data *chain_data)
{
	struct hike_chain *active_chain;
	__u64 last_retval;
	int rc;

	if (unlikely(chain_data->active_chain == 0))
		/* we cannot pop out the default loading chain */
		return -EINVAL;

	active_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!active_chain))
		return -ENOBUFS;

	last_retval = ACCESS_HIKE_CHAIN_REG(active_chain, 0);

	DEBUG_PRINT("HIKe VM debug: active chain ID=0x%x (will be popped out)",
		    active_chain->chain_id);

	rc = __hike_active_chain_down(chain_data);
	if (unlikely(rc < 0))
		return rc;

	active_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!active_chain))
		return -ENOBUFS;

	/* make available the last returned value of the previous chain.
	 *
	 * we avoid to copy back registers r1-r5 which SHOULD be saved by the
	 * caller chain caller. They are scratches registers and we do not need
	 * to rely on their value. We save a bunch of insns in this way.
	 */
	ACCESS_HIKE_CHAIN_REG(active_chain, 0) = last_retval;

	DEBUG_PRINT("HIKe VM debug: active chain ID=0x%x preserved REG_0=0x%llx",
		    active_chain->chain_id, last_retval);

	return 0;
}

static __always_inline struct
hike_insn *__hike_chain_hike_insn_at(struct hike_chain *hc, __u16 upc)
{
	struct hike_insn *insn;

	if (unlikely(upc >= hc->ninsn || upc >= HIKE_CHAIN_NINSN_MAX))
		return NULL;

	barrier();

	insn = &hc->insns[upc];
	if (!insn)
		return NULL;

	return insn;
}

static __always_inline struct
hike_insn *__hike_chain_cur_hike_insn(struct hike_chain *hc)
{
	return __hike_chain_hike_insn_at(hc, hc->upc);
}

static __always_inline int
__hike_chain_call_chain(struct hike_chain_data *chain_data, __s32 chain_id,
			__u8 nargs)
{
	return __hike_chain_push_by_id(chain_data, chain_id, nargs);
}

static __always_inline struct hike_chain_regmem *hike_chain_get_regmem()
{
	struct hike_chain_data *chain_data;
	struct hike_chain *cur_chain;

	chain_data = get_hike_chain_data();
	if (unlikely(!chain_data))
		return NULL;

	cur_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!cur_chain))
		return NULL;

	return &cur_chain->regmem;
}

#if 0
static __always_inline int hike_chain_get_reg_val(__s32 index, __u64 *const val)
{
	struct hike_chain_data *chain_data;
	struct hike_chain *cur_chain;
	int rc;

	chain_data = get_hike_chain_data();
	if (!chain_data)
		return -ENOENT;

	cur_chain = __hike_get_active_chain(chain_data);
	if (!cur_chain)
		return -ENOBUFS;

	rc = __hike_chain_load_reg(cur_chain, index, val);
	if (rc < 0)
		return rc;

	return 0;
}

int hike_chain_get_reg_ref(__s32 index, __u64 **reg)
{
	struct hike_chain_data *chain_data;
	struct hike_chain *cur_chain;
	int rc;

	chain_data = get_hike_chain_data();
	if (!chain_data)
		return -ENOENT;

	cur_chain = __hike_get_active_chain(chain_data);
	if (!cur_chain)
		return -ENOENT;

	rc = __hike_chain_ref_reg(cur_chain, index, reg);
	if (rc < 0)
		return rc;

	return 0;
}

int hike_chain_set_reg_val(__s32 index, const __u64 *val)
{
	struct hike_chain_data *chain_data;
	struct hike_chain *cur_chain;
	int rc;

	chain_data = get_hike_chain_data();
	if (!chain_data)
		return -ENOENT;

	cur_chain = __hike_get_active_chain(chain_data);
	if (!cur_chain)
		return -ENOENT;

	rc = __hike_chain_store_reg(cur_chain, index, val);
	if (rc < 0)
		return rc;

	return 0;
}
#endif

static __always_inline int __hike_chain_exit(struct hike_chain_data *chain_data)
{
	__u16 active_chain = chain_data->active_chain;
	if (unlikely(active_chain == 0)) {
		DEBUG_PRINT("HIKe VM debug: boostrap chain (active); packet will be handled by the HIKe VM");

		return -ENOBUFS;
	}

	return __hike_pop_chain(chain_data);
}

enum hike_memory_access_mode {
	HIKE_MEMORY_ACCESS_UNSPEC,
	HIKE_MEMORY_ACCESS_READ,
	HIKE_MEMORY_ACCESS_WRITE,
};

struct hike_memory_access_ctx {
	struct hike_chain_data *chain_data;
	/* specific contex for eBPF (i.e. xdp_md for XDP) */
	void *ctx;
};

static __always_inline int __hike_mem_op_size(__u8 opsize)
{
	int ret = -EINVAL;

#define OPSIZE(RET, OPSIZE, SSIZE)					\
	case (OPSIZE):							\
		RET = SSIZE;						\
		break

	switch (opsize) {
	OPSIZE(ret, HIKE_B, sizeof(__u8));
	OPSIZE(ret, HIKE_H, sizeof(__u16));
	OPSIZE(ret, HIKE_W, sizeof(__u32));
	OPSIZE(ret, HIKE_DW, sizeof(__u64));
	default:
		return -EINVAL;
	}
#undef OPSIZE

	return ret;
}

static __always_inline int
__hike_memory_xdp_packet_rw(enum hike_memory_access_mode mode, int size,
			    __u64 *ref, void *ptr, void *end)
{
#define ___hike_memory_case_load(RC, TYPE, DST, PTR, END)		\
	case (sizeof(TYPE)):						\
		if ((PTR) + sizeof(TYPE) > (END)) {			\
			RC = -ENOBUFS;					\
			break;						\
		}							\
		DST = *((TYPE *)(PTR));					\
		RC = 0;							\
		break

#define ___hike_memory_case_store(RC, TYPE, PTR, SRC, END)		\
	case (sizeof(TYPE)):						\
		if ((PTR) + sizeof(TYPE) > (END)) {			\
			RC = -ENOBUFS;					\
			break;						\
		}							\
		*((TYPE *)(PTR)) = SRC;					\
		RC = 0;							\
		break

	int rc;

	switch (mode) {
	case HIKE_MEMORY_ACCESS_READ:
		switch(size) {
		___hike_memory_case_load(rc, __u8,  *ref, ptr, end);
		___hike_memory_case_load(rc, __u16, *ref, ptr, end);
		___hike_memory_case_load(rc, __u32, *ref, ptr, end);
		___hike_memory_case_load(rc, __u64, *ref, ptr, end);
		default:
			return -EFAULT;
		}

		return rc; /* end of HIKE_MEMORY_ACCESS_READ */

	case HIKE_MEMORY_ACCESS_WRITE:
		switch(size) {
		___hike_memory_case_store(rc, __u8,  ptr, *ref, end);
		___hike_memory_case_store(rc, __u16, ptr, *ref, end);
		___hike_memory_case_store(rc, __u32, ptr, *ref, end);
		___hike_memory_case_store(rc, __u64, ptr, *ref, end);
		default:
			return -EFAULT;
		}

		return rc; /* end of HIKE_MEMORY_ACCESS_WRITE */

	default:
		return -EFAULT;
	}

	/* BUG if we land here */
	return -EBADF;

#undef ___hike_memory_case_load
#undef ___hike_memory_case_store
}

static __always_inline int
__hike_memory_xdp_packet(struct xdp_md *ctx, __u64 *ref,
			 const struct vaddr_info *vinfo, int size,
			 enum hike_memory_access_mode mode)
{
	void *data_end = (void *)(unsigned long)ctx->data_end;
	void *data = (void *)(unsigned long)ctx->data;
	void *ptr;
	__u32 off;

	off = vinfo->off;

	switch (off) {
	case HIKE_MEM_PACKET_OFF_LEN:
		if (mode != HIKE_MEMORY_ACCESS_READ)
			/* writing on len does nothing... */
			return 0;

		/* this value can be accessed only if read is aligned and starts
		 * from the beginning of the slot.
		 */
		*ref = data_end - data;
		return 0;

	/* any other slot falls into DATA */
	default:
		if (off < HIKE_MEM_PACKET_OFF_DATA_START)
			return -ENOMEM;
	/* fallthrough */
	case HIKE_MEM_PACKET_OFF_DATA_START:
		/* we have to take into account the field offset so that we can
		 * subtract it from the virtual address.
		 */
		off = HIKE_MEM_BANK_PACKET_ADJUST_OFF(off, data) &
		      HIKE_MEM_BANK_PACKET_DATA_SIZE;
		ptr = data + off;

		return __hike_memory_xdp_packet_rw(mode, size, ref, ptr,
						   data_end);
	}

	/* BUG if we land here */
	return -EBADF;
}

static __always_inline int
__hike_memory_rw(enum hike_memory_access_mode mode, int size,
		 __u64 *ref, void *ptr, __u32 off, int len)
{
#define ___hike_memory_case_load(RC, TYPE, DST, PTR, OFF, LEN)		\
	case (sizeof(TYPE)):						\
		if ((OFF) + sizeof(TYPE) > (LEN)) {			\
			RC = -ENOBUFS;					\
			break;						\
		}							\
		DST = *((TYPE *)((PTR) + (OFF)));			\
		RC = 0;							\
		break

#define ___hike_memory_case_store(RC, TYPE, PTR, OFF, SRC, LEN)		\
	case (sizeof(TYPE)):						\
		if ((OFF) + sizeof(TYPE) > (LEN)) {			\
			RC = -ENOBUFS;					\
			break;						\
		}							\
		*((TYPE *)((PTR) + (OFF))) = SRC;			\
		RC = 0;							\
		break

	int rc;

	switch (mode) {
	case HIKE_MEMORY_ACCESS_READ:
		switch(size) {
		___hike_memory_case_load(rc, __u8,  *ref, ptr, off, len);
		___hike_memory_case_load(rc, __u16, *ref, ptr, off, len);
		___hike_memory_case_load(rc, __u32, *ref, ptr, off, len);
		___hike_memory_case_load(rc, __u64, *ref, ptr, off, len);
		default:
			return -EFAULT;
		}

		return rc; /* end of HIKE_MEMORY_ACCESS_READ */

	case HIKE_MEMORY_ACCESS_WRITE:
		switch(size) {
		___hike_memory_case_store(rc, __u8,  ptr, off, *ref, len);
		___hike_memory_case_store(rc, __u16, ptr, off, *ref, len);
		___hike_memory_case_store(rc, __u32, ptr, off, *ref, len);
		___hike_memory_case_store(rc, __u64, ptr, off, *ref, len);
		default:
			return -EFAULT;
		}

		return rc; /* end of HIKE_MEMORY_ACCESS_WRITE */

	default:
		return -EFAULT;
	}

	/* BUG if we land here */
	return -EBADF;

#undef ___hike_memory_case_load
#undef ___hike_memory_case_store
}

static __always_inline int
__hike_memory_chain_stack(struct hike_chain_data *chain_data, __u64 *ref,
			  const struct vaddr_info *vinfo, int size,
			  enum hike_memory_access_mode mode)
{
	struct hike_chain *cur_chain;
	void *stack;

	cur_chain =  __hike_get_active_chain(chain_data);
	if (!cur_chain)
		return -ENOBUFS;

	stack = __ACCESS_REGMEM_STACK(&cur_chain->regmem);
	if (!stack)
		return -ENOMEM;

	return __hike_memory_rw(mode, size, ref, stack, vinfo->off,
				HIKE_CHAIN_REGMEM_STACK_SIZE);
}

/* XXX: ugly but necessary to avoid the compiler from creating a __hike_mmu
 * function with very limited stack. This limitation makes the verifier
 * unhappy reporting the error: "invalid read from stack off %d+0 size %d".
 */
#define __hike_mmu(CTX, REF, VADDR, LDSIZE, MODE) 			\
({									\
	int __rc = -EBADF;						\
	do {								\
		struct vaddr_info *__vinfo = PTR_U32_TO_PTR_VADDR(VADDR);\
		int __size = __hike_mem_op_size(LDSIZE);		\
									\
		if (__size <= 0) {					\
			/* BUG if size == 0 */				\
			__rc = !__size ? -EFAULT : __size; 		\
			break;						\
		}							\
		switch (__vinfo->bank_id) {				\
		case HIKE_MEM_BID_PACKET: 				\
			__rc = __hike_memory_xdp_packet((CTX)->ctx,	\
							(REF), __vinfo, \
							__size, (MODE));\
			break;	/* exit from the switch case */		\
		case HIKE_MEM_BID_STACK:				\
			__rc = __hike_memory_chain_stack((CTX)->chain_data,\
							 (REF), __vinfo,\
							 __size, (MODE));\
			break;	/* exit from the switch case */		\
		case HIKE_MEM_BID_ZERO:					\
		case HIKE_MEM_BID_PRIVATE:				\
		case HIKE_MEM_BID_SHARED:				\
		default:						\
			__rc = -ENOMEM;					\
			break;	/* exit from the switch case */		\
		}							\
	} while(0);							\
									\
	__rc;								\
})

static __always_inline
int __hike_elem_call_insn(struct hike_chain_data *chain_data,
			  struct hike_chain *cur_chain,
			  const struct hike_insn *insn,
			  struct hike_chain_done_insn_bottom *out)
{
	__u32 func_id = HIKE_HPFUNC_ID(insn->imm);
	__u8 nargs = 0;
	__u64 reg_val;
	__u32 elem_id;
	int rc;

	switch (func_id) {
	case __HIKE_HPFUNC_CALL_ELEM_NARGS_3_ID:
		++nargs;
		/* fallthrough */
	case __HIKE_HPFUNC_CALL_ELEM_NARGS_2_ID:
		++nargs;
		/* fallthrough */
	case __HIKE_HPFUNC_CALL_ELEM_NARGS_1_ID:
		++nargs;
		/* first argument of helper functions "hike_elem_call*" is
		 * always the elem_id which is set in HIKE_REG_1.
		 */
		rc = __hike_chain_load_reg(cur_chain, HIKE_REG_1, &reg_val);
		if (rc < 0)
			return rc;

		/* elem_id is ALWAYS 32 bits long */
		elem_id = __to_u32(reg_val);

		if (hike_is_valid_prog_id(elem_id)) {
			/* tail call is deferred, so let's set the argument of
			 * the HIKE tail call here.
			 *
			 * Tail calling directly here will not work!  Why?
			 * This whole calling function is *NO* inline... thus
			 * that's a bpf2bpf function and up to kernel 5.10
			 * mixing tail calls and bpf2bpf were prohibited...
			 */
			out->opcode = insn->hic_code;
			out->prog_id = elem_id;

			DEBUG_PRINT("HIKe VM debug: tail call for prog ID=0x%x, nargs=%d",
				    elem_id, nargs);

			return -EINPROGRESS;
		}

		if (hike_is_valid_chain_id(elem_id)) {
			rc = __hike_chain_call_chain(chain_data, elem_id,
						     nargs);
			if (unlikely(rc < 0))
				return rc;

			return 0;
		}

		DEBUG_PRINT("HIKe VM debug: invalid hike_elem_call* nargs");
		return -EINVAL;

	default:
		DEBUG_PRINT("HIKe VM debug: unknown hike_elem_call*");
		return -EFAULT;
	}

	/* unreachable code, BUG if we land here! */
	return -EFAULT;
}

static __always_inline int
__hike_chain_do_exec_one_insn_top(void *ctx, struct hike_chain_data *chain_data,
				  struct hike_chain_done_insn_bottom *out)
{
	struct hike_memory_access_ctx hike_ctx = {
		.chain_data = chain_data,
		.ctx = ctx,
	};
	struct hike_chain *cur_chain;
	const struct hike_insn *insn;
	__u64 *reg_ref;
	__u64 reg_val;
	__u8 jmp_cond;
	__u8 dst_reg;
	__s16 offset;
	__u8 src_reg;
	__s32 imm32;
	__u8 opcode;
	__u8 ldsize;
	int rc;

	cur_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!cur_chain))
		return -ENOBUFS;

	insn = __hike_chain_cur_hike_insn(cur_chain);
	if (unlikely(!insn))
		return -EFAULT;

	opcode = insn->hic_code;

	/* order of instructions here is important due to optimization done by
	 * the comiler/optimizer; program won't be verified if we swap the
	 * following 2 instructions withouth adding some barriers.
	 */
	DEBUG_PRINT("HIKe VM debug: exec insn opcode=0x%x", opcode);

	__hike_chain_upc_inc(cur_chain);
	/* PC now points to PC + 1 */

	switch (opcode) {

	/* convert endianess of a register */
	case HIKE_ALU | HIKE_END | HIKE_TO_BE:
	case HIKE_ALU | HIKE_END | HIKE_TO_LE:
		dst_reg = insn->hic_dst;
		imm32 = insn->imm;

		/* get the reference to the destination register */
		rc = __hike_chain_ref_reg(cur_chain, dst_reg, &reg_ref);
		if (rc < 0)
			return rc;

#define TOEND(END, SIZE, DST, SRC)		\
	case (SIZE):				\
		DST = cpu_to_##END##SIZE(DST);	\
		break

		if (HIKE_SRC(opcode) == HIKE_TO_BE) {
			switch (imm32) {
			TOEND(be, 16, *reg_ref, *reg_ref);
			TOEND(be, 32, *reg_ref, *reg_ref);
			TOEND(be, 64, *reg_ref, *reg_ref);
			default:
				return -EFAULT;
			}
		} else if (HIKE_SRC(opcode) == HIKE_TO_LE) {
			switch (imm32) {
			TOEND(le, 16, *reg_ref, *reg_ref);
			TOEND(le, 32, *reg_ref, *reg_ref);
			TOEND(le, 64, *reg_ref, *reg_ref);
			default:
				return -EFAULT;
			}
		} else {
			/* invalid endianess */
			return -EFAULT;
		}
#undef TOEND
		break;

	/* LD with 64 bit immediate (2 insns wide)*/
	case HIKE_LD | HIKE_IMM | HIKE_DW:
		dst_reg = insn->hic_dst;
		imm32 = insn->imm;

		rc = __hike_chain_ref_reg(cur_chain, dst_reg, &reg_ref);
		if (rc < 0)
			return rc;

		/* LD64 is split in two instructions; fetch the second one
		 * righ here.
		 */
		insn = __hike_chain_cur_hike_insn(cur_chain);
		if (!insn)
			return -EFAULT;

		__hike_chain_upc_inc(cur_chain);

		*reg_ref = ((__u64)(__u32)imm32) |
			   ((__u64)(__u32)insn->imm) << 32;

		break;

	/* LDX instructions, i,e: dst_reg = *(type)(src_reg + off) */
	case HIKE_LDX | HIKE_MEM | HIKE_DW:
	case HIKE_LDX | HIKE_MEM | HIKE_W:
	case HIKE_LDX | HIKE_MEM | HIKE_H:
	case HIKE_LDX | HIKE_MEM | HIKE_B: {
		ldsize = HIKE_SIZE(opcode);
		dst_reg = insn->hic_dst;
		src_reg = insn->hic_src;
		offset = insn->hic_off;

		/* get the reference to the destination register */
		rc = __hike_chain_ref_reg(cur_chain, dst_reg, &reg_ref);
		if (rc < 0)
			return rc;

		/* read the src register */
		rc = __hike_chain_load_reg(cur_chain, src_reg, &reg_val);
		if (rc < 0)
			return rc;

		/* add the offset to the memory address contained in the
		 * src_reg. At this point, this address is *VIRTUAL* and it
		 * must be provided to the MMU in order to be translated and
		 * get back the memory content.
		 */
		reg_val += offset;

		rc = __hike_mmu(&hike_ctx, reg_ref, &reg_val, ldsize,
				HIKE_MEMORY_ACCESS_READ);
		if (rc < 0)
			return rc;

	} break;

	/* STX unstructions, i.e.: (*type)(dst_reg + off) = imm32 */
	case HIKE_ST | HIKE_MEM | HIKE_DW:
	case HIKE_ST | HIKE_MEM | HIKE_W:
	case HIKE_ST | HIKE_MEM | HIKE_H:
	case HIKE_ST | HIKE_MEM | HIKE_B:
	/* STX unstructions, i.e.: (*type)(dst_reg + off) = src_reg */
	case HIKE_STX | HIKE_MEM | HIKE_DW:
	case HIKE_STX | HIKE_MEM | HIKE_W:
	case HIKE_STX | HIKE_MEM | HIKE_H:
	case HIKE_STX | HIKE_MEM | HIKE_B: {
		/* Compiler and optimizer emit code which doesn't like the
		 * verfier... this avoids making the verifier work with shift
		 * operations on pointers which are prohibited.
		 */
		volatile __u64 store;

		ldsize = HIKE_SIZE(opcode);
		dst_reg = insn->hic_dst;
		offset = insn->hic_off;

		switch (HIKE_CLASS(opcode)) {
		case HIKE_ST:
			store = (__u64)insn->imm;
			break;
		case HIKE_STX:
			src_reg = insn->hic_src;
			rc = __hike_chain_load_reg(cur_chain, src_reg,
						   (__u64 *)&store);
			if (rc < 0)
				return rc;
			break;
		}

		rc = __hike_chain_load_reg(cur_chain, dst_reg, &reg_val);
		if (rc < 0)
			return rc;

		reg_val += offset;

		rc = __hike_mmu(&hike_ctx, (__u64 *)&store, &reg_val, ldsize,
				HIKE_MEMORY_ACCESS_WRITE);
		if (rc < 0)
			return rc;

	} break;

	/* ALU arithmetic  */
	case HIKE_ALU64 | HIKE_ADD | HIKE_K:
	case HIKE_ALU64 | HIKE_AND | HIKE_K:
		dst_reg = insn->hic_dst;
		imm32 = insn->imm;

#define ALU(OPCODE, DST, OP, SRC, TYPE)					\
	case (OPCODE):							\
		DST = ((TYPE)DST) OP ((TYPE)SRC);			\
		break

		/* instead of calling both __hike_chain_{load/store}_reg, we use
		 * directly one single function which takes the register's
		 * reference at once.
		 */
		rc = __hike_chain_ref_reg(cur_chain, dst_reg, &reg_ref);
		if (unlikely(rc < 0))
			return rc;

		/* apply DST = DST OP SRC/imm */
		switch (opcode) {
		ALU(HIKE_ALU64 | HIKE_ADD | HIKE_K, *reg_ref, +, imm32, __s32);
		ALU(HIKE_ALU64 | HIKE_AND | HIKE_K, *reg_ref, &, imm32, __s32);
		default:
			return -EFAULT;
		}
#undef ALU

		break;

	/* ALU mov */
	case HIKE_ALU64 | HIKE_MOV | HIKE_K:
	case HIKE_ALU64 | HIKE_MOV | HIKE_X:
		dst_reg = insn->hic_dst;

		/* select the source: src register or immediate */
		switch (HIKE_SRC(opcode)) {
		case HIKE_K:
			imm32 = insn->imm;
			break;
		case HIKE_X:
			src_reg = insn->hic_src;
			rc = __hike_chain_load_reg(cur_chain, src_reg,
						   &reg_val);
			if (rc < 0)
				return rc;
			break;
		default:
			return -EFAULT;
		}

		rc = __hike_chain_ref_reg(cur_chain, dst_reg, &reg_ref);
		if (rc < 0)
			return rc;

#define ALU_MOV(OPCODE, DST, SRC, TYPE)					\
		case (OPCODE):						\
			DST = (TYPE) SRC;				\
			break

		switch (opcode) {
		ALU_MOV(HIKE_ALU64 | HIKE_MOV | HIKE_K, *reg_ref, imm32, __s64);
		ALU_MOV(HIKE_ALU64 | HIKE_MOV | HIKE_X, *reg_ref, reg_val,
			__s64);
		default:
			return -EFAULT;
		}
#undef ALU_MOV

		break;

	/* jump always */
	case HIKE_JMP64 | HIKE_JA:
		offset = insn->hic_off;

		rc = __hike_chain_upc_add(cur_chain, offset);
		if (unlikely(rc < 0))
			return rc;

		break;

	/* conditional jump section using immediate */
	case HIKE_JMP64 | HIKE_JNE | HIKE_K:
	case HIKE_JMP64 | HIKE_JEQ | HIKE_K:
	case HIKE_JMP64 | HIKE_JGT | HIKE_K:
	case HIKE_JMP64 | HIKE_JGE | HIKE_K:
	case HIKE_JMP64 | HIKE_JLT | HIKE_K:
	case HIKE_JMP64 | HIKE_JLE | HIKE_K:
		dst_reg = insn->hic_dst;
		offset = insn->hic_off;
		imm32 = insn->imm;

		rc = __hike_chain_load_reg(cur_chain, dst_reg, &reg_val);
		if (unlikely(rc < 0))
			return rc;

#define COND_JUMP(OPCODE, VAR, DST, CMP_OP, SRC, TYPE)			\
		case (OPCODE):						\
			VAR = ((TYPE)DST) CMP_OP ((TYPE)SRC);		\
			break

		switch (opcode) {
		COND_JUMP(HIKE_JMP64 | HIKE_JEQ | HIKE_K,
			  jmp_cond, reg_val, ==, imm32, __u64);
		COND_JUMP(HIKE_JMP64 | HIKE_JNE | HIKE_K,
			  jmp_cond, reg_val, !=, imm32, __u64);
		COND_JUMP(HIKE_JMP64 | HIKE_JGT | HIKE_K,
			  jmp_cond, reg_val, >, imm32, __u64);
		COND_JUMP(HIKE_JMP64 | HIKE_JGE | HIKE_K,
			  jmp_cond, reg_val, >=, imm32, __u64);
		COND_JUMP(HIKE_JMP64 | HIKE_JLT | HIKE_K,
			  jmp_cond, reg_val, <, imm32, __u64);
		COND_JUMP(HIKE_JMP64 | HIKE_JLE | HIKE_K,
			  jmp_cond, reg_val, <=, imm32, __u64);
		default:
			return -EFAULT;
		}
#undef COND_JUMP

		if (jmp_cond) {
			rc = __hike_chain_upc_add(cur_chain, offset);
			if (unlikely(rc < 0))
				return rc;
		}

		/* end of conditional jump section */
		break;

	/* HIKe exit for returning from a chain. */
	case HIKE_JMP64 | HIKE_EXIT:
		rc = __hike_chain_exit(chain_data);
		if (unlikely(rc < 0))
			return rc;

		break;

	/* HIKe calling function infrastructure */
	case HIKE_JMP64 | HIKE_CALL: {
		imm32 = (__s32)HIKE_HPFUNC_ID(insn->imm);

		switch (imm32) {
		case __HIKE_HPFUNC_CALL_ELEM_NARGS_3_ID:
		case __HIKE_HPFUNC_CALL_ELEM_NARGS_2_ID:
		case __HIKE_HPFUNC_CALL_ELEM_NARGS_1_ID:
			return __hike_elem_call_insn(chain_data, cur_chain,
						     insn, out);

		/* XXX: other helper functions can be delcared here */

		default:
			DEBUG_PRINT("HIKe VM debug: BUG! Invalid hike function call=0x%x\n",
				    imm32);
			return -EFAULT;
		}
	} break; /* end of HIKE_CALL */

	default:
		DEBUG_PRINT("HIKe VM debug: invalid opcode=0x%x", opcode);
		return -EFAULT;
	}

	return 0;
}

/* this trick accounts for the compiler optimizations... the bpf_tail_call is
 * in the calling prog rather than in any internal function and this seems to
 * be good.
 */
#define __hike_chain_do_exec(ctx, chain_data)				\
({									\
	struct hike_chain_done_insn_bottom res = { 0, };		\
	int i, rc = -ELOOP;						\
									\
	for (i = 0; i < HIKE_CHAIN_EXEC_NINSN_MAX; ++i) {		\
		rc = __hike_chain_do_exec_one_insn_top(ctx, chain_data,	\
						       &res);		\
		if (rc < 0)						\
			break;						\
	}								\
									\
	if (rc == -EINPROGRESS)	{					\
		switch (res.opcode) {					\
		case HIKE_JMP64 | HIKE_CALL:				\
			bpf_tail_call(ctx, &gen_jmp_table, res.prog_id);\
			/* fallback */					\
			rc = -ENOENT;					\
			break;						\
		default:						\
			rc = -EFAULT;					\
			break;						\
		}							\
	}								\
									\
	rc;								\
})

#define hike_chain_next(ctx)						\
({									\
	struct hike_chain_data *chain_data = get_hike_chain_data();	\
	int rc;								\
									\
	if (unlikely(!chain_data))					\
		rc = -ENOENT;						\
	else								\
		rc = __hike_chain_do_exec(ctx, chain_data);		\
									\
	rc;								\
})

static __always_inline int
__hike_chain_boostrap_install(struct hike_chain_data *chain_data)
{
	struct hike_chain *boot_chain;

	chain_data->active_chain = 0;

	boot_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!boot_chain))
		return -ENOBUFS;

	boot_chain->chain_id = CHAIN_DEFAULT_ID;
	boot_chain->upc = 0;
	boot_chain->ninsn = 2;

	/* reset RET register (the only register to be used for passing
	 * returned values between progs/chains.
	 */
	ACCESS_HIKE_CHAIN_REG(boot_chain, 0) = 0;

	ACCESS_HIKE_CHAIN_REG(boot_chain, 1) = (__u32)0xf0f0f0f0;
	ACCESS_HIKE_CHAIN_REG(boot_chain, 2) = 0;

	ACCESS_HIKE_CHAIN_REG(boot_chain, fp) = HIKE_MEM_CHAIN_STACK_DATA_END;

	/* chain loader instruction; REG_1 will be loaded with the ID of the
	 * chain id chosen in the bootstrap phase.
	 */
	boot_chain->insns[0] = HIKE_CALL_ELEM_NARGS_2_INSN();
	boot_chain->insns[1] = HIKE_EXIT_INSN();

	return 0;
}

static __always_inline int
hike_chain_boostrap(struct xdp_md *ctx, __s32 chain_id)
{
	struct hike_chain_data *chain_data;
	struct hike_chain *cur_chain;
	struct hike_insn *insn;
	int rc;

	chain_data = get_hike_chain_data();
	if (unlikely(!chain_data))
		return -ENOENT;

	rc = __hike_chain_boostrap_install(chain_data);
	if (unlikely(rc < 0))
		return rc;

	cur_chain = __hike_get_active_chain(chain_data);
	if (unlikely(!cur_chain))
		return -ENOBUFS;

	/* retrieve the first instruction of the loading chain */
	insn = __hike_chain_hike_insn_at(cur_chain, 0);
	if (unlikely(!insn))
		return -EFAULT;

	/* set the chain ID in register REG_1; that allows the HIKE VM to
	 * jump into the given chain.
	 */
	ACCESS_HIKE_CHAIN_REG(cur_chain, 1) = (__u32)chain_id;

	/* at this point, we have just created the HIKe context for the
	 * execution, let's call the exec for this first instruction.
	 */

	return __hike_chain_do_exec(ctx, chain_data);
}

#define EXPORT_HIKE_PROG(progname, progid)				\
__section_tail(GEN_PROG_MAP_ID, progid)					\
int __xdp_autogen_##progname(struct xdp_md *ctx)			\
{									\
	struct hike_chain_regmem *regmem;				\
	int rc;								\
									\
	regmem = hike_chain_get_regmem();				\
	if (unlikely(!regmem))						\
		goto aborted;						\
									\
	rc = progname(ctx, regmem);					\
	switch (rc) {							\
	case XDP_ABORTED:						\
	case XDP_DROP:							\
	case XDP_PASS:							\
	case XDP_TX:							\
	case XDP_REDIRECT:						\
		DEBUG_PRINT("HIKe VM debug: HIKe VM halt with code=0x%x",\
			    rc);					\
		return rc;						\
	}								\
									\
	barrier();							\
	hike_chain_next(ctx);						\
	/* fallback by default means aborted */				\
aborted:								\
	DEBUG_PRINT("HIKe VM debug: HIKe VM abort, no action for packet");\
	return XDP_ABORTED;						\
}

#define HIKE_PROG(progname)						\
static __always_inline int progname(struct xdp_md *ctx,			\
				    struct hike_chain_regmem *regmem)

#define _I_RREG(reg)	ACCESS_REF_REGMEM(regmem, reg)
#define _I_REG(reg)	ACCESS_REGMEM(regmem, reg)


/* TODO: move in a sperate .h file (hike_vm_uapi.h) */
/* ######################################################################### */
/* ############################## User API ################################# */
/* ######################################################################### */


#define __UAPI_PACKET_BASE_ADDR ((size_t)(HIKE_MEM_PACKET_ADDR_DATA))

#define __UAPI_READ_PACKET(__type, __offset)				\
	((volatile __type)*(__type *)((__UAPI_PACKET_BASE_ADDR) + (__offset)))

#define __UAPI_WRITE_PACKET(__type, __offset)				\
	*(volatile __type *)((__UAPI_PACKET_BASE_ADDR) + (__offset))

static __always_inline int hike_packet_read_u8(__u8 *const dst, int off)
{
	*dst = __UAPI_READ_PACKET(__u16, off);

	return 0;
}

static __always_inline int hike_packet_read_u16(__u16 *const dst, int off)
{
	__be16 v = __UAPI_READ_PACKET(__be16, off);
	*dst = bpf_ntohs(v);

	return 0;
}

static __always_inline int hike_packet_write_u8(int off, const __u8 src)
{
	__UAPI_WRITE_PACKET(__u8, off) = src;

	return 0;
}

static __always_inline int hike_packet_write_u16(int off, const __u16 src)
{
	__UAPI_WRITE_PACKET(__be16, off) = bpf_htons(src);

	return 0;
}

#define __sec_hike_chain(ID)	__section("__sec_hike_chain_"__stringify(ID))

#define __hike_chain_verify_arg(ARG)		\
{						\
	__u64 __u64_verify = (ARG);		\
	(void)__u64_verify;			\
}

#define __HIKE_CHAIN_FUNC_NAME(CNAME)	__autogen_hike_chain_##CNAME

#define __EXPORT_HIKE_CHAIN_FUNC(CNAME)	__trampoline_hike_chain_##CNAME

#define __DEF_HIKE_CHAIN_FUNC(CNAME, ...)				\
static __always_inline int						\
__HIKE_CHAIN_FUNC_NAME(CNAME)(const __u32 chain_id, ##__VA_ARGS__)

#define HIKE_CHAIN_1(CNAME) 						\
__DEF_HIKE_CHAIN_FUNC(CNAME);						\
__sec_hike_chain(CNAME)							\
int __EXPORT_HIKE_CHAIN_FUNC(CNAME)(const __u32 chain_id)		\
{									\
	__hike_chain_verify_arg(CNAME);					\
									\
	return __HIKE_CHAIN_FUNC_NAME(CNAME)(chain_id);			\
}									\
									\
__DEF_HIKE_CHAIN_FUNC(CNAME)

/* 2 args */
#define HIKE_CHAIN_2(CNAME, TA1, A1) 					\
__DEF_HIKE_CHAIN_FUNC(CNAME, TA1 A1);					\
__sec_hike_chain(CNAME)							\
int __EXPORT_HIKE_CHAIN_FUNC(CNAME)(const __u32 chain_id,		\
				    TA1 A1)				\
{									\
	__hike_chain_verify_arg(CNAME);					\
	__hike_chain_verify_arg(A1);					\
									\
	return __HIKE_CHAIN_FUNC_NAME(CNAME)(chain_id, A1);		\
}									\
									\
__DEF_HIKE_CHAIN_FUNC(CNAME, TA1 A1)

/* 3 args */
#define HIKE_CHAIN_3(CNAME, TA1, A1, TA2, A2) 				\
__DEF_HIKE_CHAIN_FUNC(CNAME, TA1 A1, TA2 A2);				\
__sec_hike_chain(CNAME)							\
int __EXPORT_HIKE_CHAIN_FUNC(CNAME)(const __u32 chain_id,		\
				    TA1 A1, TA2 A2)			\
{									\
	__hike_chain_verify_arg(CNAME);					\
	__hike_chain_verify_arg(A1);					\
	__hike_chain_verify_arg(A2);					\
									\
	return __HIKE_CHAIN_FUNC_NAME(CNAME)(chain_id, A1, A2);		\
}									\
									\
__DEF_HIKE_CHAIN_FUNC(CNAME, TA1 A1, TA2 A2)

#endif /* end of #ifdef for include header file */
