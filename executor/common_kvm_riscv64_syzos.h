// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_RISCV64_SYZOS_H
#define EXECUTOR_COMMON_KVM_RISCV64_SYZOS_H

// This file provides guest code running inside the RISCV64 KVM.

#include <linux/kvm.h>

#include "common_kvm_syzos.h"
#include "kvm.h"

// Remember these constants must match those in sys/linux/dev_kvm_riscv64.txt.
typedef enum {
	SYZOS_API_UEXIT = 0,
	SYZOS_API_CODE = 10,
	SYZOS_API_CSRR = 100,
	SYZOS_API_CSRW = 101,
	SYZOS_API_CSR_OP = 102,
	SYZOS_API_SBI_PMU_NUM_CTRS = 200,
	SYZOS_API_SBI_PMU_CTR_INFO = 201,
	SYZOS_API_SBI_PMU_CTR_CFG_MATCH = 202,
	SYZOS_API_SBI_PMU_CTR_START = 203,
	SYZOS_API_SBI_PMU_CTR_STOP = 204,
	SYZOS_API_SBI_PMU_FW_CTR_READ = 205,
	SYZOS_API_SBI_PMU_SNAPSHOT_SET_SHMEM = 206,
    SYZOS_API_SBI_STA_SET_SHMEM          = 210,
	SYZOS_API_MEMWRITE = 300,
	SYZOS_API_MEMREAD = 301,
	SYZOS_API_ECALL = 400,
	SYZOS_API_RET = 500,
	SYZOS_API_BARRIER = 600,
	SYZOS_API_SBI_GENERIC = 700,
	SYZOS_API_STOP, // Must be the last one
} syzos_api_id;

struct api_call_code {
	struct api_call_header header;
	uint32 insns[];
};

struct api_call_sbi_pmu_ctr_info {
	struct api_call_header header;
	uint64 ctr_idx;
};

struct api_call_sbi_pmu_ctr_cfg_match {
	struct api_call_header header;
	uint64 cbase;
	uint64 cmask;
	uint64 cflags;
	uint64 event;
};

struct api_call_sbi_pmu_ctr_start {
	struct api_call_header header;
	uint64 ctr_base;
	uint64 ctr_mask;
	uint64 flags;
	uint64 ival;
};

struct api_call_sbi_pmu_ctr_stop {
	struct api_call_header header;
	uint64 ctr_base;
	uint64 ctr_mask;
	uint64 flags;
};

struct api_call_sbi_pmu_fw_ctr_read {
	struct api_call_header header;
	uint64 ctr_idx;
};

struct api_call_sbi_pmu_snapshot_set_shmem {
	struct api_call_header header;
	uint64 gpa_lo;
	uint64 gpa_hi;
	uint64 flags;
};

struct api_call_sbi_sta_set_shmem {
	struct api_call_header header;
	uint64 gpa_lo;
	uint64 gpa_hi;
	uint64 flags;
};

struct api_call_8 {
	struct api_call_header header;
	uint64 args[8];
};

struct api_call_memwrite {
	struct api_call_header header;
	uint64 base_addr;
	uint64 offset;
	uint64 value;
	uint64 len;
};

struct api_call_memread {
    struct api_call_header header;
    uint64 base_addr;
    uint64 offset;
    uint64 len;
};

struct api_call_barrier {
    struct api_call_header header;
    uint64 type;
};

struct api_call_csr_op {
    struct api_call_header header;
    uint64 csr;
    uint64 val;
    uint64 op;
};

struct api_call_sbi_generic {
	struct api_call_header header;
	uint64 a0;
	uint64 a1;
	uint64 a2;
	uint64 a3;
	uint64 a4;
	uint64 a5;
	uint64 fid;
	uint64 ext;
};

GUEST_CODE static void guest_uexit(uint64 exit_code);
GUEST_CODE static void guest_execute_code(uint32* insns, uint64 size);
GUEST_CODE static void guest_handle_csrr(uint32 csr);
GUEST_CODE static void guest_handle_csrw(uint32 csr, uint64 val);
GUEST_CODE static void guest_handle_csr_op(uint64 csr, uint64 val, uint64 op);
GUEST_CODE static void guest_handle_sbi_pmu_num_ctrs(void);
GUEST_CODE static void guest_handle_sbi_pmu_ctr_info(uint64 ctr_idx);
GUEST_CODE static void guest_handle_sbi_pmu_ctr_cfg_match(uint64 cbase, uint64 cmask, uint64 cflags, uint64 event);
GUEST_CODE static void guest_handle_sbi_pmu_ctr_start(uint64 ctr_base, uint64 ctr_mask, uint64 flags, uint64 ival);
GUEST_CODE static void guest_handle_sbi_pmu_ctr_stop(uint64 ctr_base, uint64 ctr_mask, uint64 flags);
GUEST_CODE static void guest_handle_sbi_pmu_fw_ctr_read(uint64 ctr_idx);
GUEST_CODE static void guest_handle_sbi_pmu_snapshot_set_shmem(uint64 gpa_lo, uint64 gpa_hi, uint64 flags);
GUEST_CODE static void guest_handle_sbi_sta_set_shmem(uint64 gpa_lo, uint64 gpa_hi, uint64 flags);
GUEST_CODE static void guest_handle_memwrite(struct api_call_memwrite* cmd);
GUEST_CODE static void guest_handle_memread(struct api_call_memread* cmd);
GUEST_CODE static void guest_handle_ecall(uint64 a0, uint64 a1, uint64 a2, uint64 a3, uint64 a4, uint64 a5, uint64 a6, uint64 a7);
GUEST_CODE static void guest_handle_ret(uint64 unused);
GUEST_CODE static void guest_handle_barrier(uint64 type);
GUEST_CODE static void guest_handle_sbi_generic(uint64 a0, uint64 a1, uint64 a2, uint64 a3, uint64 a4, uint64 a5, uint64 fid, uint64 ext);

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
// The inner loop uses a complex if-statement, because Clang is eager to insert a jump table into
// a switch statement.
// We add single-line comments to justify having the compound statements below.
__attribute__((used))
GUEST_CODE static void
guest_main(uint64 size, uint64 cpu)
{
	uint64 addr = RISCV64_ADDR_USER_CODE + cpu * 0x1000;

	while (size >= sizeof(struct api_call_header)) {
		struct api_call_header* cmd = (struct api_call_header*)addr;
		if (cmd->call >= SYZOS_API_STOP)
			return;
		if (cmd->size > size)
			return;
		volatile uint64 call = cmd->call;
		if (call == SYZOS_API_UEXIT) {
			// Issue a user exit.
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_uexit(ccmd->arg);
		} else if (call == SYZOS_API_CODE) {
			// Execute an instruction blob.
			struct api_call_code* ccmd = (struct api_call_code*)cmd;
			guest_execute_code(ccmd->insns, cmd->size - sizeof(struct api_call_header));
		} else if (call == SYZOS_API_CSRR) {
			// Execute a csrr instruction.
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_csrr(ccmd->arg);
		} else if (call == SYZOS_API_CSRW) {
			// Execute a csrw instruction.
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_handle_csrw(ccmd->args[0], ccmd->args[1]);
		} else if (call == SYZOS_API_CSR_OP) {
    		struct api_call_csr_op* ccmd =
    		    (struct api_call_csr_op*)cmd;
    		guest_handle_csr_op(ccmd->csr, ccmd->val, ccmd->op); 
		} else if (call == SYZOS_API_SBI_PMU_NUM_CTRS) {
			// Query total number of PMU counters via SBI.
			guest_handle_sbi_pmu_num_ctrs();
		} else if (call == SYZOS_API_SBI_PMU_CTR_INFO) {
			// Get counter info (type, CSR, width) for a given index.
			struct api_call_sbi_pmu_ctr_info* ccmd =
			    (struct api_call_sbi_pmu_ctr_info*)cmd;
			guest_handle_sbi_pmu_ctr_info(ccmd->ctr_idx);
		} else if (call == SYZOS_API_SBI_PMU_CTR_CFG_MATCH) {
			// Find and configure a counter matching the requested event.
			struct api_call_sbi_pmu_ctr_cfg_match* ccmd =
			    (struct api_call_sbi_pmu_ctr_cfg_match*)cmd;
			guest_handle_sbi_pmu_ctr_cfg_match(ccmd->cbase, ccmd->cmask,
							   ccmd->cflags, ccmd->event);
		} else if (call == SYZOS_API_SBI_PMU_CTR_START) {
			// Start one or more configured counters.
			struct api_call_sbi_pmu_ctr_start* ccmd =
			    (struct api_call_sbi_pmu_ctr_start*)cmd;
			guest_handle_sbi_pmu_ctr_start(ccmd->ctr_base, ccmd->ctr_mask,
						       ccmd->flags, ccmd->ival);
		} else if (call == SYZOS_API_SBI_PMU_CTR_STOP) {
			// Stop one or more running counters.
			struct api_call_sbi_pmu_ctr_stop* ccmd =
			    (struct api_call_sbi_pmu_ctr_stop*)cmd;
			guest_handle_sbi_pmu_ctr_stop(ccmd->ctr_base, ccmd->ctr_mask,
						      ccmd->flags);
		} else if (call == SYZOS_API_SBI_PMU_FW_CTR_READ) {
			// Read a firmware counter value.
			struct api_call_sbi_pmu_fw_ctr_read* ccmd =
			    (struct api_call_sbi_pmu_fw_ctr_read*)cmd;
			guest_handle_sbi_pmu_fw_ctr_read(ccmd->ctr_idx);
		} else if (call == SYZOS_API_SBI_PMU_SNAPSHOT_SET_SHMEM) {
			// Set the PMU snapshot shared memory region.
			struct api_call_sbi_pmu_snapshot_set_shmem* ccmd =
			    (struct api_call_sbi_pmu_snapshot_set_shmem*)cmd;
			guest_handle_sbi_pmu_snapshot_set_shmem(ccmd->gpa_lo,
								ccmd->gpa_hi,
								ccmd->flags);
		} else if (call == SYZOS_API_SBI_STA_SET_SHMEM) {
            // Register steal-time shared memory (SBI STA FID=0).
            struct api_call_sbi_sta_set_shmem* ccmd =
                (struct api_call_sbi_sta_set_shmem*)cmd;
            guest_handle_sbi_sta_set_shmem(ccmd->gpa_lo, ccmd->gpa_hi,
                                           ccmd->flags);
		} else if (call == SYZOS_API_MEMWRITE) {
			guest_handle_memwrite((struct api_call_memwrite*)cmd);
		} else if (call == SYZOS_API_MEMREAD) {
			guest_handle_memread((struct api_call_memread*)cmd);
		} else if (call == SYZOS_API_ECALL) {
			struct api_call_8* ccmd = (struct api_call_8*)cmd;
			guest_handle_ecall(ccmd->args[0], ccmd->args[1], ccmd->args[2], ccmd->args[3], ccmd->args[4], ccmd->args[5], ccmd->args[6], ccmd->args[7]);
		} else if (call == SYZOS_API_RET) {
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_ret(ccmd->arg);
        } else if (call == SYZOS_API_BARRIER) {
			struct api_call_barrier* ccmd = (struct api_call_barrier*)cmd;
			guest_handle_barrier(ccmd->type);
		} else if (call == SYZOS_API_SBI_GENERIC) {
			struct api_call_sbi_generic* ccmd =
				(struct api_call_sbi_generic*)cmd;

			guest_handle_sbi_generic(
				ccmd->a0, ccmd->a1, ccmd->a2, ccmd->a3,
				ccmd->a4, ccmd->a5,
				ccmd->fid, ccmd->ext);
		}
		addr += cmd->size;
		size -= cmd->size;
	};
	guest_uexit((uint64)-1);
}

// Perform a userspace exit that can be handled by the host.
// The host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO,
// and can handle the call depending on the data passed as exit code.
GUEST_CODE static noinline void guest_uexit(uint64 exit_code)
{
	volatile uint64* ptr = (volatile uint64*)RISCV64_ADDR_UEXIT;
	*ptr = exit_code;
}

GUEST_CODE static noinline void guest_execute_code(uint32* insns, uint64 size)
{
	asm volatile("fence.i" ::
			 : "memory");
	volatile void (*fn)() = (volatile void (*)())insns;
	fn();
}

// Host sets CORE_TP to contain the virtual CPU id.
GUEST_CODE static uint32 get_cpu_id()
{
	uint64 val = 0;
	asm volatile("mv %0, tp"
		     : "=r"(val));
	return (uint32)val;
}

#define MAX_CACHE_LINE_SIZE 256
#define RISCV_OPCODE_SYSTEM 0x73
#define FUNCT3_CSRRW 0x1
#define FUNCT3_CSRRS 0x2
#define FUNCT3_CSRRC 0x3
#define REG_ZERO 0
#define REG_A0 10
#define ENCODE_CSR_INSN(csr, rs1, funct3, rd) \
	(((csr) << 20) | ((rs1) << 15) | ((funct3) << 12) | ((rd) << 7) | RISCV_OPCODE_SYSTEM)

GUEST_CODE static noinline void
guest_handle_csrr(uint32 csr)
{
	uint32 cpu_id = get_cpu_id();
	// Make sure CPUs use different cache lines for scratch code.
	uint32* insn = (uint32*)((uint64)RISCV64_ADDR_SCRATCH_CODE + cpu_id * MAX_CACHE_LINE_SIZE);
	// insn[0] - csrr a0, csr
	// insn[1] - ret
	insn[0] = ENCODE_CSR_INSN(csr, REG_ZERO, FUNCT3_CSRRS, REG_A0);
	insn[1] = 0x00008067;
	asm volatile("fence.i" ::
			 : "memory");
	asm volatile(
	    "jalr ra, 0(%0)"
	    :
	    : "r"(insn)
	    : "ra", "a0", "memory");
}

GUEST_CODE static noinline void
guest_handle_csrw(uint32 csr, uint64 val)
{
	uint32 cpu_id = get_cpu_id();
	// Make sure CPUs use different cache lines for scratch code.
	uint32* insn = (uint32*)((uint64)RISCV64_ADDR_SCRATCH_CODE + cpu_id * MAX_CACHE_LINE_SIZE);
	// insn[0] - csrw csr, a0
	// insn[1] - ret
	insn[0] = ENCODE_CSR_INSN(csr, REG_A0, FUNCT3_CSRRW, REG_ZERO);
	insn[1] = 0x00008067;
	asm volatile("fence.i" ::
			 : "memory");
	asm volatile(
	    "mv a0, %0\n"
	    "jalr ra, 0(%1)"
	    :
	    : "r"(val), "r"(insn)
	    : "a0", "ra", "memory");
}

#define SYZOS_CSR_OP_SWAP        0  // csrrw
#define SYZOS_CSR_OP_SET         1  // csrs
#define SYZOS_CSR_OP_CLEAR       2  // csrc
#define SYZOS_CSR_OP_READ_SET    3  // csrrs
#define SYZOS_CSR_OP_READ_CLEAR  4  // csrrc

GUEST_CODE static noinline void
guest_handle_csr_op(uint64 csr, uint64 val, uint64 op)
{
    uint32 cpu_id = get_cpu_id();

    uint32* insn = (uint32*)((uint64)RISCV64_ADDR_SCRATCH_CODE +
                              cpu_id * MAX_CACHE_LINE_SIZE);

    uint32 funct3;

    switch (op) {
    case SYZOS_CSR_OP_SWAP:
        funct3 = FUNCT3_CSRRW;
        break;
    case SYZOS_CSR_OP_SET:
    case SYZOS_CSR_OP_READ_SET:
        funct3 = FUNCT3_CSRRS;
        break;
    case SYZOS_CSR_OP_CLEAR:
    case SYZOS_CSR_OP_READ_CLEAR:
        funct3 = FUNCT3_CSRRC;
        break;
    default:
        funct3 = FUNCT3_CSRRW;
        break;
    }

    // rd = a0（读取返回值）
    insn[0] = ENCODE_CSR_INSN(csr, REG_A0, funct3, REG_A0);

    // ret
    insn[1] = 0x00008067;

    asm volatile("fence.i" ::: "memory");

    uint64 out;

    asm volatile(
        "mv a0, %2\n"
        "jalr ra, 0(%1)\n"
        "mv %0, a0\n"
        : "=r"(out)
        : "r"(insn), "r"(val)
        : "a0", "ra", "memory");

    // 防优化
    asm volatile("" :: "r"(out) : "memory");
}

// The exception vector table setup and SBI invocation here follow the
// implementation in Linux kselftest KVM RISC-V tests.
// See https://elixir.bootlin.com/linux/v6.19-rc5/source/tools/testing/selftests/kvm/lib/riscv/processor.c#L337 .
#define KVM_RISCV_SBI_EXT 0x08FFFFFF
#define KVM_RISCV_SBI_UNEXP 1

struct sbiret {
	long error;
	long value;
};

GUEST_CODE static inline struct sbiret
sbi_ecall(unsigned long arg0, unsigned long arg1,
	  unsigned long arg2, unsigned long arg3,
	  unsigned long arg4, unsigned long arg5,
	  int fid, int ext)
{
	struct sbiret ret;

	register unsigned long a0 asm("a0") = arg0;
	register unsigned long a1 asm("a1") = arg1;
	register unsigned long a2 asm("a2") = arg2;
	register unsigned long a3 asm("a3") = arg3;
	register unsigned long a4 asm("a4") = arg4;
	register unsigned long a5 asm("a5") = arg5;
	register unsigned long a6 asm("a6") = fid;
	register unsigned long a7 asm("a7") = ext;
	asm volatile("ecall"
		     : "+r"(a0), "+r"(a1)
		     : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
		     : "memory");
	ret.error = a0;
	ret.value = a1;

	return ret;
}

GUEST_CODE __attribute__((used)) __attribute((__aligned__(16))) static void
guest_unexp_trap(void)
{
	sbi_ecall(0, 0, 0, 0, 0, 0,
		  KVM_RISCV_SBI_UNEXP,
		  KVM_RISCV_SBI_EXT);
}

// SBI PMU extension calls.
#define SBI_EXT_PMU 0x504D55
#define SBI_EXT_PMU_NUM_COUNTERS 0
#define SBI_EXT_PMU_COUNTER_GET_INFO 1
#define SBI_EXT_PMU_COUNTER_CFG_MATCH 2
#define SBI_EXT_PMU_COUNTER_START 3
#define SBI_EXT_PMU_COUNTER_STOP 4
#define SBI_EXT_PMU_COUNTER_FW_READ 5
#define SBI_EXT_PMU_COUNTER_FW_READ_HI 6
#define SBI_EXT_PMU_SNAPSHOT_SET_SHMEM 7
#define SBI_EXT_PMU_EVENT_GET_INFO 8

GUEST_CODE static noinline void guest_handle_sbi_pmu_num_ctrs(void)
{
	sbi_ecall(0, 0, 0, 0, 0, 0,
		  SBI_EXT_PMU_NUM_COUNTERS, SBI_EXT_PMU);
}

GUEST_CODE static noinline void guest_handle_sbi_pmu_ctr_info(uint64 ctr_idx)
{
	sbi_ecall(ctr_idx, 0, 0, 0, 0, 0,
		  SBI_EXT_PMU_COUNTER_GET_INFO, SBI_EXT_PMU);
}

GUEST_CODE static noinline void
guest_handle_sbi_pmu_ctr_cfg_match(uint64 cbase, uint64 cmask,
				   uint64 cflags, uint64 event)
{
	sbi_ecall(cbase, cmask, cflags, event, 0, 0,
		  SBI_EXT_PMU_COUNTER_CFG_MATCH, SBI_EXT_PMU);
}

GUEST_CODE static noinline void
guest_handle_sbi_pmu_ctr_start(uint64 ctr_base, uint64 ctr_mask,
			       uint64 flags, uint64 ival)
{
	sbi_ecall(ctr_base, ctr_mask, flags, ival, 0, 0,
		  SBI_EXT_PMU_COUNTER_START, SBI_EXT_PMU);
}

GUEST_CODE static noinline void
guest_handle_sbi_pmu_ctr_stop(uint64 ctr_base, uint64 ctr_mask, uint64 flags)
{
	sbi_ecall(ctr_base, ctr_mask, flags, 0, 0, 0,
		  SBI_EXT_PMU_COUNTER_STOP, SBI_EXT_PMU);
}

GUEST_CODE static noinline void guest_handle_sbi_pmu_fw_ctr_read(uint64 ctr_idx)
{
	sbi_ecall(ctr_idx, 0, 0, 0, 0, 0,
		  SBI_EXT_PMU_COUNTER_FW_READ, SBI_EXT_PMU);
}

GUEST_CODE static noinline void
guest_handle_sbi_pmu_snapshot_set_shmem(uint64 gpa_lo, uint64 gpa_hi, uint64 flags)
{
	sbi_ecall(gpa_lo, gpa_hi, flags, 0, 0, 0,
		  SBI_EXT_PMU_SNAPSHOT_SET_SHMEM, SBI_EXT_PMU);
}

// SBI STA (Steal Time Accounting) extension.
#define SBI_EXT_STA                      0x535441
#define SBI_EXT_STA_STEAL_TIME_SET_SHMEM 0

GUEST_CODE static noinline void
guest_handle_sbi_sta_set_shmem(uint64 gpa_lo, uint64 gpa_hi, uint64 flags)
{
	sbi_ecall(gpa_lo, gpa_hi, flags, 0, 0, 0,
		  SBI_EXT_STA_STEAL_TIME_SET_SHMEM, SBI_EXT_STA);
}

GUEST_CODE static noinline void guest_handle_memwrite(struct api_call_memwrite* cmd)
{
	uint64 dest = cmd->base_addr + cmd->offset;
	switch (cmd->len) {
	case 1: {
		volatile uint8* p = (uint8*)dest;
		*p = (uint8)cmd->value;
		break;
	}

	case 2: {
		volatile uint16* p = (uint16*)dest;
		*p = (uint16)cmd->value;
		break;
	}
	case 4: {
		volatile uint32* p = (uint32*)dest;
		*p = (uint32)cmd->value;
		break;
	}
	case 8:
	default: {
		volatile uint64* p = (uint64*)dest;
		*p = (uint64)cmd->value;
		break;
	}
	}
}

GUEST_CODE static noinline void
guest_handle_memread(struct api_call_memread* cmd)
{
    uint64 addr = cmd->base_addr + cmd->offset;
    volatile uint64 val = 0;

    switch (cmd->len) {
    case 1: {
        volatile uint8* p = (uint8*)addr;
        val = *p;
        break;
    }
    case 2: {
        volatile uint16* p = (uint16*)addr;
        val = *p;
        break;
    }
    case 4: {
        volatile uint32* p = (uint32*)addr;
        val = *p;
        break;
    }
    case 8:
    default: {
        volatile uint64* p = (uint64*)addr;
        val = *p;
        break;
    }
    }

    // 防止优化：制造副作用
    asm volatile("" :: "r"(val) : "memory");
}

GUEST_CODE static noinline void guest_handle_ecall(uint64 a0, uint64 a1,
                                                   uint64 a2, uint64 a3,
                                                   uint64 a4, uint64 a5,
												   uint64 a6, uint64 a7)
{
    register uint64 ra0 asm("a0") = a0;
    register uint64 ra1 asm("a1") = a1;
    register uint64 ra2 asm("a2") = a2;
    register uint64 ra3 asm("a3") = a3;
    register uint64 ra4 asm("a4") = a4;
    register uint64 ra5 asm("a5") = a5;
    register uint64 ra6 asm("a6") = a6;
    register uint64 ra7 asm("a7") = a7;

    asm volatile(
        "ecall"
        : "+r"(ra0)
        : "r"(ra1), "r"(ra2), "r"(ra3), "r"(ra4), "r"(ra5), "r"(ra6), "r"(ra7)
        : "memory");
}

GUEST_CODE static noinline void guest_handle_ret(uint64 unused)
{
    uint64 hstatus;

    asm volatile("csrr %0, hstatus" : "=r"(hstatus));

    if (hstatus & (1ULL << 7)) {
        asm volatile("hret" ::: "memory");
    }

    asm volatile("sret" ::: "memory");
}

enum {
    SYZOS_BARRIER_MB = 0,
    SYZOS_BARRIER_RMB = 1,
    SYZOS_BARRIER_WMB = 2,
	SYZOS_BARRIER_SMP_MB = 3,
	SYZOS_BARRIER_SMP_RMB = 4,
	SYZOS_BARRIER_SMP_WMB = 5
};

GUEST_CODE static noinline void guest_handle_barrier(uint64 type)
{
    if (type == SYZOS_BARRIER_MB) {
        asm volatile("fence iorw, iorw" ::: "memory");
    }

    if (type == SYZOS_BARRIER_RMB) {
        asm volatile("fence ir, ir" ::: "memory");
    }

    if (type == SYZOS_BARRIER_WMB) {
        asm volatile("fence ow, ow" ::: "memory");
    }

    if (type == SYZOS_BARRIER_SMP_MB) {
        asm volatile("fence rw, rw" ::: "memory");
    }

    if (type == SYZOS_BARRIER_SMP_RMB) {
        asm volatile("fence r, r" ::: "memory");
    }

    if (type == SYZOS_BARRIER_SMP_WMB) {
        asm volatile("fence w, w" ::: "memory");
    }

    if (type == 0 || type > SYZOS_BARRIER_SMP_WMB) {
        asm volatile("fence iorw, iorw" ::: "memory");
    }
}

GUEST_CODE static noinline void
guest_handle_sbi_generic(uint64 a0, uint64 a1,
			 uint64 a2, uint64 a3,
			 uint64 a4, uint64 a5,
			 uint64 fid, uint64 ext)
{
	sbi_ecall(a0, a1, a2, a3, a4, a5, fid, ext);
}

#endif // EXECUTOR_COMMON_KVM_RISCV64_SYZOS_H