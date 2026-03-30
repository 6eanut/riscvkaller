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
	SYZOS_API_SBI_BASE   = 800,
	SYZOS_API_SBI_TIME   = 900,
	SYZOS_API_SBI_IPI    = 1000,
	SYZOS_API_SBI_RFENCE = 1100,
	SYZOS_API_SBI_HSM    = 1200,
	SYZOS_API_SBI_SRST   = 1300,
	SYZOS_API_SBI_SUSP   = 1400,
	SYZOS_API_SBI_DBCN   = 1500,
	SYZOS_API_SBI_NACL   = 1600,
	SYZOS_API_SBI_FWFT   = 1700,
	SYZOS_API_SBI_MPXY   = 1800,
	SYZOS_API_SBI_DBTR   = 1900,
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

// BASE (0x10): fids 0-6, a0 used only for PROBE_EXT (fid=3).
struct api_call_sbi_base {
	struct api_call_header header;
	uint64 fid;
	uint64 a0; // ext_id for PROBE_EXT; ignored for others
};

// TIME (0x54494D45): fid always 0 (SET_TIMER), a0 = stime_value.
struct api_call_sbi_time {
	struct api_call_header header;
	uint64 stime;
};

// IPI (0x735049): fid always 0 (SEND_IPI).
struct api_call_sbi_ipi {
	struct api_call_header header;
	uint64 hart_mask;
	uint64 hart_mask_base;
};

// RFENCE (0x52464E43): fids 0-6, up to 5 args.
struct api_call_sbi_rfence {
	struct api_call_header header;
	uint64 fid;
	uint64 hart_mask;
	uint64 hart_mask_base;
	uint64 start_addr;
	uint64 size;
	uint64 aux; // asid or vmid depending on fid
};

// HSM (0x48534D): fids 0-3.
struct api_call_sbi_hsm {
	struct api_call_header header;
	uint64 fid;
	uint64 a0; // hartid / suspend_type
	uint64 a1; // start_addr / resume_addr
	uint64 a2; // opaque
};

// SRST (0x53525354): fid always 0 (RESET).
struct api_call_sbi_srst {
	struct api_call_header header;
	uint64 reset_type;
	uint64 reset_reason;
};

// SUSP (0x53555350): fid always 0 (SYSTEM_SUSPEND).
struct api_call_sbi_susp {
	struct api_call_header header;
	uint64 sleep_type;
	uint64 resume_addr;
	uint64 opaque;
};

// DBCN (0x4442434E): fids 0-2.
struct api_call_sbi_dbcn {
	struct api_call_header header;
	uint64 fid;
	uint64 a0; // num_bytes or byte value
	uint64 a1; // base_addr_lo
	uint64 a2; // base_addr_hi
};

// NACL (0x4E41434C): fids 0-4.
struct api_call_sbi_nacl {
	struct api_call_header header;
	uint64 fid;
	uint64 a0;
	uint64 a1;
};

// FWFT (0x46574654): fid 0 (SET) or 1 (GET).
struct api_call_sbi_fwft {
	struct api_call_header header;
	uint64 fid;
	uint64 feature;
	uint64 value; // only for SET (fid=0)
	uint64 flags; // only for SET (fid=0)
};

// MPXY (0x4D505859): fids 0-7.
struct api_call_sbi_mpxy {
	struct api_call_header header;
	uint64 fid;
	uint64 a0;
	uint64 a1;
	uint64 a2;
	uint64 a3;
	uint64 a4;
};

// DBTR (0x44425452): fids 0-7.
struct api_call_sbi_dbtr {
	struct api_call_header header;
	uint64 fid;
	uint64 a0;
	uint64 a1;
	uint64 a2;
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
GUEST_CODE static void guest_handle_sbi_base(uint64 fid, uint64 a0);
GUEST_CODE static void guest_handle_sbi_time(uint64 stime);
GUEST_CODE static void guest_handle_sbi_ipi(uint64 hart_mask, uint64 hart_mask_base);
GUEST_CODE static void guest_handle_sbi_rfence(uint64 fid, uint64 hart_mask, uint64 hart_mask_base, uint64 start_addr, uint64 size, uint64 aux);
GUEST_CODE static void guest_handle_sbi_hsm(uint64 fid, uint64 a0, uint64 a1, uint64 a2);
GUEST_CODE static void guest_handle_sbi_srst(uint64 reset_type, uint64 reset_reason);
GUEST_CODE static void guest_handle_sbi_susp(uint64 sleep_type, uint64 resume_addr, uint64 opaque);
GUEST_CODE static void guest_handle_sbi_dbcn(uint64 fid, uint64 a0, uint64 a1, uint64 a2);
GUEST_CODE static void guest_handle_sbi_nacl(uint64 fid, uint64 a0, uint64 a1);
GUEST_CODE static void guest_handle_sbi_fwft(uint64 fid, uint64 feature, uint64 value, uint64 flags);
GUEST_CODE static void guest_handle_sbi_mpxy(uint64 fid, uint64 a0, uint64 a1, uint64 a2, uint64 a3, uint64 a4);
GUEST_CODE static void guest_handle_sbi_dbtr(uint64 fid, uint64 a0, uint64 a1, uint64 a2);

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
		} else if (call == SYZOS_API_SBI_BASE) {
			// SBI BASE extension: version/probe queries.
			struct api_call_sbi_base* ccmd = (struct api_call_sbi_base*)cmd;
			guest_handle_sbi_base(ccmd->fid, ccmd->a0);
		} else if (call == SYZOS_API_SBI_TIME) {
			// SBI TIME extension: set timer.
			struct api_call_sbi_time* ccmd = (struct api_call_sbi_time*)cmd;
			guest_handle_sbi_time(ccmd->stime);
		} else if (call == SYZOS_API_SBI_IPI) {
			// SBI IPI extension: send IPI to hart mask.
			struct api_call_sbi_ipi* ccmd = (struct api_call_sbi_ipi*)cmd;
			guest_handle_sbi_ipi(ccmd->hart_mask, ccmd->hart_mask_base);
		} else if (call == SYZOS_API_SBI_RFENCE) {
			// SBI RFENCE extension: remote fence operations.
			struct api_call_sbi_rfence* ccmd = (struct api_call_sbi_rfence*)cmd;
			guest_handle_sbi_rfence(ccmd->fid, ccmd->hart_mask,
						ccmd->hart_mask_base,
						ccmd->start_addr, ccmd->size,
						ccmd->aux);
		} else if (call == SYZOS_API_SBI_HSM) {
			// SBI HSM extension: hart state management.
			struct api_call_sbi_hsm* ccmd = (struct api_call_sbi_hsm*)cmd;
			guest_handle_sbi_hsm(ccmd->fid, ccmd->a0, ccmd->a1, ccmd->a2);
		} else if (call == SYZOS_API_SBI_SRST) {
			// SBI SRST extension: system reset.
			struct api_call_sbi_srst* ccmd = (struct api_call_sbi_srst*)cmd;
			guest_handle_sbi_srst(ccmd->reset_type, ccmd->reset_reason);
		} else if (call == SYZOS_API_SBI_SUSP) {
			// SBI SUSP extension: system suspend.
			struct api_call_sbi_susp* ccmd = (struct api_call_sbi_susp*)cmd;
			guest_handle_sbi_susp(ccmd->sleep_type, ccmd->resume_addr,
					      ccmd->opaque);
		} else if (call == SYZOS_API_SBI_DBCN) {
			// SBI DBCN extension: debug console I/O.
			struct api_call_sbi_dbcn* ccmd = (struct api_call_sbi_dbcn*)cmd;
			guest_handle_sbi_dbcn(ccmd->fid, ccmd->a0, ccmd->a1, ccmd->a2);
		} else if (call == SYZOS_API_SBI_NACL) {
			// SBI NACL extension: nested acceleration.
			struct api_call_sbi_nacl* ccmd = (struct api_call_sbi_nacl*)cmd;
			guest_handle_sbi_nacl(ccmd->fid, ccmd->a0, ccmd->a1);
		} else if (call == SYZOS_API_SBI_FWFT) {
			// SBI FWFT extension: firmware feature set/get.
			struct api_call_sbi_fwft* ccmd = (struct api_call_sbi_fwft*)cmd;
			guest_handle_sbi_fwft(ccmd->fid, ccmd->feature,
					      ccmd->value, ccmd->flags);
		} else if (call == SYZOS_API_SBI_MPXY) {
			// SBI MPXY extension: message proxy.
			struct api_call_sbi_mpxy* ccmd = (struct api_call_sbi_mpxy*)cmd;
			guest_handle_sbi_mpxy(ccmd->fid, ccmd->a0, ccmd->a1,
					      ccmd->a2, ccmd->a3, ccmd->a4);
		} else if (call == SYZOS_API_SBI_DBTR) {
			// SBI DBTR extension: debug triggers.
			struct api_call_sbi_dbtr* ccmd = (struct api_call_sbi_dbtr*)cmd;
			guest_handle_sbi_dbtr(ccmd->fid, ccmd->a0, ccmd->a1, ccmd->a2);
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

// ---- SBI BASE ----
#define SBI_EXT_BASE 0x10

GUEST_CODE static noinline void
guest_handle_sbi_base(uint64 fid, uint64 a0)
{
	sbi_ecall(a0, 0, 0, 0, 0, 0, fid, SBI_EXT_BASE);
}

// ---- SBI TIME ----
#define SBI_EXT_TIME          0x54494D45
#define SBI_EXT_TIME_SET_TIMER 0

GUEST_CODE static noinline void
guest_handle_sbi_time(uint64 stime)
{
	sbi_ecall(stime, 0, 0, 0, 0, 0,
		  SBI_EXT_TIME_SET_TIMER, SBI_EXT_TIME);
}

// ---- SBI IPI ----
#define SBI_EXT_IPI          0x735049
#define SBI_EXT_IPI_SEND_IPI 0

GUEST_CODE static noinline void
guest_handle_sbi_ipi(uint64 hart_mask, uint64 hart_mask_base)
{
	sbi_ecall(hart_mask, hart_mask_base, 0, 0, 0, 0,
		  SBI_EXT_IPI_SEND_IPI, SBI_EXT_IPI);
}

// ---- SBI RFENCE ----
#define SBI_EXT_RFENCE                       0x52464E43
#define SBI_EXT_RFENCE_REMOTE_FENCE_I        0
#define SBI_EXT_RFENCE_REMOTE_SFENCE_VMA     1
#define SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID 2
#define SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID 3
#define SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA    4
#define SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID 5
#define SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA    6

GUEST_CODE static noinline void
guest_handle_sbi_rfence(uint64 fid, uint64 hart_mask, uint64 hart_mask_base,
			uint64 start_addr, uint64 size, uint64 aux)
{
	// aux = asid for SFENCE_VMA_ASID/HFENCE_VVMA_ASID,
	//       vmid for HFENCE_GVMA_VMID, ignored otherwise.
	sbi_ecall(hart_mask, hart_mask_base, start_addr, size, aux, 0,
		  fid, SBI_EXT_RFENCE);
}

// ---- SBI HSM ----
#define SBI_EXT_HSM              0x48534D
#define SBI_EXT_HSM_HART_START   0
#define SBI_EXT_HSM_HART_STOP    1
#define SBI_EXT_HSM_HART_STATUS  2
#define SBI_EXT_HSM_HART_SUSPEND 3

GUEST_CODE static noinline void
guest_handle_sbi_hsm(uint64 fid, uint64 a0, uint64 a1, uint64 a2)
{
	sbi_ecall(a0, a1, a2, 0, 0, 0, fid, SBI_EXT_HSM);
}

// ---- SBI SRST ----
#define SBI_EXT_SRST       0x53525354
#define SBI_EXT_SRST_RESET 0

GUEST_CODE static noinline void
guest_handle_sbi_srst(uint64 reset_type, uint64 reset_reason)
{
	sbi_ecall(reset_type, reset_reason, 0, 0, 0, 0,
		  SBI_EXT_SRST_RESET, SBI_EXT_SRST);
}

// ---- SBI SUSP ----
#define SBI_EXT_SUSP                  0x53555350
#define SBI_EXT_SUSP_SYSTEM_SUSPEND   0

GUEST_CODE static noinline void
guest_handle_sbi_susp(uint64 sleep_type, uint64 resume_addr, uint64 opaque)
{
	sbi_ecall(sleep_type, resume_addr, opaque, 0, 0, 0,
		  SBI_EXT_SUSP_SYSTEM_SUSPEND, SBI_EXT_SUSP);
}

// ---- SBI DBCN ----
#define SBI_EXT_DBCN                    0x4442434E
#define SBI_EXT_DBCN_CONSOLE_WRITE      0
#define SBI_EXT_DBCN_CONSOLE_READ       1
#define SBI_EXT_DBCN_CONSOLE_WRITE_BYTE 2

GUEST_CODE static noinline void
guest_handle_sbi_dbcn(uint64 fid, uint64 a0, uint64 a1, uint64 a2)
{
	sbi_ecall(a0, a1, a2, 0, 0, 0, fid, SBI_EXT_DBCN);
}

// ---- SBI NACL ----
#define SBI_EXT_NACL               0x4E41434C
#define SBI_EXT_NACL_PROBE_FEATURE 0
#define SBI_EXT_NACL_SET_SHMEM     1
#define SBI_EXT_NACL_SYNC_CSR      2
#define SBI_EXT_NACL_SYNC_HFENCE   3
#define SBI_EXT_NACL_SYNC_SRET     4

GUEST_CODE static noinline void
guest_handle_sbi_nacl(uint64 fid, uint64 a0, uint64 a1)
{
	sbi_ecall(a0, a1, 0, 0, 0, 0, fid, SBI_EXT_NACL);
}

// ---- SBI FWFT ----
#define SBI_EXT_FWFT     0x46574654
#define SBI_EXT_FWFT_SET 0
#define SBI_EXT_FWFT_GET 1

GUEST_CODE static noinline void
guest_handle_sbi_fwft(uint64 fid, uint64 feature, uint64 value, uint64 flags)
{
	// For GET (fid=1) value and flags are unused by the firmware, but we
	// pass them anyway; the firmware ignores extra registers.
	sbi_ecall(feature, value, flags, 0, 0, 0, fid, SBI_EXT_FWFT);
}

// ---- SBI MPXY ----
#define SBI_EXT_MPXY                         0x4D505859
#define SBI_EXT_MPXY_GET_SHMEM_SIZE          0
#define SBI_EXT_MPXY_SET_SHMEM               1
#define SBI_EXT_MPXY_GET_CHANNEL_IDS         2
#define SBI_EXT_MPXY_READ_ATTRS              3
#define SBI_EXT_MPXY_WRITE_ATTRS             4
#define SBI_EXT_MPXY_SEND_MSG_WITH_RESP      5
#define SBI_EXT_MPXY_SEND_MSG_WITHOUT_RESP   6
#define SBI_EXT_MPXY_GET_NOTIFICATION_EVENTS 7

GUEST_CODE static noinline void
guest_handle_sbi_mpxy(uint64 fid, uint64 a0, uint64 a1,
		      uint64 a2, uint64 a3, uint64 a4)
{
	sbi_ecall(a0, a1, a2, a3, a4, 0, fid, SBI_EXT_MPXY);
}

// ---- SBI DBTR ----
#define SBI_EXT_DBTR                0x44425452
#define SBI_EXT_DBTR_NUM_TRIGGERS   0
#define SBI_EXT_DBTR_SETUP_SHMEM    1
#define SBI_EXT_DBTR_TRIG_READ      2
#define SBI_EXT_DBTR_TRIG_INSTALL   3
#define SBI_EXT_DBTR_TRIG_UPDATE    4
#define SBI_EXT_DBTR_TRIG_UNINSTALL 5
#define SBI_EXT_DBTR_TRIG_ENABLE    6
#define SBI_EXT_DBTR_TRIG_DISABLE   7

GUEST_CODE static noinline void
guest_handle_sbi_dbtr(uint64 fid, uint64 a0, uint64 a1, uint64 a2)
{
	sbi_ecall(a0, a1, a2, 0, 0, 0, fid, SBI_EXT_DBTR);
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