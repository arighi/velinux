// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include <asm/sgx.h>

#include "cpuid.h"
#include "kvm_cache_regs.h"
#include "nested.h"
#include "sgx.h"
#include "vmx.h"
#include "x86.h"

bool __read_mostly enable_sgx = 1;
module_param_named(sgx, enable_sgx, bool, 0444);

static inline bool encls_leaf_enabled_in_guest(struct kvm_vcpu *vcpu, u32 leaf)
{
	if (!enable_sgx || !guest_cpuid_has(vcpu, X86_FEATURE_SGX))
		return false;

	if (leaf >= ECREATE && leaf <= ETRACK)
		return guest_cpuid_has(vcpu, X86_FEATURE_SGX1);

	if (leaf >= EAUG && leaf <= EMODT)
		return guest_cpuid_has(vcpu, X86_FEATURE_SGX2);

	return false;
}

static inline bool sgx_enabled_in_guest_bios(struct kvm_vcpu *vcpu)
{
	const u64 bits = FEAT_CTL_SGX_ENABLED | FEAT_CTL_LOCKED;

	return (to_vmx(vcpu)->msr_ia32_feature_control & bits) == bits;
}

int handle_encls(struct kvm_vcpu *vcpu)
{
	u32 leaf = (u32)kvm_rax_read(vcpu);

	if (!encls_leaf_enabled_in_guest(vcpu, leaf)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
	} else if (!sgx_enabled_in_guest_bios(vcpu)) {
		kvm_inject_gp(vcpu, 0);
	} else {
		WARN(1, "KVM: unexpected exit on ENCLS[%u]", leaf);
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = EXIT_REASON_ENCLS;
		return 0;
	}
	return 1;
}

/*
 * ECREATE must be intercepted to enforce MISCSELECT, ATTRIBUTES and XFRM
 * restrictions if the guest's allowed-1 settings diverge from hardware.
 */
static bool sgx_intercept_encls_ecreate(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *guest_cpuid;
	u32 eax, ebx, ecx, edx;

	if (!vcpu->kvm->arch.sgx_provisioning_allowed)
		return true;

	guest_cpuid = kvm_find_cpuid_entry(vcpu, 0x12, 0);
	if (!guest_cpuid)
		return true;

	cpuid_count(0x12, 0, &eax, &ebx, &ecx, &edx);
	if (guest_cpuid->ebx != ebx || guest_cpuid->edx != edx)
		return true;

	guest_cpuid = kvm_find_cpuid_entry(vcpu, 0x12, 1);
	if (!guest_cpuid)
		return true;

	cpuid_count(0x12, 1, &eax, &ebx, &ecx, &edx);
	if (guest_cpuid->eax != eax || guest_cpuid->ebx != ebx ||
	    guest_cpuid->ecx != ecx || guest_cpuid->edx != edx)
		return true;

	return false;
}

void vmx_write_encls_bitmap(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	/*
	 * There is no software enable bit for SGX that is virtualized by
	 * hardware, e.g. there's no CR4.SGXE, so when SGX is disabled in the
	 * guest (either by the host or by the guest's BIOS) but enabled in the
	 * host, trap all ENCLS leafs and inject #UD/#GP as needed to emulate
	 * the expected system behavior for ENCLS.
	 */
	u64 bitmap = -1ull;

	/* Nothing to do if hardware doesn't support SGX */
	if (!cpu_has_vmx_encls_vmexit())
		return;

	if (guest_cpuid_has(vcpu, X86_FEATURE_SGX) &&
	    sgx_enabled_in_guest_bios(vcpu)) {
		if (guest_cpuid_has(vcpu, X86_FEATURE_SGX1)) {
			bitmap &= ~GENMASK_ULL(ETRACK, ECREATE);
			if (sgx_intercept_encls_ecreate(vcpu))
				bitmap |= (1 << ECREATE);
		}

		if (guest_cpuid_has(vcpu, X86_FEATURE_SGX2))
			bitmap &= ~GENMASK_ULL(EMODT, EAUG);

		/*
		 * Trap and execute EINIT if launch control is enabled in the
		 * host using the guest's values for launch control MSRs, even
		 * if the guest's values are fixed to hardware default values.
		 * The MSRs are not loaded/saved on VM-Enter/VM-Exit as writing
		 * the MSRs is extraordinarily expensive.
		 */
		if (boot_cpu_has(X86_FEATURE_SGX_LC))
			bitmap |= (1 << EINIT);

		if (!vmcs12 && is_guest_mode(vcpu))
			vmcs12 = get_vmcs12(vcpu);
		if (vmcs12 && nested_cpu_has_encls_exit(vmcs12))
			bitmap |= vmcs12->encls_exiting_bitmap;
	}
	vmcs_write64(ENCLS_EXITING_BITMAP, bitmap);
}
