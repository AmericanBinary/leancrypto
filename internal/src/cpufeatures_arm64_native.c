/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "cpufeatures.h"
#include "ext_headers_internal.h"
#include "ext_headers_arm.h"
#include "visibility.h"

#if defined(_WIN32)
#include <windows.h>

/*
 * The SHA-3 and SHA-512 processor feature numbers were added with the
 * Windows 11 24H2 SDK. mingw-w64 headers older than late 2025 (including
 * the llvm-mingw 20250709 toolchain) do not define them, so provide the
 * values from the Windows SDK. IsProcessorFeaturePresent() returns FALSE
 * for feature numbers an older kernel does not know, which leaves the
 * corresponding acceleration disabled instead of faulting.
 */
#ifndef PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE
#define PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE 64
#endif
#ifndef PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE
#define PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE 65
#endif
#endif /* _WIN32 */

/*
 * Read the feature register ID_AA64ISAR0_EL1
 *
 * Purpose: Provides information about the instructions implemented in
 * AArch64 state. For general information about the interpretation of the ID
 * registers, see 'Principles of the ID scheme for fields in ID registers'.
 *
 * Documentation: https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/ID-AA64ISAR0-EL1--AArch64-Instruction-Set-Attribute-Register-0?lang=en
 */
#define ARM8_RNDR_FEATURE (UINT64_C(0xf) << 60)
#define ARM8_SM4_FEATURE (UINT64_C(0xf) << 40)
#define ARM8_SM3_FEATURE (UINT64_C(0xf) << 36)
#define ARM8_SHA3_FEATURE (UINT64_C(0xf) << 32)
#define ARM8_SHA2_FEATURE (UINT64_C(0x11) << 12)
#define ARM8_SHA256_FEATURE (UINT64_C(0x1) << 12) /* SHA256 */
#define ARM8_SHA256512_FEATURE (UINT64_C(0x1) << 13) /* SHA256 and SHA512 */
#define ARM8_SHA1_FEATURE (UINT64_C(0xf) << 8)
#define ARM8_PMULL_FEATURE (UINT64_C(0x1) << 5)
#define ARM8_AES_FEATURE (UINT64_C(0x11) << 4)

static inline unsigned long arm_id_aa64isar0_el1_feature(void)
{
	unsigned long id_aa64isar0_el1_val = 0;

#if (defined(__APPLE__))
	int64_t ret;
	size_t size = sizeof(ret);

	/* Kernel-only support */
	//id_aa64isar0_el1_val = __builtin_arm_rsr64("ID_AA64ISAR0_EL1");

	/*
	 * See https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics
	 */

	/*
	 * There is no corresponding code in leancrypto to warrant those
	 * queries.
	 */
	ret = 0;
	if (!sysctlbyname("hw.optional.arm.FEAT_SHA256", &ret, &size, NULL,
			  0)) {
		if (ret)
			id_aa64isar0_el1_val |= ARM8_SHA256_FEATURE;
	}

	ret = 0;
	if (!sysctlbyname("hw.optional.arm.FEAT_SHA512", &ret, &size, NULL,
			  0)) {
		if (ret)
			id_aa64isar0_el1_val |= ARM8_SHA256512_FEATURE;
	}

	ret = 0;
	if (!sysctlbyname("hw.optional.arm.FEAT_AES", &ret, &size, NULL, 0)) {
		if (ret)
			id_aa64isar0_el1_val |= ARM8_AES_FEATURE;
	}

	ret = 0;
	if (!sysctlbyname("hw.optional.arm.FEAT_SHA3", &ret, &size, NULL, 0)) {
		if (ret)
			id_aa64isar0_el1_val |= ARM8_SHA3_FEATURE;
	}

	ret = 0;
	if (!sysctlbyname("hw.optional.arm.FEAT_PMULL", &ret, &size, NULL, 0)) {
		if (ret)
			id_aa64isar0_el1_val |= ARM8_PMULL_FEATURE;
	}

#elif defined(_WIN32)
	/*
	 * ID_AA64ISAR0_EL1 is an EL1 register. Linux traps and emulates the
	 * MRS from user space, Windows does not and the read raises
	 * STATUS_ILLEGAL_INSTRUCTION (0xC000001D). Ask the kernel instead.
	 */
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE))
		id_aa64isar0_el1_val |= ARM8_SHA256_FEATURE | ARM8_AES_FEATURE |
					ARM8_PMULL_FEATURE;

	if (IsProcessorFeaturePresent(PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE))
		id_aa64isar0_el1_val |= ARM8_SHA256512_FEATURE;

	if (IsProcessorFeaturePresent(PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE))
		id_aa64isar0_el1_val |= ARM8_SHA3_FEATURE;

#else
	__asm__ __volatile__("mrs %0, id_aa64isar0_el1 \n"
			     : "=r"(id_aa64isar0_el1_val));
#endif

	return id_aa64isar0_el1_val;
}

static enum lc_cpu_features features = LC_CPU_FEATURE_UNSET;

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_disable, void)
{
	features = LC_CPU_FEATURE_ARM;
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_enable, void)
{
	features = LC_CPU_FEATURE_UNSET;
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_set, enum lc_cpu_features feature)
{
	features = feature;
}

LC_INTERFACE_FUNCTION(enum lc_cpu_features, lc_cpu_feature_available, void)
{
	if (features == LC_CPU_FEATURE_UNSET) {
		unsigned long id_aa64isar0_el1_val =
			arm_id_aa64isar0_el1_feature();

		features = LC_CPU_FEATURE_ARM | LC_CPU_FEATURE_ARM_NEON;

		if (id_aa64isar0_el1_val & ARM8_AES_FEATURE)
			features |= LC_CPU_FEATURE_ARM_AES;

		if (id_aa64isar0_el1_val & ARM8_SHA256_FEATURE)
			features |= LC_CPU_FEATURE_ARM_SHA2;

		if (id_aa64isar0_el1_val & ARM8_SHA256512_FEATURE)
			features |= LC_CPU_FEATURE_ARM_SHA2_512;

		if (id_aa64isar0_el1_val & ARM8_SHA3_FEATURE)
			features |= LC_CPU_FEATURE_ARM_SHA3;

		if (id_aa64isar0_el1_val & ARM8_PMULL_FEATURE)
			features |= LC_CPU_FEATURE_ARM_PMULL;
	}

	return features;
}
