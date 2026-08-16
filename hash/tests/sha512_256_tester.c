/*
 * Copyright (C) 2020 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "lc_sha512.h"
#include "sha512_arm_ce.h"
#include "sha512_arm_neon.h"
#include "sha512_avx2.h"
#include "sha512_c.h"
#include "sha512_riscv.h"
#include "sha512_riscv_zbb.h"
#include "sha512_shani.h"
#include "test_helper_common.h"
#include "visibility.h"

#define LC_EXEC_ONE_TEST(sha512_256_impl)                                          \
	if (sha512_256_impl)                                                       \
	ret += _sha512_256_tester(sha512_256_impl, #sha512_256_impl)

static int _sha512_256_tester(const struct lc_hash *sha512_256, const char *name)
{
	struct lc_hash_ctx *ctx512_256 = NULL;
	static const uint8_t msg_512_256[] = { 0x61, 0x62, 0x63 };
	static const uint8_t exp_512_256[] = {
		0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E,
		0x29, 0xB7, 0x6B, 0x4C, 0x7D, 0xAB, 0xE4, 0xC2, 0xD0, 0xC6,
		0x34, 0xFC, 0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31, 0x07, 0xE7,
		0xAF, 0x23
	};
	uint8_t act[LC_SHA512_256_SIZE_DIGEST];
	int ret;
	struct lc_hash_ctx ctx2;
	LC_HASH_CTX_ON_STACK(ctx512_256_stack, sha512_256);
	LC_SHA512_256_CTX_ON_STACK(sha512_256_stack);

	printf("hash ctx %s (%s implementation) len %u\n", name,
	       sha512_256 == lc_sha512_256_c ? "C" : "accelerated",
	       (unsigned int)LC_HASH_CTX_SIZE);
	if (lc_hash_init(ctx512_256_stack))
		return 1;
	lc_hash_update(ctx512_256_stack, msg_512_256, sizeof(msg_512_256));
	lc_hash_final(ctx512_256_stack, act);
	ret = lc_compare(act, exp_512_256, LC_SHA512_256_SIZE_DIGEST, "SHA-512/256 1");
	lc_hash_zero(ctx512_256_stack);

	if (lc_hash_alloc(lc_sha512_256, &ctx512_256))
		return 1;
	if (lc_hash_init(ctx512_256)) {
		lc_hash_zero_free(ctx512_256);
		return 1;
	}
	lc_hash_update(ctx512_256, msg_512_256, sizeof(msg_512_256));
	lc_hash_final(ctx512_256, act);
	ret += lc_compare(act, exp_512_256, LC_SHA512_256_SIZE_DIGEST, "SHA-512/256 2");
	lc_hash_zero_free(ctx512_256);

	if (lc_hash_init(sha512_256_stack))
		return 1;
	lc_hash_update(sha512_256_stack, msg_512_256, sizeof(msg_512_256));
	memcpy(&ctx2, sha512_256_stack, sizeof(ctx2));
	lc_hash_set_ctx(sha512_256, &ctx2);
	lc_hash_final(sha512_256_stack, act);
	lc_hash_zero(sha512_256_stack);
	ret += lc_compare(act, exp_512_256, LC_SHA512_256_SIZE_DIGEST, "SHA-512/256 stack");
	lc_hash_final(&ctx2, act);
	lc_hash_zero(&ctx2);
	ret += lc_compare(act, exp_512_256, LC_SHA512_256_SIZE_DIGEST,
			  "SHA-512/256 duplicated context");

	return ret;
}

static int sha512_256_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_sha512_256);
	LC_EXEC_ONE_TEST(lc_sha512_256_c);
	LC_EXEC_ONE_TEST(lc_sha512_256_avx2);
	LC_EXEC_ONE_TEST(lc_sha512_256_shani);
	LC_EXEC_ONE_TEST(lc_sha512_256_arm_ce);
	LC_EXEC_ONE_TEST(lc_sha512_256_arm_neon);
	LC_EXEC_ONE_TEST(lc_sha512_256_riscv);
	LC_EXEC_ONE_TEST(lc_sha512_256_riscv_zbb);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = sha512_256_tester();

	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256), 1);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256_c),
				   lc_sha512_256 == lc_sha512_256_c);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256_avx2),
				   lc_sha512_256 == lc_sha512_256_avx2);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256_shani),
				   lc_sha512_256 == lc_sha512_256_shani);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256_arm_ce),
				   lc_sha512_256 == lc_sha512_256_arm_ce);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256_arm_neon),
				   lc_sha512_256 == lc_sha512_256_arm_neon);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256_riscv),
				   lc_sha512_256 == lc_sha512_256_riscv);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512_256_riscv_zbb),
				   lc_sha512_256 == lc_sha512_256_riscv_zbb);
	ret += test_print_status();
	ret += test_print_status();

	return ret;
}
