/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include "alignment.h"
#include "bitshift_le.h"
#include "compare.h"
#include "lc_aes_gcm.h"
#include "test_helper_common.h"
#include "visibility.h"

static void det_iv_fill(uint8_t iv[12], const uint8_t fixed[4],
			uint64_t counter)
{
	memcpy(iv, fixed, 4);
	le64_to_ptr(iv + 4, counter);
}

static int lc_aes_gcm_det_iv_test(void)
{
	static const uint8_t aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde,
				       0xad, 0xbe, 0xef, 0xab, 0xad };
	static const uint8_t pt[] = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84,
				      0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
				      0xaf, 0xf5, 0x26, 0x9a };
	static const uint8_t key[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
				       0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				       0x67, 0x30, 0x83, 0x08, 0xfe, 0xff,
				       0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
				       0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
				       0x83, 0x08 };
	static const uint8_t fixed_a[4] = { 0x00, 0x00, 0x00, 0x00 };
	static const uint8_t fixed_b[4] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t iv[12] __align(sizeof(uint32_t));
	uint8_t act_iv[12] __align(sizeof(uint32_t));
	uint8_t ct[sizeof(pt)] __align(sizeof(uint32_t));
	uint8_t dec[sizeof(pt)] __align(sizeof(uint32_t));
	uint8_t tag[16] __align(sizeof(uint32_t));
	int ret = 0;
	LC_AES_GCM_CTX_ON_STACK(aes_gcm);
	LC_AES_GCM_CTX_ON_STACK(aes_gcm_dec);

	/* First use: counter 1 with zero fixed field */
	if (lc_aead_setkey(aes_gcm, key, sizeof(key), NULL, 0))
		return 1;
	det_iv_fill(iv, fixed_a, 1);
	if (lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				   sizeof(act_iv), lc_aes_gcm_iv_deterministic))
		return 1;
	ret += lc_compare(act_iv, iv, sizeof(iv), "AES GCM det IV returned");

	if (lc_aead_encrypt(aes_gcm, pt, ct, sizeof(pt), aad, sizeof(aad), tag,
			    sizeof(tag)))
		return 1;

	/* Decryption with the externally provided IV must work */
	if (lc_aead_setkey(aes_gcm_dec, key, sizeof(key), iv, sizeof(iv)))
		return 1;
	if (lc_aead_decrypt(aes_gcm_dec, ct, dec, sizeof(ct), aad, sizeof(aad),
			    tag, sizeof(tag)))
		return 1;
	ret += lc_compare(dec, pt, sizeof(pt), "AES GCM det IV decrypt");
	lc_aead_zero(aes_gcm_dec);

	/* Counter repetition must be rejected */
	det_iv_fill(iv, fixed_a, 1);
	if (!lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				    sizeof(act_iv),
				    lc_aes_gcm_iv_deterministic)) {
		printf("AES GCM det IV: counter reuse not rejected\n");
		return 1;
	}

	/*
	 * An unused counter within the trailing window is accepted once
	 * (out-of-order encryption pipeline), a second use is rejected.
	 */
	det_iv_fill(iv, fixed_a, 0);
	if (lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				   sizeof(act_iv),
				   lc_aes_gcm_iv_deterministic)) {
		printf("AES GCM det IV: unused window counter rejected\n");
		return 1;
	}
	det_iv_fill(iv, fixed_a, 0);
	if (!lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				    sizeof(act_iv),
				    lc_aes_gcm_iv_deterministic)) {
		printf("AES GCM det IV: window counter reuse not rejected\n");
		return 1;
	}

	/* Fixed field change must be rejected */
	det_iv_fill(iv, fixed_b, 2);
	if (!lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				    sizeof(act_iv),
				    lc_aes_gcm_iv_deterministic)) {
		printf("AES GCM det IV: fixed field change not rejected\n");
		return 1;
	}

	/* A counter far below the window must be rejected as stale */
	det_iv_fill(iv, fixed_a, 100);
	if (lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				   sizeof(act_iv),
				   lc_aes_gcm_iv_deterministic)) {
		printf("AES GCM det IV: window advance rejected\n");
		return 1;
	}
	det_iv_fill(iv, fixed_a, 2);
	if (!lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				    sizeof(act_iv),
				    lc_aes_gcm_iv_deterministic)) {
		printf("AES GCM det IV: stale counter not rejected\n");
		return 1;
	}

	/* Incremented counter with stable fixed field must succeed */
	det_iv_fill(iv, fixed_a, 101);
	if (lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				   sizeof(act_iv), lc_aes_gcm_iv_deterministic))
		return 1;
	if (lc_aead_encrypt(aes_gcm, pt, ct, sizeof(pt), aad, sizeof(aad), tag,
			    sizeof(tag)))
		return 1;

	if (lc_aead_setkey(aes_gcm_dec, key, sizeof(key), iv, sizeof(iv)))
		return 1;
	if (lc_aead_decrypt(aes_gcm_dec, ct, dec, sizeof(ct), aad, sizeof(aad),
			    tag, sizeof(tag)))
		return 1;
	ret += lc_compare(dec, pt, sizeof(pt),
			  "AES GCM det IV decrypt after counter increment");
	lc_aead_zero(aes_gcm_dec);

	lc_aead_zero(aes_gcm);

	/* A fresh context accepts an arbitrary first IV (single-use key) */
	if (lc_aead_setkey(aes_gcm, key, sizeof(key), NULL, 0))
		return 1;
	det_iv_fill(iv, fixed_b, 0xdeadbeefcafeULL);
	if (lc_aes_gcm_generate_iv(aes_gcm, iv, sizeof(iv), act_iv,
				   sizeof(act_iv), lc_aes_gcm_iv_deterministic))
		return 1;
	if (lc_aead_encrypt(aes_gcm, pt, ct, sizeof(pt), aad, sizeof(aad), tag,
			    sizeof(tag)))
		return 1;
	lc_aead_zero(aes_gcm);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return lc_aes_gcm_det_iv_test();
}
