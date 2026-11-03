/*
 * Copyright (C) 2026, Ambit Inc, DBA American Binary
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

/*
 * lc_kyber_enc_rng: encapsulation draws its randomness from the given RNG
 * (two identically seeded RNGs give identical ciphertexts, a different RNG
 * a different one), NULL selects lc_seeded_rng, and every result decapsulates
 * to the same shared secret.
 */

#include "ext_headers_internal.h"
#include "kyber_type.h"
#include "lc_rng.h"
#include "lc_memcmp_secure.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "small_stack_support.h"
#include "visibility.h"

static int kyber_enc_rng_tester(void)
{
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;
		struct lc_kyber_ct ct1, ct2, ct3;
		struct lc_kyber_ss ss1, ss2, ss3, ssd;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(rng_a);
	LC_SELFTEST_DRNG_CTX_ON_STACK(rng_b);

	CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, lc_seeded_rng));

	CKINT(lc_kyber_enc_rng(&ws->ct1, &ws->ss1, &ws->pk, rng_a));
	CKINT(lc_kyber_enc_rng(&ws->ct2, &ws->ss2, &ws->pk, rng_b));
	if (memcmp(&ws->ct1, &ws->ct2, sizeof(ws->ct1)) ||
	    memcmp(&ws->ss1, &ws->ss2, sizeof(ws->ss1))) {
		printf("identically seeded RNGs gave different results\n");
		ret = -EFAULT;
		goto out;
	}

	CKINT(lc_kyber_enc_rng(&ws->ct3, &ws->ss3, &ws->pk, NULL));
	if (!memcmp(&ws->ct1, &ws->ct3, sizeof(ws->ct1))) {
		printf("NULL RNG reproduced the self-test RNG's ciphertext\n");
		ret = -EFAULT;
		goto out;
	}

	CKINT(lc_kyber_dec(&ws->ssd, &ws->ct1, &ws->sk));
	if (memcmp(&ws->ssd, &ws->ss1, sizeof(ws->ssd))) {
		printf("decapsulation mismatch (caller RNG)\n");
		ret = -EFAULT;
		goto out;
	}
	CKINT(lc_kyber_dec(&ws->ssd, &ws->ct3, &ws->sk));
	if (memcmp(&ws->ssd, &ws->ss3, sizeof(ws->ssd))) {
		printf("decapsulation mismatch (seeded RNG)\n");
		ret = -EFAULT;
		goto out;
	}
	ret = 0;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kyber_enc_rng_tester();
}
