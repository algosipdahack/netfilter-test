//
// from : suricata-4.1.8.tar.gz > src > util_spm_bm.c
// modified by gilgil
//

#include "bm.h"
#include <stdlib.h>
#include <stdio.h>

static int PreBmGs(const uint8_t *x, uint16_t m, uint16_t *bmGs);
static void PreBmBc(const uint8_t *x, uint16_t m, uint16_t *bmBc);


BmCtx *BoyerMooreCtxInit(const uint8_t *needle, uint16_t needle_len)
{
	BmCtx *new = malloc(sizeof(BmCtx));

	/* Prepare bad chars */
	PreBmBc(needle, needle_len, new->bmBc);

	new->bmGs = malloc(sizeof(uint16_t) * (needle_len + 1));

	/* Prepare good Suffixes */
	PreBmGs(needle, needle_len, new->bmGs);

	return new;
}


void BoyerMooreCtxDeInit(BmCtx *bmctx)
{
	if (bmctx == NULL)
		return;

	if (bmctx->bmGs != NULL)
		free(bmctx->bmGs);

	free(bmctx);
}

static void PreBmBc(const uint8_t *x, uint16_t m, uint16_t *bmBc)
{
	int32_t i;

	for (i = 0; i < 256; ++i) {
		bmBc[i] = m;
	}
	for (i = 0; i < m - 1; ++i) {
		bmBc[(unsigned char)x[i]] = m - i - 1;
	}
}


static void BoyerMooreSuffixes(const uint8_t *x, uint16_t m, uint16_t *suff)
{
	int32_t f = 0, g, i;
	suff[m - 1] = m;
	g = m - 1;
	for (i = m - 2; i >= 0; --i) {
		if (i > g && suff[i + m - 1 - f] < i - g)
			suff[i] = suff[i + m - 1 - f];
		else {
			if (i < g)
				g = i;
			f = i;
			while (g >= 0 && x[g] == x[g + m - 1 - f])
				--g;
			suff[i] = f - g;
		}
	}
}

static int PreBmGs(const uint8_t *x, uint16_t m, uint16_t *bmGs)
{
	int32_t i, j;
	uint16_t suff[m + 1];

	BoyerMooreSuffixes(x, m, suff);

	for (i = 0; i < m; ++i)
		bmGs[i] = m;

	j = 0;

	for (i = m - 1; i >= -1; --i)
		if (i == -1 || suff[i] == i + 1)
			for (; j < m - 1 - i; ++j)
				if (bmGs[j] == m)
					bmGs[j] = m - 1 - i;

	for (i = 0; i <= m - 2; ++i)
		bmGs[m - 1 - suff[i]] = m - 1 - i;
	return 0;
}

uint8_t *BoyerMoore(const uint8_t *x, uint16_t m, const uint8_t *y, uint32_t n, BmCtx *bm_ctx)
{
	uint16_t *bmGs = bm_ctx->bmGs;
	uint16_t *bmBc = bm_ctx->bmBc;

	int i, j, m1, m2;
	int32_t int_n;
#if 0
	printf("\nBad:\n");
	for (i=0;i<ALPHABET_SIZE;i++)
		printf("%c,%d ", i, bmBc[i]);

	printf("\ngood:\n");
	for (i=0;i<m;i++)
		printf("%c, %d ", x[i],bmBc[i]);
	printf("\n");
#endif
	// force casting to int32_t (if possible)
	int_n = (n > INT32_MAX) ? INT32_MAX : n;
	j = 0;
	while (j <= int_n - m ) {
		for (i = m - 1; i >= 0 && x[i] == y[i + j]; --i);

		if (i < 0) {
			return (uint8_t *)(y + j);
		} else {
			m1 = bmGs[i];
			m2 = bmBc[y[i + j]] - m + 1 + i;
			//printf("index=%d BC=%d GS=%d\n", j, m2, m1);
			j += m1 > m2 ? m1: m2;
		}
	}
	return NULL;
}

