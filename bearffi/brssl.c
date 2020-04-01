/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "brssl.h"

static void
dn_append(void *ctx, const void *buf, size_t len)
{
	VEC_ADDMANY(*(bvector *)ctx, buf, len);
}

static int
certificate_to_trust_anchor_inner(br_x509_trust_anchor *ta,
	br_x509_certificate *xc)
{
	br_x509_decoder_context dc;
	bvector vdn = VEC_INIT;
	br_x509_pkey *pk;

	br_x509_decoder_init(&dc, dn_append, &vdn);
	br_x509_decoder_push(&dc, xc->data, xc->data_len);
	pk = br_x509_decoder_get_pkey(&dc);
	if (pk == NULL) {
		fprintf(stderr, "ERROR: CA decoding failed with error %d\n",
			br_x509_decoder_last_error(&dc));
		VEC_CLEAR(vdn);
		return -1;
	}
	ta->dn.data = VEC_TOARRAY(vdn);
	ta->dn.len = VEC_LEN(vdn);
	VEC_CLEAR(vdn);
	ta->flags = 0;
	if (br_x509_decoder_isCA(&dc)) {
		ta->flags |= BR_X509_TA_CA;
	}
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
		ta->pkey.key_type = BR_KEYTYPE_RSA;
		ta->pkey.key.rsa.n = xblobdup(pk->key.rsa.n, pk->key.rsa.nlen);
		ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
		ta->pkey.key.rsa.e = xblobdup(pk->key.rsa.e, pk->key.rsa.elen);
		ta->pkey.key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		ta->pkey.key_type = BR_KEYTYPE_EC;
		ta->pkey.key.ec.curve = pk->key.ec.curve;
		ta->pkey.key.ec.q = xblobdup(pk->key.ec.q, pk->key.ec.qlen);
		ta->pkey.key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		fprintf(stderr, "ERROR: unsupported public key type in CA\n");
		xfree(ta->dn.data);
		return -1;
	}
	return 0;
}

/* see brssl.h */
br_x509_trust_anchor *
certificate_to_trust_anchor(br_x509_certificate *xc)
{
	br_x509_trust_anchor ta;

	if (certificate_to_trust_anchor_inner(&ta, xc) < 0) {
		return NULL;
	} else {
		return xblobdup(&ta, sizeof ta);
	}
}

/* see brssl.h */
void
free_ta_contents(br_x509_trust_anchor *ta)
{
	xfree(ta->dn.data);
	switch (ta->pkey.key_type) {
	case BR_KEYTYPE_RSA:
		xfree(ta->pkey.key.rsa.n);
		xfree(ta->pkey.key.rsa.e);
		break;
	case BR_KEYTYPE_EC:
		xfree(ta->pkey.key.ec.q);
		break;
	}
}

/* see brssl.h */
size_t
read_trust_anchors(anchor_list *dst, const char *fname)
{
	br_x509_certificate *xcs;
	anchor_list tas = VEC_INIT;
	size_t u, num;

	xcs = read_certificates(fname, &num);
	if (xcs == NULL) {
		return 0;
	}
	for (u = 0; u < num; u ++) {
		br_x509_trust_anchor ta;

		if (certificate_to_trust_anchor_inner(&ta, &xcs[u]) < 0) {
			VEC_CLEAREXT(tas, free_ta_contents);
			free_certificates(xcs, num);
			return 0;
		}
		VEC_ADD(tas, ta);
	}
	VEC_ADDMANY(*dst, &VEC_ELT(tas, 0), num);
	VEC_CLEAR(tas);
	free_certificates(xcs, num);
	return num;
}

/* see brssl.h */
int
get_cert_signer_algo(br_x509_certificate *xc)
{
	br_x509_decoder_context dc;
	int err;

	br_x509_decoder_init(&dc, 0, 0);
	br_x509_decoder_push(&dc, xc->data, xc->data_len);
	err = br_x509_decoder_last_error(&dc);
	if (err != 0) {
		fprintf(stderr,
			"ERROR: certificate decoding failed with error %d\n",
			-err);
		return 0;
	}
	return br_x509_decoder_get_signer_key_type(&dc);
}

static void
xwc_start_chain(const br_x509_class **ctx, const char *server_name)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->start_chain(xwc->inner, server_name);
}

static void
xwc_start_cert(const br_x509_class **ctx, uint32_t length)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->start_cert(xwc->inner, length);
}

static void
xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->append(xwc->inner, buf, len);
}

static void
xwc_end_cert(const br_x509_class **ctx)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->end_cert(xwc->inner);
}

static unsigned
xwc_end_chain(const br_x509_class **ctx)
{
	x509_noanchor_context *xwc;
	unsigned r;

	xwc = (x509_noanchor_context *)ctx;
	r = (*xwc->inner)->end_chain(xwc->inner);
	if (r == BR_ERR_X509_NOT_TRUSTED) {
		r = 0;
	}
	return r;
}

static const br_x509_pkey *
xwc_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	return (*xwc->inner)->get_pkey(xwc->inner, usages);
}

/* see brssl.h */
const br_x509_class x509_noanchor_vtable = {
	sizeof(x509_noanchor_context),
	xwc_start_chain,
	xwc_start_cert,
	xwc_append,
	xwc_end_cert,
	xwc_end_chain,
	xwc_get_pkey
};

/* see brssl.h */
void
x509_noanchor_init(x509_noanchor_context *xwc, const br_x509_class **inner)
{
	xwc->vtable = &x509_noanchor_vtable;
	xwc->inner = inner;
}


/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "brssl.h"

/* see brssl.h */
void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "ERROR: could not allocate %lu byte(s)\n",
			(unsigned long)len);
		exit(EXIT_FAILURE);
	}
	return buf;
}

/* see brssl.h */
void
xfree(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

/* see brssl.h */
void *
xblobdup(const void *src, size_t len)
{
	void *buf;

	buf = xmalloc(len);
	memcpy(buf, src, len);
	return buf;
}

/* see brssl.h */
char *
xstrdup(const void *src)
{
	return xblobdup(src, strlen(src) + 1);
}

/* see brssl.h */
br_x509_pkey *
xpkeydup(const br_x509_pkey *pk)
{
	br_x509_pkey *pk2;

	pk2 = xmalloc(sizeof *pk2);
	pk2->key_type = pk->key_type;
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
		pk2->key.rsa.n = xblobdup(pk->key.rsa.n, pk->key.rsa.nlen);
		pk2->key.rsa.nlen = pk->key.rsa.nlen;
		pk2->key.rsa.e = xblobdup(pk->key.rsa.e, pk->key.rsa.elen);
		pk2->key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		pk2->key.ec.curve = pk->key.ec.curve;
		pk2->key.ec.q = xblobdup(pk->key.ec.q, pk->key.ec.qlen);
		pk2->key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		fprintf(stderr, "Unknown public key type: %u\n",
			(unsigned)pk->key_type);
		exit(EXIT_FAILURE);
	}
	return pk2;
}

/* see brssl.h */
void
xfreepkey(br_x509_pkey *pk)
{
	if (pk != NULL) {
		switch (pk->key_type) {
		case BR_KEYTYPE_RSA:
			xfree(pk->key.rsa.n);
			xfree(pk->key.rsa.e);
			break;
		case BR_KEYTYPE_EC:
			xfree(pk->key.ec.q);
			break;
		default:
			fprintf(stderr, "Unknown public key type: %u\n",
				(unsigned)pk->key_type);
			exit(EXIT_FAILURE);
		}
		xfree(pk);
	}
}
/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "brssl.h"

/*
 * Prepare a vector buffer for adding 'extra' elements.
 *   buf      current buffer
 *   esize    size of a vector element
 *   ptr      pointer to the 'ptr' vector field
 *   len      pointer to the 'len' vector field
 *   extra    number of elements to add
 *
 * If the buffer must be enlarged, then this function allocates the new
 * buffer and releases the old one. The new buffer address is then returned.
 * If the buffer needs not be enlarged, then the buffer address is returned.
 *
 * In case of enlargement, the 'len' field is adjusted accordingly. The
 * 'ptr' field is not modified.
 */
void *
vector_expand(void *buf,
	size_t esize, size_t *ptr, size_t *len, size_t extra)
{
	size_t nlen;
	void *nbuf;

	if (*len - *ptr >= extra) {
		return buf;
	}
	nlen = (*len << 1);
	if (nlen - *ptr < extra) {
		nlen = extra + *ptr;
		if (nlen < 8) {
			nlen = 8;
		}
	}
	nbuf = xmalloc(nlen * esize);
	if (buf != NULL) {
		memcpy(nbuf, buf, *len * esize);
		xfree(buf);
	}
	*len = nlen;
	return nbuf;
}
/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "brssl.h"

/* see brssl.h */
unsigned char *
read_file(const char *fname, size_t *len)
{
	bvector vbuf = VEC_INIT;
	FILE *f;

	*len = 0;
	f = fopen(fname, "rb");
	if (f == NULL) {
		fprintf(stderr,
			"ERROR: could not open file '%s' for reading\n", fname);
		return NULL;
	}
	for (;;) {
		unsigned char tmp[1024];
		size_t rlen;

		rlen = fread(tmp, 1, sizeof tmp, f);
		if (rlen == 0) {
			unsigned char *buf;

			if (ferror(f)) {
				fprintf(stderr,
					"ERROR: read error on file '%s'\n",
					fname);
				fclose(f);
				return NULL;
			}
			buf = VEC_TOARRAY(vbuf);
			*len = VEC_LEN(vbuf);
			VEC_CLEAR(vbuf);
			fclose(f);
			return buf;
		}
		VEC_ADDMANY(vbuf, tmp, rlen);
	}
}

/* see brssl.h */
int
write_file(const char *fname, const void *data, size_t len)
{
	FILE *f;
	const unsigned char *buf;

	f = fopen(fname, "wb");
	if (f == NULL) {
		fprintf(stderr,
			"ERROR: could not open file '%s' for reading\n", fname);
		return -1;
	}
	buf = data;
	while (len > 0) {
		size_t wlen;

		wlen = fwrite(buf, 1, len, f);
		if (wlen == 0) {
			fprintf(stderr,
				"ERROR: could not write all bytes to '%s'\n",
				fname);
			fclose(f);
			return -1;
		}
		buf += wlen;
		len -= wlen;
	}
	if (ferror(f)) {
		fprintf(stderr, "ERROR: write error on file '%s'\n", fname);
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* see brssl.h */
int
looks_like_DER(const unsigned char *buf, size_t len)
{
	int fb;
	size_t dlen;

	if (len < 2) {
		return 0;
	}
	if (*buf ++ != 0x30) {
		return 0;
	}
	fb = *buf ++;
	len -= 2;
	if (fb < 0x80) {
		return (size_t)fb == len;
	} else if (fb == 0x80) {
		return 0;
	} else {
		fb -= 0x80;
		if (len < (size_t)fb + 2) {
			return 0;
		}
		len -= (size_t)fb;
		dlen = 0;
		while (fb -- > 0) {
			if (dlen > (len >> 8)) {
				return 0;
			}
			dlen = (dlen << 8) + (size_t)*buf ++;
		}
		return dlen == len;
	}
}

static void
vblob_append(void *cc, const void *data, size_t len)
{
	bvector *bv;

	bv = cc;
	VEC_ADDMANY(*bv, data, len);
}

/* see brssl.h */
void
free_pem_object_contents(pem_object *po)
{
	if (po != NULL) {
		xfree(po->name);
		xfree(po->data);
	}
}

/* see brssl.h */
pem_object *
decode_pem(const void *src, size_t len, size_t *num)
{
	VECTOR(pem_object) pem_list = VEC_INIT;
	br_pem_decoder_context pc;
	pem_object po, *pos;
	const unsigned char *buf;
	bvector bv = VEC_INIT;
	int inobj;
	int extra_nl;

	*num = 0;
	br_pem_decoder_init(&pc);
	buf = src;
	inobj = 0;
	po.name = NULL;
	po.data = NULL;
	po.data_len = 0;
	extra_nl = 1;
	while (len > 0) {
		size_t tlen;

		tlen = br_pem_decoder_push(&pc, buf, len);
		buf += tlen;
		len -= tlen;
		switch (br_pem_decoder_event(&pc)) {

		case BR_PEM_BEGIN_OBJ:
			po.name = xstrdup(br_pem_decoder_name(&pc));
			br_pem_decoder_setdest(&pc, vblob_append, &bv);
			inobj = 1;
			break;

		case BR_PEM_END_OBJ:
			if (inobj) {
				po.data = VEC_TOARRAY(bv);
				po.data_len = VEC_LEN(bv);
				VEC_ADD(pem_list, po);
				VEC_CLEAR(bv);
				po.name = NULL;
				po.data = NULL;
				po.data_len = 0;
				inobj = 0;
			}
			break;

		case BR_PEM_ERROR:
			xfree(po.name);
			VEC_CLEAR(bv);
			fprintf(stderr,
				"ERROR: invalid PEM encoding\n");
			VEC_CLEAREXT(pem_list, &free_pem_object_contents);
			return NULL;
		}

		/*
		 * We add an extra newline at the end, in order to
		 * support PEM files that lack the newline on their last
		 * line (this is somwehat invalid, but PEM format is not
		 * standardised and such files do exist in the wild, so
		 * we'd better accept them).
		 */
		if (len == 0 && extra_nl) {
			extra_nl = 0;
			buf = (const unsigned char *)"\n";
			len = 1;
		}
	}
	if (inobj) {
		fprintf(stderr, "ERROR: unfinished PEM object\n");
		xfree(po.name);
		VEC_CLEAR(bv);
		VEC_CLEAREXT(pem_list, &free_pem_object_contents);
		return NULL;
	}

	*num = VEC_LEN(pem_list);
	VEC_ADD(pem_list, po);
	pos = VEC_TOARRAY(pem_list);
	VEC_CLEAR(pem_list);
	return pos;
}

/* see brssl.h */
br_x509_certificate *
read_certificates(const char *fname, size_t *num)
{
	VECTOR(br_x509_certificate) cert_list = VEC_INIT;
	unsigned char *buf;
	size_t len;
	pem_object *pos;
	size_t u, num_pos;
	br_x509_certificate *xcs;
	br_x509_certificate dummy;

	*num = 0;

	/*
	 * TODO: reading the whole file is crude; we could parse them
	 * in a streamed fashion. But it does not matter much in practice.
	 */
	buf = read_file(fname, &len);
	if (buf == NULL) {
		return NULL;
	}

	/*
	 * Check for a DER-encoded certificate.
	 */
	if (looks_like_DER(buf, len)) {
		xcs = xmalloc(2 * sizeof *xcs);
		xcs[0].data = buf;
		xcs[0].data_len = len;
		xcs[1].data = NULL;
		xcs[1].data_len = 0;
		*num = 1;
		return xcs;
	}

	pos = decode_pem(buf, len, &num_pos);
	xfree(buf);
	if (pos == NULL) {
		return NULL;
	}
	for (u = 0; u < num_pos; u ++) {
		if (eqstr(pos[u].name, "CERTIFICATE")
			|| eqstr(pos[u].name, "X509 CERTIFICATE"))
		{
			br_x509_certificate xc;

			xc.data = pos[u].data;
			xc.data_len = pos[u].data_len;
			pos[u].data = NULL;
			VEC_ADD(cert_list, xc);
		}
	}
	for (u = 0; u < num_pos; u ++) {
		free_pem_object_contents(&pos[u]);
	}
	xfree(pos);

	if (VEC_LEN(cert_list) == 0) {
		fprintf(stderr, "ERROR: no certificate in file '%s'\n", fname);
		return NULL;
	}
	*num = VEC_LEN(cert_list);
	dummy.data = NULL;
	dummy.data_len = 0;
	VEC_ADD(cert_list, dummy);
	xcs = VEC_TOARRAY(cert_list);
	VEC_CLEAR(cert_list);
	return xcs;
}

/* see brssl.h */
void
free_certificates(br_x509_certificate *certs, size_t num)
{
	size_t u;

	for (u = 0; u < num; u ++) {
		xfree(certs[u].data);
	}
	xfree(certs);
}
/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "brssl.h"
#include "bearssl.h"

/* see brssl.h */
const protocol_version protocol_versions[] = {
	{ "tls10", BR_TLS10, "TLS 1.0" },
	{ "tls11", BR_TLS11, "TLS 1.1" },
	{ "tls12", BR_TLS12, "TLS 1.2" },
	{ NULL, 0, NULL }
};

/* see brssl.h */
const hash_function hash_functions[] = {
	{ "md5",     &br_md5_vtable,     "MD5" },
	{ "sha1",    &br_sha1_vtable,    "SHA-1" },
	{ "sha224",  &br_sha224_vtable,  "SHA-224" },
	{ "sha256",  &br_sha256_vtable,  "SHA-256" },
	{ "sha384",  &br_sha384_vtable,  "SHA-384" },
	{ "sha512",  &br_sha512_vtable,  "SHA-512" },
	{ NULL, 0, NULL }
};

/* see brssl.h */
const cipher_suite cipher_suites[] = {
	{
		"ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		REQ_ECDHE_ECDSA | REQ_CHAPOL | REQ_SHA256 | REQ_TLS12,
		"ECDHE with ECDSA, ChaCha20+Poly1305 encryption (TLS 1.2+)"
	},
	{
		"ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		REQ_ECDHE_RSA | REQ_CHAPOL | REQ_SHA256 | REQ_TLS12,
		"ECDHE with RSA, ChaCha20+Poly1305 encryption (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		REQ_ECDHE_ECDSA | REQ_AESGCM | REQ_SHA256 | REQ_TLS12,
		"ECDHE with ECDSA, AES-128/GCM encryption (TLS 1.2+)"
	},
	{
		"ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		REQ_ECDHE_RSA | REQ_AESGCM | REQ_SHA256 | REQ_TLS12,
		"ECDHE with RSA, AES-128/GCM encryption (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		REQ_ECDHE_ECDSA | REQ_AESGCM | REQ_SHA384 | REQ_TLS12,
		"ECDHE with ECDSA, AES-256/GCM encryption (TLS 1.2+)"
	},
	{
		"ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		REQ_ECDHE_RSA | REQ_AESGCM | REQ_SHA384 | REQ_TLS12,
		"ECDHE with RSA, AES-256/GCM encryption (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_128_CCM",
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		REQ_ECDHE_ECDSA | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"ECDHE with ECDSA, AES-128/CCM encryption (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_256_CCM",
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
		REQ_ECDHE_ECDSA | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"ECDHE with ECDSA, AES-256/CCM encryption (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_128_CCM_8",
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		REQ_ECDHE_ECDSA | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"ECDHE with ECDSA, AES-128/CCM_8 encryption (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_256_CCM_8",
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
		REQ_ECDHE_ECDSA | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"ECDHE with ECDSA, AES-256/CCM_8 encryption (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		REQ_ECDHE_ECDSA | REQ_AESCBC | REQ_SHA256 | REQ_TLS12,
		"ECDHE with ECDSA, AES-128/CBC + SHA-256 (TLS 1.2+)"
	},
	{
		"ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		REQ_ECDHE_RSA | REQ_AESCBC | REQ_SHA256 | REQ_TLS12,
		"ECDHE with RSA, AES-128/CBC + SHA-256 (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		REQ_ECDHE_ECDSA | REQ_AESCBC | REQ_SHA384 | REQ_TLS12,
		"ECDHE with ECDSA, AES-256/CBC + SHA-384 (TLS 1.2+)"
	},
	{
		"ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		REQ_ECDHE_RSA | REQ_AESCBC | REQ_SHA384 | REQ_TLS12,
		"ECDHE with RSA, AES-256/CBC + SHA-384 (TLS 1.2+)"
	},
	{
		"ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		REQ_ECDHE_ECDSA | REQ_AESCBC | REQ_SHA1,
		"ECDHE with ECDSA, AES-128/CBC + SHA-1"
	},
	{
		"ECDHE_RSA_WITH_AES_128_CBC_SHA",
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		REQ_ECDHE_RSA | REQ_AESCBC | REQ_SHA1,
		"ECDHE with RSA, AES-128/CBC + SHA-1"
	},
	{
		"ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		REQ_ECDHE_ECDSA | REQ_AESCBC | REQ_SHA1,
		"ECDHE with ECDSA, AES-256/CBC + SHA-1"
	},
	{
		"ECDHE_RSA_WITH_AES_256_CBC_SHA",
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		REQ_ECDHE_RSA | REQ_AESCBC | REQ_SHA1,
		"ECDHE with RSA, AES-256/CBC + SHA-1"
	},
	{
		"ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		REQ_ECDH | REQ_AESGCM | REQ_SHA256 | REQ_TLS12,
		"ECDH key exchange (EC cert), AES-128/GCM (TLS 1.2+)"
	},
	{
		"ECDH_RSA_WITH_AES_128_GCM_SHA256",
		BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		REQ_ECDH | REQ_AESGCM | REQ_SHA256 | REQ_TLS12,
		"ECDH key exchange (RSA cert), AES-128/GCM (TLS 1.2+)"
	},
	{
		"ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
		BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		REQ_ECDH | REQ_AESGCM | REQ_SHA384 | REQ_TLS12,
		"ECDH key exchange (EC cert), AES-256/GCM (TLS 1.2+)"
	},
	{
		"ECDH_RSA_WITH_AES_256_GCM_SHA384",
		BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		REQ_ECDH | REQ_AESGCM | REQ_SHA384 | REQ_TLS12,
		"ECDH key exchange (RSA cert), AES-256/GCM (TLS 1.2+)"
	},
	{
		"ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
		BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		REQ_ECDH | REQ_AESCBC | REQ_SHA256 | REQ_TLS12,
		"ECDH key exchange (EC cert), AES-128/CBC + HMAC/SHA-256 (TLS 1.2+)"
	},
	{
		"ECDH_RSA_WITH_AES_128_CBC_SHA256",
		BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		REQ_ECDH | REQ_AESCBC | REQ_SHA256 | REQ_TLS12,
		"ECDH key exchange (RSA cert), AES-128/CBC + HMAC/SHA-256 (TLS 1.2+)"
	},
	{
		"ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
		BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		REQ_ECDH | REQ_AESCBC | REQ_SHA384 | REQ_TLS12,
		"ECDH key exchange (EC cert), AES-256/CBC + HMAC/SHA-384 (TLS 1.2+)"
	},
	{
		"ECDH_RSA_WITH_AES_256_CBC_SHA384",
		BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		REQ_ECDH | REQ_AESCBC | REQ_SHA384 | REQ_TLS12,
		"ECDH key exchange (RSA cert), AES-256/CBC + HMAC/SHA-384 (TLS 1.2+)"
	},
	{
		"ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		REQ_ECDH | REQ_AESCBC | REQ_SHA1,
		"ECDH key exchange (EC cert), AES-128/CBC + HMAC/SHA-1"
	},
	{
		"ECDH_RSA_WITH_AES_128_CBC_SHA",
		BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		REQ_ECDH | REQ_AESCBC | REQ_SHA1,
		"ECDH key exchange (RSA cert), AES-128/CBC + HMAC/SHA-1"
	},
	{
		"ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		REQ_ECDH | REQ_AESCBC | REQ_SHA1,
		"ECDH key exchange (EC cert), AES-256/CBC + HMAC/SHA-1"
	},
	{
		"ECDH_RSA_WITH_AES_256_CBC_SHA",
		BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		REQ_ECDH | REQ_AESCBC | REQ_SHA1,
		"ECDH key exchange (RSA cert), AES-256/CBC + HMAC/SHA-1"
	},
	{
		"RSA_WITH_AES_128_GCM_SHA256",
		BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
		REQ_RSAKEYX | REQ_AESGCM | REQ_SHA256 | REQ_TLS12,
		"RSA key exchange, AES-128/GCM encryption (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_256_GCM_SHA384",
		BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
		REQ_RSAKEYX | REQ_AESGCM | REQ_SHA384 | REQ_TLS12,
		"RSA key exchange, AES-256/GCM encryption (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_128_CCM",
		BR_TLS_RSA_WITH_AES_128_CCM,
		REQ_RSAKEYX | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"RSA key exchange, AES-128/CCM encryption (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_256_CCM",
		BR_TLS_RSA_WITH_AES_256_CCM,
		REQ_RSAKEYX | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"RSA key exchange, AES-256/CCM encryption (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_128_CCM_8",
		BR_TLS_RSA_WITH_AES_128_CCM_8,
		REQ_RSAKEYX | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"RSA key exchange, AES-128/CCM_8 encryption (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_256_CCM_8",
		BR_TLS_RSA_WITH_AES_256_CCM_8,
		REQ_RSAKEYX | REQ_AESCCM | REQ_SHA256 | REQ_TLS12,
		"RSA key exchange, AES-256/CCM_8 encryption (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_128_CBC_SHA256",
		BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
		REQ_RSAKEYX | REQ_AESCBC | REQ_SHA256 | REQ_TLS12,
		"RSA key exchange, AES-128/CBC + HMAC/SHA-256 (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_256_CBC_SHA256",
		BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
		REQ_RSAKEYX | REQ_AESCBC | REQ_SHA256 | REQ_TLS12,
		"RSA key exchange, AES-256/CBC + HMAC/SHA-256 (TLS 1.2+)"
	},
	{
		"RSA_WITH_AES_128_CBC_SHA",
		BR_TLS_RSA_WITH_AES_128_CBC_SHA,
		REQ_RSAKEYX | REQ_AESCBC | REQ_SHA1,
		"RSA key exchange, AES-128/CBC + HMAC/SHA-1"
	},
	{
		"RSA_WITH_AES_256_CBC_SHA",
		BR_TLS_RSA_WITH_AES_256_CBC_SHA,
		REQ_RSAKEYX | REQ_AESCBC | REQ_SHA1,
		"RSA key exchange, AES-256/CBC + HMAC/SHA-1"
	},
	{
		"ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		REQ_ECDHE_ECDSA | REQ_3DESCBC | REQ_SHA1,
		"ECDHE with ECDSA, 3DES/CBC + SHA-1"
	},
	{
		"ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		REQ_ECDHE_RSA | REQ_3DESCBC | REQ_SHA1,
		"ECDHE with RSA, 3DES/CBC + SHA-1"
	},
	{
		"ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
		REQ_ECDH | REQ_3DESCBC | REQ_SHA1,
		"ECDH key exchange (EC cert), 3DES/CBC + HMAC/SHA-1"
	},
	{
		"ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
		REQ_ECDH | REQ_3DESCBC | REQ_SHA1,
		"ECDH key exchange (RSA cert), 3DES/CBC + HMAC/SHA-1"
	},
	{
		"RSA_WITH_3DES_EDE_CBC_SHA",
		BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		REQ_RSAKEYX | REQ_3DESCBC | REQ_SHA1,
		"RSA key exchange, 3DES/CBC + HMAC/SHA-1"
	},
	{ NULL, 0, 0, NULL }
};

static const struct {
	int id;
	const char *name;
	const char *sid[4];
} curves[] = {
	{ BR_EC_sect163k1,
	  "sect163k1",
	  { "sect163k1", "K-163", NULL, NULL } },
	{ BR_EC_sect163r1,
	  "sect163r1",
	  { "sect163r1", NULL, NULL, NULL } },
	{ BR_EC_sect163r2,
	  "sect163r2",
	  { "sect163r2", "B-163", NULL, NULL } },
	{ BR_EC_sect193r1,
	  "sect193r1",
	  { "sect193r1", NULL, NULL, NULL } },
	{ BR_EC_sect193r2,
	  "sect193r2",
	  { "sect193r2", NULL, NULL, NULL } },
	{ BR_EC_sect233k1,
	  "sect233k1",
	  { "sect233k1", "K-233", NULL, NULL } },
	{ BR_EC_sect233r1,
	  "sect233r1",
	  { "sect233r1", "B-233", NULL, NULL } },
	{ BR_EC_sect239k1,
	  "sect239k1",
	  { "sect239k1", NULL, NULL, NULL } },
	{ BR_EC_sect283k1,
	  "sect283k1",
	  { "sect283k1", "K-283", NULL, NULL } },
	{ BR_EC_sect283r1,
	  "sect283r1",
	  { "sect283r1", "B-283", NULL, NULL } },
	{ BR_EC_sect409k1,
	  "sect409k1",
	  { "sect409k1", "K-409", NULL, NULL } },
	{ BR_EC_sect409r1,
	  "sect409r1",
	  { "sect409r1", "B-409", NULL, NULL } },
	{ BR_EC_sect571k1,
	  "sect571k1",
	  { "sect571k1", "K-571", NULL, NULL } },
	{ BR_EC_sect571r1,
	  "sect571r1",
	  { "sect571r1", "B-571", NULL, NULL } },
	{ BR_EC_secp160k1,
	  "secp160k1",
	  { "secp160k1", NULL, NULL, NULL } },
	{ BR_EC_secp160r1,
	  "secp160r1",
	  { "secp160r1", NULL, NULL, NULL } },
	{ BR_EC_secp160r2,
	  "secp160r2",
	  { "secp160r2", NULL, NULL, NULL } },
	{ BR_EC_secp192k1,
	  "secp192k1",
	  { "secp192k1", NULL, NULL, NULL } },
	{ BR_EC_secp192r1,
	  "secp192r1",
	  { "secp192r1", "P-192", NULL, NULL } },
	{ BR_EC_secp224k1,
	  "secp224k1",
	  { "secp224k1", NULL, NULL, NULL } },
	{ BR_EC_secp224r1,
	  "secp224r1",
	  { "secp224r1", "P-224", NULL, NULL } },
	{ BR_EC_secp256k1,
	  "secp256k1",
	  { "secp256k1", NULL, NULL, NULL } },
	{ BR_EC_secp256r1,
	  "secp256r1 (P-256)",
	  { "secp256r1", "P-256", "prime256v1", NULL } },
	{ BR_EC_secp384r1,
	  "secp384r1 (P-384)",
	  { "secp384r1", "P-384", NULL, NULL } },
	{ BR_EC_secp521r1,
	  "secp521r1 (P-521)",
	  { "secp521r1", "P-521", NULL, NULL } },
	{ BR_EC_brainpoolP256r1,
	  "brainpoolP256r1",
	  { "brainpoolP256r1", NULL, NULL, NULL } },
	{ BR_EC_brainpoolP384r1,
	  "brainpoolP384r1",
	  { "brainpoolP384r1", NULL, NULL, NULL } },
	{ BR_EC_brainpoolP512r1,
	  "brainpoolP512r1",
	  { "brainpoolP512r1", NULL, NULL, NULL } },
	{ BR_EC_curve25519,
	  "Curve25519",
	  { "curve25519", "c25519", NULL, NULL } },
	{ BR_EC_curve448,
	  "Curve448",
	  { "curve448", "c448", NULL, NULL } },
	{ 0, 0, { 0, 0, 0, 0 } }
};

static const struct {
	const char *long_name;
	const char *short_name;
	const void *impl;
} algo_names[] = {
	/* Block ciphers */
	{ "aes_big_cbcenc",    "big",         &br_aes_big_cbcenc_vtable },
	{ "aes_big_cbcdec",    "big",         &br_aes_big_cbcdec_vtable },
	{ "aes_big_ctr",       "big",         &br_aes_big_ctr_vtable },
	{ "aes_big_ctrcbc",    "big",         &br_aes_big_ctrcbc_vtable },
	{ "aes_small_cbcenc",  "small",       &br_aes_small_cbcenc_vtable },
	{ "aes_small_cbcdec",  "small",       &br_aes_small_cbcdec_vtable },
	{ "aes_small_ctr",     "small",       &br_aes_small_ctr_vtable },
	{ "aes_small_ctrcbc",  "small",       &br_aes_small_ctrcbc_vtable },
	{ "aes_ct_cbcenc",     "ct",          &br_aes_ct_cbcenc_vtable },
	{ "aes_ct_cbcdec",     "ct",          &br_aes_ct_cbcdec_vtable },
	{ "aes_ct_ctr",        "ct",          &br_aes_ct_ctr_vtable },
	{ "aes_ct_ctrcbc",     "ct",          &br_aes_ct_ctrcbc_vtable },
	{ "aes_ct64_cbcenc",   "ct64",        &br_aes_ct64_cbcenc_vtable },
	{ "aes_ct64_cbcdec",   "ct64",        &br_aes_ct64_cbcdec_vtable },
	{ "aes_ct64_ctr",      "ct64",        &br_aes_ct64_ctr_vtable },
	{ "aes_ct64_ctrcbc",   "ct64",        &br_aes_ct64_ctrcbc_vtable },

	{ "des_tab_cbcenc",    "tab",         &br_des_tab_cbcenc_vtable },
	{ "des_tab_cbcdec",    "tab",         &br_des_tab_cbcdec_vtable },
	{ "des_ct_cbcenc",     "ct",          &br_des_ct_cbcenc_vtable },
	{ "des_ct_cbcdec",     "ct",          &br_des_ct_cbcdec_vtable },

	{ "chacha20_ct",       "ct",          &br_chacha20_ct_run },

	{ "ghash_ctmul",       "ctmul",       &br_ghash_ctmul },
	{ "ghash_ctmul32",     "ctmul32",     &br_ghash_ctmul32 },
	{ "ghash_ctmul64",     "ctmul64",     &br_ghash_ctmul64 },

	{ "poly1305_ctmul",    "ctmul",       &br_poly1305_ctmul_run },
	{ "poly1305_ctmul32",  "ctmul32",     &br_poly1305_ctmul32_run },

	{ "ec_all_m15",        "all_m15",     &br_ec_all_m15 },
	{ "ec_all_m31",        "all_m31",     &br_ec_all_m31 },
	{ "ec_c25519_i15",     "c25519_i15",  &br_ec_c25519_i15 },
	{ "ec_c25519_i31",     "c25519_i31",  &br_ec_c25519_i31 },
	{ "ec_c25519_m15",     "c25519_m15",  &br_ec_c25519_m15 },
	{ "ec_c25519_m31",     "c25519_m31",  &br_ec_c25519_m31 },
	{ "ec_p256_m15",       "p256_m15",    &br_ec_p256_m15 },
	{ "ec_p256_m31",       "p256_m31",    &br_ec_p256_m31 },
	{ "ec_prime_i15",      "prime_i15",   &br_ec_prime_i15 },
	{ "ec_prime_i31",      "prime_i31",   &br_ec_prime_i31 },

	{ "ecdsa_i15_sign_asn1",  "i15_asn1",  &br_ecdsa_i15_sign_asn1 },
	{ "ecdsa_i15_sign_raw",   "i15_raw",   &br_ecdsa_i15_sign_raw },
	{ "ecdsa_i31_sign_asn1",  "i31_asn1",  &br_ecdsa_i31_sign_asn1 },
	{ "ecdsa_i31_sign_raw",   "i31_raw",   &br_ecdsa_i31_sign_raw },
	{ "ecdsa_i15_vrfy_asn1",  "i15_asn1",  &br_ecdsa_i15_vrfy_asn1 },
	{ "ecdsa_i15_vrfy_raw",   "i15_raw",   &br_ecdsa_i15_vrfy_raw },
	{ "ecdsa_i31_vrfy_asn1",  "i31_asn1",  &br_ecdsa_i31_vrfy_asn1 },
	{ "ecdsa_i31_vrfy_raw",   "i31_raw",   &br_ecdsa_i31_vrfy_raw },

	{ "rsa_i15_pkcs1_sign",   "i15",       &br_rsa_i15_pkcs1_sign },
	{ "rsa_i31_pkcs1_sign",   "i31",       &br_rsa_i31_pkcs1_sign },
	{ "rsa_i32_pkcs1_sign",   "i32",       &br_rsa_i32_pkcs1_sign },
	{ "rsa_i15_pkcs1_vrfy",   "i15",       &br_rsa_i15_pkcs1_vrfy },
	{ "rsa_i31_pkcs1_vrfy",   "i31",       &br_rsa_i31_pkcs1_vrfy },
	{ "rsa_i32_pkcs1_vrfy",   "i32",       &br_rsa_i32_pkcs1_vrfy },

	{ 0, 0, 0 }
};

static const struct {
	const char *long_name;
	const char *short_name;
	const void *(*get)(void);
} algo_names_dyn[] = {
	{ "aes_pwr8_cbcenc",      "pwr8",
		(const void *(*)(void))&br_aes_pwr8_cbcenc_get_vtable },
	{ "aes_pwr8_cbcdec",      "pwr8",
		(const void *(*)(void))&br_aes_pwr8_cbcdec_get_vtable },
	{ "aes_pwr8_ctr",         "pwr8",
		(const void *(*)(void))&br_aes_pwr8_ctr_get_vtable },
	{ "aes_pwr8_ctrcbc",      "pwr8",
		(const void *(*)(void))&br_aes_pwr8_ctrcbc_get_vtable },
	{ "aes_x86ni_cbcenc",     "x86ni",
		(const void *(*)(void))&br_aes_x86ni_cbcenc_get_vtable },
	{ "aes_x86ni_cbcdec",     "x86ni",
		(const void *(*)(void))&br_aes_x86ni_cbcdec_get_vtable },
	{ "aes_x86ni_ctr",        "x86ni",
		(const void *(*)(void))&br_aes_x86ni_ctr_get_vtable },
	{ "aes_x86ni_ctrcbc",     "x86ni",
		(const void *(*)(void))&br_aes_x86ni_ctrcbc_get_vtable },
	{ "chacha20_sse2",        "sse2",
		(const void *(*)(void))&br_chacha20_sse2_get },
	{ "ghash_pclmul",         "pclmul",
		(const void *(*)(void))&br_ghash_pclmul_get },
	{ "ghash_pwr8",           "pwr8",
		(const void *(*)(void))&br_ghash_pwr8_get },
	{ "poly1305_ctmulq",      "ctmulq",
		(const void *(*)(void))&br_poly1305_ctmulq_get },
	{ "rsa_i62_pkcs1_sign",   "i62",
		(const void *(*)(void))&br_rsa_i62_pkcs1_sign_get },
	{ "rsa_i62_pkcs1_vrfy",   "i62",
		(const void *(*)(void))&br_rsa_i62_pkcs1_vrfy_get },
	{ 0, 0, 0, }
};

/* see brssl.h */
const char *
get_algo_name(const void *impl, int long_name)
{
	size_t u;

	for (u = 0; algo_names[u].long_name; u ++) {
		if (impl == algo_names[u].impl) {
			return long_name
				? algo_names[u].long_name
				: algo_names[u].short_name;
		}
	}
	for (u = 0; algo_names_dyn[u].long_name; u ++) {
		if (impl == algo_names_dyn[u].get()) {
			return long_name
				? algo_names_dyn[u].long_name
				: algo_names_dyn[u].short_name;
		}
	}
	return "UNKNOWN";
}

/* see brssl.h */
const char *
get_curve_name(int id)
{
	size_t u;

	for (u = 0; curves[u].name; u ++) {
		if (curves[u].id == id) {
			return curves[u].name;
		}
	}
	return NULL;
}

/* see brssl.h */
int
get_curve_name_ext(int id, char *dst, size_t len)
{
	const char *name;
	char tmp[30];
	size_t n;

	name = get_curve_name(id);
	if (name == NULL) {
		sprintf(tmp, "unknown (%d)", id);
		name = tmp;
	}
	n = 1 + strlen(name);
	if (n > len) {
		if (len > 0) {
			dst[0] = 0;
		}
		return -1;
	}
	memcpy(dst, name, n);
	return 0;
}

/* see brssl.h */
const char *
get_suite_name(unsigned suite)
{
	size_t u;

	for (u = 0; cipher_suites[u].name; u ++) {
		if (cipher_suites[u].suite == suite) {
			return cipher_suites[u].name;
		}
	}
	return NULL;
}

/* see brssl.h */
int
get_suite_name_ext(unsigned suite, char *dst, size_t len)
{
	const char *name;
	char tmp[30];
	size_t n;

	name = get_suite_name(suite);
	if (name == NULL) {
		sprintf(tmp, "unknown (0x%04X)", suite);
		name = tmp;
	}
	n = 1 + strlen(name);
	if (n > len) {
		if (len > 0) {
			dst[0] = 0;
		}
		return -1;
	}
	memcpy(dst, name, n);
	return 0;
}

/* see brssl.h */
int
uses_ecdhe(unsigned suite)
{
	size_t u;

	for (u = 0; cipher_suites[u].name; u ++) {
		if (cipher_suites[u].suite == suite) {
			return (cipher_suites[u].req
				& (REQ_ECDHE_RSA | REQ_ECDHE_ECDSA)) != 0;
		}
	}
	return 0;
}

/* see brssl.h */
void
list_names(void)
{
	size_t u;

	printf("Protocol versions:\n");
	for (u = 0; protocol_versions[u].name; u ++) {
		printf("   %-8s %s\n",
			protocol_versions[u].name,
			protocol_versions[u].comment);
	}
	printf("Hash functions:\n");
	for (u = 0; hash_functions[u].name; u ++) {
		printf("   %-8s %s\n",
			hash_functions[u].name,
			hash_functions[u].comment);
	}
	printf("Cipher suites:\n");
	for (u = 0; cipher_suites[u].name; u ++) {
		printf("   %s\n        %s\n",
			cipher_suites[u].name,
			cipher_suites[u].comment);
	}
}

/* see brssl.h */
void
list_curves(void)
{
	size_t u;
	for (u = 0; curves[u].name; u ++) {
		size_t v;

		for (v = 0; curves[u].sid[v]; v ++) {
			if (v == 0) {
				printf("   ");
			} else if (v == 1) {
				printf(" (");
			} else {
				printf(", ");
			}
			printf("%s", curves[u].sid[v]);
		}
		if (v > 1) {
			printf(")");
		}
		printf("\n");
	}
}

static int
is_ign(int c)
{
	if (c == 0) {
		return 0;
	}
	if (c <= 32 || c == '-' || c == '_' || c == '.'
		|| c == '/' || c == '+' || c == ':')
	{
		return 1;
	}
	return 0;
}

/*
 * Get next non-ignored character, normalised:
 *    ASCII letters are converted to lowercase
 *    control characters, space, '-', '_', '.', '/', '+' and ':' are ignored
 * A terminating zero is returned as 0.
 */
static int
next_char(const char **ps, const char *limit)
{
	for (;;) {
		int c;

		if (*ps == limit) {
			return 0;
		}
		c = *(*ps) ++;
		if (c == 0) {
			return 0;
		}
		if (c >= 'A' && c <= 'Z') {
			c += 'a' - 'A';
		}
		if (!is_ign(c)) {
			return c;
		}
	}
}

/*
 * Partial string equality comparison, with normalisation.
 */
static int
eqstr_chunk(const char *s1, size_t s1_len, const char *s2, size_t s2_len)
{
	const char *lim1, *lim2;

	lim1 = s1 + s1_len;
	lim2 = s2 + s2_len;
	for (;;) {
		int c1, c2;

		c1 = next_char(&s1, lim1);
		c2 = next_char(&s2, lim2);
		if (c1 != c2) {
			return 0;
		}
		if (c1 == 0) {
			return 1;
		}
	}
}

/* see brssl.h */
int
eqstr(const char *s1, const char *s2)
{
	return eqstr_chunk(s1, strlen(s1), s2, strlen(s2));
}

static int
hexval(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else {
		return -1;
	}
}

/* see brssl.h */
size_t
parse_size(const char *s)
{
	int radix;
	size_t acc;
	const char *t;

	t = s;
	if (t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
		radix = 16;
		t += 2;
	} else {
		radix = 10;
	}
	acc = 0;
	for (;;) {
		int c, d;
		size_t z;

		c = *t ++;
		if (c == 0) {
			return acc;
		}
		d = hexval(c);
		if (d < 0 || d >= radix) {
			fprintf(stderr, "ERROR: not a valid digit: '%c'\n", c);
			return (size_t)-1;
		}
		z = acc * (size_t)radix + (size_t)d;
		if (z < (size_t)d || (z / (size_t)radix) != acc
			|| z == (size_t)-1)
		{
			fprintf(stderr, "ERROR: value too large: %s\n", s);
			return (size_t)-1;
		}
		acc = z;
	}
}

/*
 * Comma-separated list enumeration. This returns a pointer to the first
 * word in the string, skipping leading ignored characters. '*len' is
 * set to the word length (not counting trailing ignored characters).
 * '*str' is updated to point to immediately after the next comma, or to
 * the terminating zero, whichever comes first.
 *
 * Empty words are skipped. If there is no next non-empty word, then this
 * function returns NULL and sets *len to 0.
 */
static const char *
next_word(const char **str, size_t *len)
{
	int c;
	const char *begin;
	size_t u;

	/*
	 * Find next non-ignored character which is not a comma.
	 */
	for (;;) {
		c = **str;
		if (c == 0) {
			*len = 0;
			return NULL;
		}
		if (!is_ign(c) && c != ',') {
			break;
		}
		(*str) ++;
	}

	/*
	 * Find next comma or terminator.
	 */
	begin = *str;
	for (;;) {
		c = *(*str);
		if (c == 0 || c == ',') {
			break;
		}
		(*str) ++;
	}

	/*
	 * Remove trailing ignored characters.
	 */
	u = (size_t)(*str - begin);
	while (u > 0 && is_ign(begin[u - 1])) {
		u --;
	}
	if (c == ',') {
		(*str) ++;
	}
	*len = u;
	return begin;
}

/* see brssl.h */
unsigned
parse_version(const char *name, size_t len)
{
	size_t u;

	for (u = 0;; u ++) {
		const char *ref;

		ref = protocol_versions[u].name;
		if (ref == NULL) {
			fprintf(stderr, "ERROR: unrecognised protocol"
				" version name: '%s'\n", name);
			return 0;
		}
		if (eqstr_chunk(ref, strlen(ref), name, len)) {
			return protocol_versions[u].version;
		}
	}
}

/* see brssl.h */
unsigned
parse_hash_functions(const char *arg)
{
	unsigned r;

	r = 0;
	for (;;) {
		const char *name;
		size_t len;
		size_t u;

		name = next_word(&arg, &len);
		if (name == NULL) {
			break;
		}
		for (u = 0;; u ++) {
			const char *ref;

			ref = hash_functions[u].name;
			if (ref == 0) {
				fprintf(stderr, "ERROR: unrecognised"
					" hash function name: '");
				fwrite(name, 1, len, stderr);
				fprintf(stderr, "'\n");
				return 0;
			}
			if (eqstr_chunk(ref, strlen(ref), name, len)) {
				int id;

				id = (hash_functions[u].hclass->desc
					>> BR_HASHDESC_ID_OFF)
					& BR_HASHDESC_ID_MASK;
				r |= (unsigned)1 << id;
				break;
			}
		}
	}
	if (r == 0) {
		fprintf(stderr, "ERROR: no hash function name provided\n");
	}
	return r;
}

/* see brssl.h */
cipher_suite *
parse_suites(const char *arg, size_t *num)
{
	VECTOR(cipher_suite) suites = VEC_INIT;
	cipher_suite *r;

	for (;;) {
		const char *name;
		size_t u, len;

		name = next_word(&arg, &len);
		if (name == NULL) {
			break;
		}
		for (u = 0;; u ++) {
			const char *ref;

			ref = cipher_suites[u].name;
			if (ref == NULL) {
				fprintf(stderr, "ERROR: unrecognised"
					" cipher suite '");
				fwrite(name, 1, len, stderr);
				fprintf(stderr, "'\n");
				return 0;
			}
			if (eqstr_chunk(ref, strlen(ref), name, len)) {
				VEC_ADD(suites, cipher_suites[u]);
				break;
			}
		}
	}
	if (VEC_LEN(suites) == 0) {
		fprintf(stderr, "ERROR: no cipher suite provided\n");
	}
	r = VEC_TOARRAY(suites);
	*num = VEC_LEN(suites);
	VEC_CLEAR(suites);
	return r;
}

/* see brssl.h */
const char *
ec_curve_name(int curve)
{
	switch (curve) {
	case BR_EC_sect163k1:        return "sect163k1";
	case BR_EC_sect163r1:        return "sect163r1";
	case BR_EC_sect163r2:        return "sect163r2";
	case BR_EC_sect193r1:        return "sect193r1";
	case BR_EC_sect193r2:        return "sect193r2";
	case BR_EC_sect233k1:        return "sect233k1";
	case BR_EC_sect233r1:        return "sect233r1";
	case BR_EC_sect239k1:        return "sect239k1";
	case BR_EC_sect283k1:        return "sect283k1";
	case BR_EC_sect283r1:        return "sect283r1";
	case BR_EC_sect409k1:        return "sect409k1";
	case BR_EC_sect409r1:        return "sect409r1";
	case BR_EC_sect571k1:        return "sect571k1";
	case BR_EC_sect571r1:        return "sect571r1";
	case BR_EC_secp160k1:        return "secp160k1";
	case BR_EC_secp160r1:        return "secp160r1";
	case BR_EC_secp160r2:        return "secp160r2";
	case BR_EC_secp192k1:        return "secp192k1";
	case BR_EC_secp192r1:        return "secp192r1";
	case BR_EC_secp224k1:        return "secp224k1";
	case BR_EC_secp224r1:        return "secp224r1";
	case BR_EC_secp256k1:        return "secp256k1";
	case BR_EC_secp256r1:        return "secp256r1";
	case BR_EC_secp384r1:        return "secp384r1";
	case BR_EC_secp521r1:        return "secp521r1";
	case BR_EC_brainpoolP256r1:  return "brainpoolP256r1";
	case BR_EC_brainpoolP384r1:  return "brainpoolP384r1";
	case BR_EC_brainpoolP512r1:  return "brainpoolP512r1";
	default:
		return "unknown";
	}
}

/* see brssl.h */
int
get_curve_by_name(const char *str)
{
	size_t u, v;

	for (u = 0; curves[u].name; u ++) {
		for (v = 0; curves[u].sid[v]; v ++) {
			if (eqstr(curves[u].sid[v], str)) {
				return curves[u].id;
			}
		}
	}
	return -1;
}

/* see brssl.h */
const char *
hash_function_name(int id)
{
	switch (id) {
	case br_md5sha1_ID:  return "MD5+SHA-1";
	case br_md5_ID:      return "MD5";
	case br_sha1_ID:     return "SHA-1";
	case br_sha224_ID:   return "SHA-224";
	case br_sha256_ID:   return "SHA-256";
	case br_sha384_ID:   return "SHA-384";
	case br_sha512_ID:   return "SHA-512";
	default:
		return "unknown";
	}
}
/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "brssl.h"
#include "bearssl.h"

static private_key *
decode_key(const unsigned char *buf, size_t len)
{
	br_skey_decoder_context dc;
	int err;
	private_key *sk;

	br_skey_decoder_init(&dc);
	br_skey_decoder_push(&dc, buf, len);
	err = br_skey_decoder_last_error(&dc);
	if (err != 0) {
		const char *errname, *errmsg;

		fprintf(stderr, "ERROR (decoding): err=%d\n", err);
		errname = find_error_name(err, &errmsg);
		if (errname != NULL) {
			fprintf(stderr, "  %s: %s\n", errname, errmsg);
		} else {
			fprintf(stderr, "  (unknown)\n");
		}
		return NULL;
	}
	switch (br_skey_decoder_key_type(&dc)) {
		const br_rsa_private_key *rk;
		const br_ec_private_key *ek;

	case BR_KEYTYPE_RSA:
		rk = br_skey_decoder_get_rsa(&dc);
		sk = xmalloc(sizeof *sk);
		sk->key_type = BR_KEYTYPE_RSA;
		sk->key.rsa.n_bitlen = rk->n_bitlen;
		sk->key.rsa.p = xblobdup(rk->p, rk->plen);
		sk->key.rsa.plen = rk->plen;
		sk->key.rsa.q = xblobdup(rk->q, rk->qlen);
		sk->key.rsa.qlen = rk->qlen;
		sk->key.rsa.dp = xblobdup(rk->dp, rk->dplen);
		sk->key.rsa.dplen = rk->dplen;
		sk->key.rsa.dq = xblobdup(rk->dq, rk->dqlen);
		sk->key.rsa.dqlen = rk->dqlen;
		sk->key.rsa.iq = xblobdup(rk->iq, rk->iqlen);
		sk->key.rsa.iqlen = rk->iqlen;
		break;

	case BR_KEYTYPE_EC:
		ek = br_skey_decoder_get_ec(&dc);
		sk = xmalloc(sizeof *sk);
		sk->key_type = BR_KEYTYPE_EC;
		sk->key.ec.curve = ek->curve;
		sk->key.ec.x = xblobdup(ek->x, ek->xlen);
		sk->key.ec.xlen = ek->xlen;
		break;

	default:
		fprintf(stderr, "Unknown key type: %d\n",
			br_skey_decoder_key_type(&dc));
		sk = NULL;
		break;
	}

	return sk;
}

/* see brssl.h */
private_key *
read_private_key(const char *fname)
{
	unsigned char *buf;
	size_t len;
	private_key *sk;
	pem_object *pos;
	size_t num, u;

	buf = NULL;
	pos = NULL;
	sk = NULL;
	buf = read_file(fname, &len);
	if (buf == NULL) {
		goto deckey_exit;
	}
	if (looks_like_DER(buf, len)) {
		sk = decode_key(buf, len);
		goto deckey_exit;
	} else {
		pos = decode_pem(buf, len, &num);
		if (pos == NULL) {
			goto deckey_exit;
		}
		for (u = 0; pos[u].name; u ++) {
			const char *name;

			name = pos[u].name;
			if (eqstr(name, "RSA PRIVATE KEY")
				|| eqstr(name, "EC PRIVATE KEY")
				|| eqstr(name, "PRIVATE KEY"))
			{
				sk = decode_key(pos[u].data, pos[u].data_len);
				goto deckey_exit;
			}
		}
		fprintf(stderr, "ERROR: no private key in file '%s'\n", fname);
		goto deckey_exit;
	}

deckey_exit:
	if (buf != NULL) {
		xfree(buf);
	}
	if (pos != NULL) {
		for (u = 0; pos[u].name; u ++) {
			free_pem_object_contents(&pos[u]);
		}
		xfree(pos);
	}
	return sk;
}

/* see brssl.h */
void
free_private_key(private_key *sk)
{
	if (sk == NULL) {
		return;
	}
	switch (sk->key_type) {
	case BR_KEYTYPE_RSA:
		xfree(sk->key.rsa.p);
		xfree(sk->key.rsa.q);
		xfree(sk->key.rsa.dp);
		xfree(sk->key.rsa.dq);
		xfree(sk->key.rsa.iq);
		break;
	case BR_KEYTYPE_EC:
		xfree(sk->key.ec.x);
		break;
	}
	xfree(sk);
}

/*
 * OID for hash functions in RSA signatures.
 */
static const unsigned char HASH_OID_SHA1[] = {
	0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A
};

static const unsigned char HASH_OID_SHA224[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
};

static const unsigned char HASH_OID_SHA256[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};

static const unsigned char HASH_OID_SHA384[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};

static const unsigned char HASH_OID_SHA512[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

static const unsigned char *HASH_OID[] = {
	HASH_OID_SHA1,
	HASH_OID_SHA224,
	HASH_OID_SHA256,
	HASH_OID_SHA384,
	HASH_OID_SHA512
};

/* see brssl.h */
const unsigned char *
get_hash_oid(int id)
{
	if (id >= 2 && id <= 6) {
		return HASH_OID[id - 2];
	} else {
		return NULL;
	}
}

/* see brssl.h */
const br_hash_class *
get_hash_impl(int hash_id)
{
	size_t u;

	if (hash_id == 0) {
		return &br_md5sha1_vtable;
	}
	for (u = 0; hash_functions[u].name; u ++) {
		const br_hash_class *hc;
		int id;

		hc = hash_functions[u].hclass;
		id = (hc->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK;
		if (id == hash_id) {
			return hc;
		}
	}
	return NULL;
}
/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "brssl.h"
#include "bearssl.h"

static struct {
	int err;
	const char *name;
	const char *comment;
} errors[] = {
	{
		BR_ERR_BAD_PARAM,
		"BR_ERR_BAD_PARAM",
		"Caller-provided parameter is incorrect."
	}, {
		BR_ERR_BAD_STATE,
		"BR_ERR_BAD_STATE",
		"Operation requested by the caller cannot be applied with"
		" the current context state (e.g. reading data while"
		" outgoing data is waiting to be sent)."
	}, {
		BR_ERR_UNSUPPORTED_VERSION,
		"BR_ERR_UNSUPPORTED_VERSION",
		"Incoming protocol or record version is unsupported."
	}, {
		BR_ERR_BAD_VERSION,
		"BR_ERR_BAD_VERSION",
		"Incoming record version does not match the expected version."
	}, {
		BR_ERR_BAD_LENGTH,
		"BR_ERR_BAD_LENGTH",
		"Incoming record length is invalid."
	}, {
		BR_ERR_TOO_LARGE,
		"BR_ERR_TOO_LARGE",
		"Incoming record is too large to be processed, or buffer"
		" is too small for the handshake message to send."
	}, {
		BR_ERR_BAD_MAC,
		"BR_ERR_BAD_MAC",
		"Decryption found an invalid padding, or the record MAC is"
		" not correct."
	}, {
		BR_ERR_NO_RANDOM,
		"BR_ERR_NO_RANDOM",
		"No initial entropy was provided, and none can be obtained"
		" from the OS."
	}, {
		BR_ERR_UNKNOWN_TYPE,
		"BR_ERR_UNKNOWN_TYPE",
		"Incoming record type is unknown."
	}, {
		BR_ERR_UNEXPECTED,
		"BR_ERR_UNEXPECTED",
		"Incoming record or message has wrong type with regards to"
		" the current engine state."
	}, {
		BR_ERR_BAD_CCS,
		"BR_ERR_BAD_CCS",
		"ChangeCipherSpec message from the peer has invalid contents."
	}, {
		BR_ERR_BAD_ALERT,
		"BR_ERR_BAD_ALERT",
		"Alert message from the peer has invalid contents"
		" (odd length)."
	}, {
		BR_ERR_BAD_HANDSHAKE,
		"BR_ERR_BAD_HANDSHAKE",
		"Incoming handshake message decoding failed."
	}, {
		BR_ERR_OVERSIZED_ID,
		"BR_ERR_OVERSIZED_ID",
		"ServerHello contains a session ID which is larger than"
		" 32 bytes."
	}, {
		BR_ERR_BAD_CIPHER_SUITE,
		"BR_ERR_BAD_CIPHER_SUITE",
		"Server wants to use a cipher suite that we did not claim"
		" to support. This is also reported if we tried to advertise"
		" a cipher suite that we do not support."
	}, {
		BR_ERR_BAD_COMPRESSION,
		"BR_ERR_BAD_COMPRESSION",
		"Server wants to use a compression that we did not claim"
		" to support."
	}, {
		BR_ERR_BAD_FRAGLEN,
		"BR_ERR_BAD_FRAGLEN",
		"Server's max fragment length does not match client's."
	}, {
		BR_ERR_BAD_SECRENEG,
		"BR_ERR_BAD_SECRENEG",
		"Secure renegotiation failed."
	}, {
		BR_ERR_EXTRA_EXTENSION,
		"BR_ERR_EXTRA_EXTENSION",
		"Server sent an extension type that we did not announce,"
		" or used the same extension type several times in a"
		" single ServerHello."
	}, {
		BR_ERR_BAD_SNI,
		"BR_ERR_BAD_SNI",
		"Invalid Server Name Indication contents (when used by"
		" the server, this extension shall be empty)."
	}, {
		BR_ERR_BAD_HELLO_DONE,
		"BR_ERR_BAD_HELLO_DONE",
		"Invalid ServerHelloDone from the server (length is not 0)."
	}, {
		BR_ERR_LIMIT_EXCEEDED,
		"BR_ERR_LIMIT_EXCEEDED",
		"Internal limit exceeded (e.g. server's public key is too"
		" large)."
	}, {
		BR_ERR_BAD_FINISHED,
		"BR_ERR_BAD_FINISHED",
		"Finished message from peer does not match the expected"
		" value."
	}, {
		BR_ERR_RESUME_MISMATCH,
		"BR_ERR_RESUME_MISMATCH",
		"Session resumption attempt with distinct version or cipher"
		" suite."
	}, {
		BR_ERR_INVALID_ALGORITHM,
		"BR_ERR_INVALID_ALGORITHM",
		"Unsupported or invalid algorithm (ECDHE curve, signature"
		" algorithm, hash function)."
	}, {
		BR_ERR_BAD_SIGNATURE,
		"BR_ERR_BAD_SIGNATURE",
		"Invalid signature in ServerKeyExchange or"
		" CertificateVerify message."
	}, {
		BR_ERR_WRONG_KEY_USAGE,
		"BR_ERR_WRONG_KEY_USAGE",
		"Peer's public key does not have the proper type or is"
		" not allowed for the requested operation."
	}, {
		BR_ERR_NO_CLIENT_AUTH,
		"BR_ERR_NO_CLIENT_AUTH",
		"Client did not send a certificate upon request, or the"
		" client certificate could not be validated."
	}, {
		BR_ERR_IO,
		"BR_ERR_IO",
		"I/O error or premature close on transport stream."
	}, {
		BR_ERR_X509_INVALID_VALUE,
		"BR_ERR_X509_INVALID_VALUE",
		"Invalid value in an ASN.1 structure."
	},
	{
		BR_ERR_X509_TRUNCATED,
		"BR_ERR_X509_TRUNCATED",
		"Truncated certificate or other ASN.1 object."
	},
	{
		BR_ERR_X509_EMPTY_CHAIN,
		"BR_ERR_X509_EMPTY_CHAIN",
		"Empty certificate chain (no certificate at all)."
	},
	{
		BR_ERR_X509_INNER_TRUNC,
		"BR_ERR_X509_INNER_TRUNC",
		"Decoding error: inner element extends beyond outer element"
		" size."
	},
	{
		BR_ERR_X509_BAD_TAG_CLASS,
		"BR_ERR_X509_BAD_TAG_CLASS",
		"Decoding error: unsupported tag class (application or"
		" private)."
	},
	{
		BR_ERR_X509_BAD_TAG_VALUE,
		"BR_ERR_X509_BAD_TAG_VALUE",
		"Decoding error: unsupported tag value."
	},
	{
		BR_ERR_X509_INDEFINITE_LENGTH,
		"BR_ERR_X509_INDEFINITE_LENGTH",
		"Decoding error: indefinite length."
	},
	{
		BR_ERR_X509_EXTRA_ELEMENT,
		"BR_ERR_X509_EXTRA_ELEMENT",
		"Decoding error: extraneous element."
	},
	{
		BR_ERR_X509_UNEXPECTED,
		"BR_ERR_X509_UNEXPECTED",
		"Decoding error: unexpected element."
	},
	{
		BR_ERR_X509_NOT_CONSTRUCTED,
		"BR_ERR_X509_NOT_CONSTRUCTED",
		"Decoding error: expected constructed element, but is"
		" primitive."
	},
	{
		BR_ERR_X509_NOT_PRIMITIVE,
		"BR_ERR_X509_NOT_PRIMITIVE",
		"Decoding error: expected primitive element, but is"
		" constructed."
	},
	{
		BR_ERR_X509_PARTIAL_BYTE,
		"BR_ERR_X509_PARTIAL_BYTE",
		"Decoding error: BIT STRING length is not multiple of 8."
	},
	{
		BR_ERR_X509_BAD_BOOLEAN,
		"BR_ERR_X509_BAD_BOOLEAN",
		"Decoding error: BOOLEAN value has invalid length."
	},
	{
		BR_ERR_X509_OVERFLOW,
		"BR_ERR_X509_OVERFLOW",
		"Decoding error: value is off-limits."
	},
	{
		BR_ERR_X509_BAD_DN,
		"BR_ERR_X509_BAD_DN",
		"Invalid distinguished name."
	},
	{
		BR_ERR_X509_BAD_TIME,
		"BR_ERR_X509_BAD_TIME",
		"Invalid date/time representation."
	},
	{
		BR_ERR_X509_UNSUPPORTED,
		"BR_ERR_X509_UNSUPPORTED",
		"Certificate contains unsupported features that cannot be"
		" ignored."
	},
	{
		BR_ERR_X509_LIMIT_EXCEEDED,
		"BR_ERR_X509_LIMIT_EXCEEDED",
		"Key or signature size exceeds internal limits."
	},
	{
		BR_ERR_X509_WRONG_KEY_TYPE,
		"BR_ERR_X509_WRONG_KEY_TYPE",
		"Key type does not match that which was expected."
	},
	{
		BR_ERR_X509_BAD_SIGNATURE,
		"BR_ERR_X509_BAD_SIGNATURE",
		"Signature is invalid."
	},
	{
		BR_ERR_X509_TIME_UNKNOWN,
		"BR_ERR_X509_TIME_UNKNOWN",
		"Validation time is unknown."
	},
	{
		BR_ERR_X509_EXPIRED,
		"BR_ERR_X509_EXPIRED",
		"Certificate is expired or not yet valid."
	},
	{
		BR_ERR_X509_DN_MISMATCH,
		"BR_ERR_X509_DN_MISMATCH",
		"Issuer/Subject DN mismatch in the chain."
	},
	{
		BR_ERR_X509_BAD_SERVER_NAME,
		"BR_ERR_X509_BAD_SERVER_NAME",
		"Expected server name was not found in the chain."
	},
	{
		BR_ERR_X509_CRITICAL_EXTENSION,
		"BR_ERR_X509_CRITICAL_EXTENSION",
		"Unknown critical extension in certificate."
	},
	{
		BR_ERR_X509_NOT_CA,
		"BR_ERR_X509_NOT_CA",
		"Not a CA, or path length constraint violation."
	},
	{
		BR_ERR_X509_FORBIDDEN_KEY_USAGE,
		"BR_ERR_X509_FORBIDDEN_KEY_USAGE",
		"Key Usage extension prohibits intended usage."
	},
	{
		BR_ERR_X509_WEAK_PUBLIC_KEY,
		"BR_ERR_X509_WEAK_PUBLIC_KEY",
		"Public key found in certificate is too small."
	},
	{
		BR_ERR_X509_NOT_TRUSTED,
		"BR_ERR_X509_NOT_TRUSTED",
		"Chain could not be linked to a trust anchor."
	},
	{ 0, 0, 0 }
};

/* see brssl.h */
const char *
find_error_name(int err, const char **comment)
{
	size_t u;

	for (u = 0; errors[u].name; u ++) {
		if (errors[u].err == err) {
			if (comment != NULL) {
				*comment = errors[u].comment;
			}
			return errors[u].name;
		}
	}
	return NULL;
}
