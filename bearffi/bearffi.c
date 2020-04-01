#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <bearssl.h>

#include "brssl.h"

struct wrapper {
	br_ssl_server_context sc;
	br_ssl_client_context cc;
	void *eng;
	br_x509_minimal_context xc;
	br_sslio_context ioc;
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
};

static br_x509_trust_anchor *trust_anchors;
static int num_trust_anchors;
static br_x509_certificate *server_chain;
static size_t server_chain_len;
static private_key *server_key;

static void
load_certs(void)
{
	anchor_list anchors = VEC_INIT;

	read_trust_anchors(&anchors, "/etc/ssl/cert.pem");
	trust_anchors =  &VEC_ELT(anchors, 0);
	num_trust_anchors = VEC_LEN(anchors);
}

int
bear_init(const char *certfile, const char *keyfile)
{
	load_certs();
	server_chain = read_certificates(certfile, &server_chain_len);
	server_key = read_private_key(keyfile);
	return 0;
}

struct wrapper *
bear_server(void *rh, void *readfn, void *wh, void *writefn)
{
	struct wrapper *wrapper;

	wrapper = malloc(sizeof(*wrapper));
	if (!wrapper) {
		return NULL;
	}

	br_ssl_server_init_full_rsa(&wrapper->sc, server_chain, server_chain_len, &server_key->key.rsa);

	br_ssl_engine_set_buffer(&wrapper->sc.eng, wrapper->iobuf, sizeof wrapper->iobuf, 1);

	br_ssl_server_reset(&wrapper->sc);

	br_sslio_init(&wrapper->ioc, &wrapper->sc.eng, readfn, rh, writefn, wh);

	wrapper->eng = &wrapper->sc.eng;

	return wrapper;
}

struct wrapper *
bear_client(const char *hostname, void *rh, void *readfn, void *wh, void *writefn)
{
	struct wrapper *wrapper;

	wrapper = malloc(sizeof(*wrapper));
	if (!wrapper) {
		return NULL;
	}

	br_ssl_client_init_full(&wrapper->cc, &wrapper->xc, trust_anchors, num_trust_anchors);

	br_ssl_engine_set_buffer(&wrapper->cc.eng, wrapper->iobuf, sizeof wrapper->iobuf, 1);

	br_ssl_client_reset(&wrapper->cc, hostname, 0);

	br_sslio_init(&wrapper->ioc, &wrapper->cc.eng, readfn, rh, writefn, wh);

	wrapper->eng = &wrapper->cc.eng;

	return wrapper;
}

int
bear_close(struct wrapper *wrapper)
{
	int rv = br_sslio_close(&wrapper->ioc);
	return rv;
}

void
bear_freewrapper(struct wrapper *wrapper)
{
	free(wrapper);
}

int
bear_read(struct wrapper *wrapper, unsigned char *buf, size_t buflen)
{
	int rv = br_sslio_read(&wrapper->ioc, buf, buflen);
	return rv;
}

int
bear_write(struct wrapper *wrapper, unsigned char *buf, size_t buflen)
{
	int rv = br_sslio_write(&wrapper->ioc, buf, buflen);
	return rv;
}

int
bear_flush(struct wrapper *wrapper)
{
	int rv = br_sslio_flush(&wrapper->ioc);
	return rv;
}

int
bear_error(struct wrapper *wrapper)
{
	return br_ssl_engine_last_error(wrapper->eng);
}
