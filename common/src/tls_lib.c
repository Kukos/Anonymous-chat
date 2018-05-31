#include <tls_lib.h>
#include <openssl/err.h>
#include <log.h>

/*
    Create tls context for server / client (based on get_method function)

    PARAMS
    @IN cert - path to cert file
    @IN key - path to key file
    @IN get_method - get CTX_METHOD

    RETURN
    NULL iff failure
    New SSL_CTX iff success
*/
static SSL_CTX *__tls_create_context(const char *cert, const char *key, const SSL_METHOD *(*get_method)(void));

static int verify_callback(int preverify, X509_STORE_CTX* ctx)
{
    char   buf[256];
    X509   *cert;
    int    depth;

    TRACE();
    cert = X509_STORE_CTX_get_current_cert(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);

    LOG("Preverify OK, depth=%d:%s\n", depth, buf);

    (void)preverify;
    return 1;
}

static SSL_CTX *__tls_create_context(const char *cert, const char *key, const SSL_METHOD *(*get_method)(void))
{
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    TRACE();

    if (cert == NULL)
        ERROR("cert == NULL\n", NULL);

    if (key == NULL)
        ERROR("key == NULL\n", NULL);

    LOG("Getting SSL metod\n");
    method = get_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
        ERROR("SSL_CTX_new error\n", NULL);

    LOG("Getting cert from %s and key from %s\n", cert, key);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
        ERROR("SSL_CTX_use_cert error\n", NULL);

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
        ERROR("SSL_CTX_use_priv_key error\n", NULL);

    if (SSL_CTX_check_private_key(ctx) != 1)
        ERROR("cert %s is not valid with priv key %s\n", NULL, cert, key);

    SSL_CTX_set_verify_depth(ctx, 0);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    LOG("TLS context created and configured\n");

    return ctx;
}

void tls_init(void)
{
    TRACE();

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();

    LOG("SSL libarry inited\n");
}

void tls_clenup(void)
{
    TRACE();

    EVP_cleanup();

    LOG("SSL libary cleaned\n");
}

SSL_CTX *tls_create_server_context(const char *cert, const char *key)
{
    return __tls_create_context(cert, key, SSLv23_server_method);
}

SSL_CTX *tls_create_client_context(const char *cert, const char *key)
{
    return __tls_create_context(cert, key, SSLv23_method);
}

void tls_destroy_context(SSL_CTX *ctx)
{
    if (ctx == NULL)
        return;

    SSL_CTX_free(ctx);
}

SSL *tls_accept(SSL_CTX *ctx, int fd)
{
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        ERROR("SSL_new error\n", NULL);

    SSL_set_fd(ssl, fd);

    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        ERROR("cannot accept tls connection from %d fd\n", NULL, fd);
    }

    LOG("TLS connection for %d fd accepted\n", fd);

    return ssl;
}

SSL *tls_request_connection(SSL_CTX *ctx, int fd)
{
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        ERROR("SSL_new error\n", NULL);

    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        ERROR("SSL_connect error\n", NULL);
    }

    LOG("TLS connection for %d fd done\n", fd);

    return ssl;
}