#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "connection.h"

// Initialize OpenSSL
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}


BIO* create_unsecured_connection(const char *hostname, const char *port) {
    BIO *bio = NULL;
    char host_port[256];

    // Combine hostname and port into a single string like "hostname:port"
    snprintf(host_port, sizeof(host_port), "%s:%s", hostname, port);

    // Create a new BIO object for the connection
    bio = BIO_new_connect(host_port);
    if (bio == NULL) {
        fprintf(stderr, "Error creating BIO connection object.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Attempt to connect to the server
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to server %s:%s.\n", hostname, port);
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        return NULL;
    }

    printf("Connected to %s on port %s\n", hostname, port);
    return bio;  // Return the BIO object for further communication
}



SSL_CTX* create_ssl_context(const char *certfile, const char *certdir) {
    SSL_CTX *ctx;
    const SSL_METHOD *method = SSLv23_client_method();  // TLS client method

    if ((ctx = SSL_CTX_new(method)) == NULL) {
        fprintf(stderr, "Unable to create SSL context.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set SSL context options (disable SSLv2, SSLv3, compression)
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    // Load certificates if provided
    if (certfile && SSL_CTX_load_verify_locations(ctx, certfile, certdir) != 1) {
        fprintf(stderr, "Error loading certificates.\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

BIO* create_secure_connection(struct Config *config, SSL_CTX **out_ctx) {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *web;
    char server_port[256];

    // Create SSL context
    ctx = create_ssl_context(config->certfile, config->certdir);
    if (!ctx) return NULL;

    int ret = snprintf(server_port, sizeof(server_port), "%s:%d", config->server, config->port);

    if (ret < 0 || (size_t)ret >= sizeof(server_port)) {
        fprintf(stderr, "Error: server and port string too long.\n");
        return NULL;
    }

    // Create BIO and set hostname and port
    web = BIO_new_ssl_connect(ctx);
    if (web == NULL) {
        fprintf(stderr, "Error creating BIO object.\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    BIO_set_conn_hostname(web, server_port);

    // Perform SSL handshake
    if (BIO_do_connect(web) <= 0 || BIO_do_handshake(web) <= 0) {
        fprintf(stderr, "Connection or handshake failed.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(web);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Retrieve the underlying SSL object
    BIO_get_ssl(web, &ssl);

    // Check server certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        printf("Server certificate received.\n");
        // You can further validate the certificate here, e.g., checking subject or issuer.
        X509_free(cert);  // Free after use
    } else {
        fprintf(stderr, "No certificate presented by the server.\n");
        BIO_free_all(web);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Return the SSL context to be used for cleanup
    *out_ctx = ctx;
    return web;  // Return the BIO object
}

void disconnect_unsecured(BIO *bio) {
    if (bio) {
        BIO_free_all(bio);  // Frees the BIO and closes the connection
        printf("Unsecured connection closed.\n");
    }
}

void disconnect_secure(BIO *bio, SSL_CTX *ctx) {
    if (bio) {
        BIO_free_all(bio);  // Frees the BIO, SSL, and underlying connection
        printf("Secure connection closed.\n");
    }

    if (ctx) {
        SSL_CTX_free(ctx);  // Frees the SSL context
        printf("SSL context freed.\n");
    }
}