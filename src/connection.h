#ifndef CONNECTION_H
#define CONNECTION_H

#include "main.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

// Initialize OpenSSL (only needs to be called once)
void initialize_openssl();

// Function to create a non-secure connection (returns a BIO object)
BIO* create_unsecured_connection(const char *hostname, const char *port);

// Function to create an SSL context for a secure connection
SSL_CTX* create_ssl_context(const char *certfile, const char *certdir);

// Function to create a secure SSL connection (returns a BIO object)
BIO* create_secure_connection(struct Config *config, SSL_CTX **out_ctx);

// Function to close a non-secure connection
void disconnect_unsecured(BIO *bio);

// Function to close a secure connection and free the SSL context
void disconnect_secure(BIO *bio, SSL_CTX *ctx);

#endif