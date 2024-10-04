#ifndef CONNECTION_H
#define CONNECTION_H

#include "main.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

// Initialize OpenSSL (only needs to be called once)
void initialize_openssl();

// Create SSL context (for optional certificate file and directory)
SSL_CTX* create_ssl_context(const char *certfile, const char *certdir);

// Function to create socket
int create_raw_socket(const char *hostname, int port);

// Function to create a secure SSL connection
SSL* create_secure_connection(int sockfd, SSL_CTX *ctx);

// Function to close a secure connection and free the SSL context
void close_secure_connection(SSL *ssl, SSL_CTX *ctx);

#endif