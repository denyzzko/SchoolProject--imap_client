/**
 * @file connection.h
 * @brief Header file for connection.c
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#ifndef CONNECTION_H
#define CONNECTION_H

#include "main.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

// Function to initialize openssl
void initialize_openssl();

// Function to create socket
int create_raw_socket(const char *hostname, int port);

// Function to create ssl context (for optional certificate file and directory)
SSL_CTX* create_ssl_context(const char *certfile, const char *certdir);

// Function to create a secure connection with raw socket and SSL context
SSL* create_secure_connection(int sockfd, SSL_CTX *ctx);

// Function to close a secure SSL connection and free resources
void close_secure_connection(SSL *ssl, SSL_CTX *ctx);

#endif