/**
 * @file connection.c
 * @brief Manages the creation of raw socket, connecting it to server and securing it with SSL/TLS
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "main.h"


void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

int create_raw_socket(const char *hostname, int port) {
    int sock;
    struct addrinfo hints, *res, *p;
    char port_str[6];
    int status;

    // Convert port number to string
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Both ipv4 and ipv6
    hints.ai_socktype = SOCK_STREAM; // TCP sockets

    // Resolve hostname to an IP address
    if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) {
        // Hostname resolution failed
        fprintf(stderr, "Error: getaddrinfo failed: %s\n", gai_strerror(status));
        return -1;
    }

    // Loop through results and attemp to connect
    for (p = res; p != NULL; p = p->ai_next) {
        // Create socket
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            // Socket creation failed, skip to next adress
            continue;
        }

        // Set socket timeouts for 10 seconds
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        // Connect to the server
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            // Connection failed
            close(sock);
            continue;
        }

        // Successfully connected
        break;
    }

    // Free address info structure
    freeaddrinfo(res);

    if (p == NULL) {
        // No connection successfully established
        fprintf(stderr, "Error: Failed to connect to %s on port %d\n", hostname, port);
        return -1;
    }

    // Return the socket file descriptor
    return sock;
}

SSL_CTX* create_ssl_context(const char *certfile, const char *certdir) {
    SSL_CTX *ctx;

    // Create an SSL context for TLS client
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        // SSL context creation failed
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Load the specified certificate file, if provided
    if (certfile && strlen(certfile) > 0) {
        if (SSL_CTX_load_verify_locations(ctx, certfile, NULL) != 1) {
            // Loading failed
            fprintf(stderr, "Error: loading certificate from file %s failed.\n", certfile);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    // Load certificates from the directory
    if (certdir && strlen(certdir) > 0) {
        if (SSL_CTX_load_verify_locations(ctx, NULL, certdir) != 1) {
            // Loading failed
            fprintf(stderr, "Error: loading certificates from directory %s failed.\n", certdir);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    // Return created SSL context
    return ctx;
}

SSL* create_secure_connection(int sockfd, SSL_CTX *ctx) {
    SSL *ssl;

    // Create SSL object and bind it to raw socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        // Handshake failed
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    // Get the server's certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        // Server's certificate was received
        // Check if certificate is valid
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            // Certificate verification failed
            fprintf(stderr, "Error: Certificate verification failed: %s\n", X509_verify_cert_error_string(verify_result));
            X509_free(cert);
            SSL_free(ssl);
            return NULL;
        }
        //Server's certificate verified

        // Free memory allocated for certificates
        X509_free(cert);
    } else {
        // No certificate found
        fprintf(stderr, "Error: No server certificate found.\n");
        SSL_free(ssl);
        return NULL;
    }

    // Return SSL object for secure communication
    return ssl;
}

void close_secure_connection(SSL *ssl, SSL_CTX *ctx) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}