/**
 * @file connection.c
 * @brief Manages the creation and handling of raw and secure connections to the server
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

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

SSL_CTX* create_ssl_context(const char *certfile, const char *certdir) {
    SSL_CTX *ctx;

    // Create an SSL context for TLS client
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Load the specified certificate file, if provided
    if (certfile && strlen(certfile) > 0) {
        if (SSL_CTX_load_verify_locations(ctx, certfile, NULL) != 1) {
            fprintf(stderr, "Error: loading certificate from file %s failed.\n", certfile);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        } else {
            printf("Loaded certificate file: %s\n", certfile);
        }
    }

    // Load certificates from the specified directory, if provided
    if (certdir && strlen(certdir) > 0) {
        if (SSL_CTX_load_verify_locations(ctx, NULL, certdir) != 1) {
            fprintf(stderr, "Error: loading certificates from directory %s failed.\n", certdir);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        } else {
            printf("Loaded certificates from directory: %s\n", certdir);
        }
    }

    // If neither a file nor a directory is provided, use the default paths
    if ((!certfile || strlen(certfile) == 0) && (!certdir || strlen(certdir) == 0)) {
        if (!SSL_CTX_set_default_verify_paths(ctx)) {
            fprintf(stderr, "Error: loading default certificate paths failed.\n");
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        } else {
            printf("Loaded default certificate paths.\n");
        }
    }

    return ctx;
}



int create_raw_socket(const char *hostname, int port) {
    int sock ;
    struct sockaddr_in server_addr;
    struct hostent *servent;        // Structure to hold server address

    // Resolve the hostname to an IP address using gethostbyname()
    if ((servent = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "Error: Hostname resolution failed or IPv6 address is used which is not supported.\n");
        return -1;
    }

    // Ensure that the address is IPv4
    if (servent->h_addrtype != AF_INET) {
        fprintf(stderr, "Error: Only IPv4 addresses are supported.\n");
        return -1;
    }

    // Create a socket (AF_INET for IPv4, SOCK_STREAM for TCP)
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Error: Socket creation failed.\n");
        return -1;
    }

    // Set timeout for the socket
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // Set server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Copy the resolved IP address to the server address structure
    memcpy(&server_addr.sin_addr, servent->h_addr_list[0], servent->h_length);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error: Connection failed.\n");
        close(sock);
        return -1;
    }

    printf("Connected to %s on port %d\n", hostname, port);
    return sock; // Return the socket file descriptor
}

SSL* create_secure_connection(int sockfd, SSL_CTX *ctx) {
    SSL *ssl;

    // Create an SSL object and bind it to the raw socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    printf("SSL connection established\n");

    // Get the server's certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        printf("Server's certificate was received.\n");

        // Check if the certificate is valid
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            fprintf(stderr, "Error: Certificate verification failed: %s\n", X509_verify_cert_error_string(verify_result));
            X509_free(cert);
            SSL_free(ssl);
            return NULL;
        }

        // Optionally: Print certificate information (subject, issuer, etc.)
        char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        printf("Certificate Subject: %s\n", subject);
        printf("Certificate Issuer: %s\n", issuer);

        OPENSSL_free(subject);
        OPENSSL_free(issuer);
        X509_free(cert);
    } else {
        fprintf(stderr, "Error: No server certificate found.\n");
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

void close_secure_connection(SSL *ssl, SSL_CTX *ctx) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("Secure connection closed, SSL context freed.\n");
}