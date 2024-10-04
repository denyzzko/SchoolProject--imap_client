/**
 * @file main.c
 * @brief Main file for email client using protocol IMAP4rev1
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#include "main.h"
#include "parser.h"
#include "connection.h"

#include <unistd.h>        // For close()
#include <sys/socket.h>    // For send() and recv()
#include <openssl/ssl.h>   // For SSL
#include <openssl/err.h>   // For SSL error printing

int main(int argc, char* argv[]) {
    struct Config config;

    // Parse command-line arguments
    if (!parse_arguments(argc, argv, &config)) {
        return 1;
    }

    // Create raw socket
    int sockfd = create_raw_socket(config.server, config.port);
    if (sockfd < 0) {
        return 1;
    }

    // If secure connection
    if (config.use_ssl) {
        // Initialize OpenSSL
        initialize_openssl();
        
        // Create an SSL context
        SSL_CTX *ctx = create_ssl_context(config.certfile, config.certdir);
        if (!ctx) {
            ERR_print_errors_fp(stderr);
            close(sockfd);
            return 1;
        }

        // Create SSL connection over the raw socket
        SSL *ssl = create_secure_connection(sockfd, ctx);
        if (!ssl) {
            close(sockfd);
            SSL_CTX_free(ctx);
            return 1;
        }

        // Send and receive data using SSL_read and SSL_write

        // Clean up
        printf("Closing secure connection...\n");
        close_secure_connection(ssl, ctx);
        printf("closed\n");
    } else {
        // Send and receive data using send() and recv() for unsecure connection
        char *msg = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        send(sockfd, msg, strlen(msg), 0);

        char buffer[1024];
        int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Server response: %s\n", buffer);
        }

        printf("Closing unsecure connection...\n");
        close(sockfd); // Close unsecure socket
        printf("closed\n");
    }

    return 0;
}