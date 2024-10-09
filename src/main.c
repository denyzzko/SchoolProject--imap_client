/**
 * @file main.c
 * @brief Main file for email client using protocol IMAP4rev1
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#include "main.h"
#include "parser.h"
#include "connection.h"
#include "communication.h"

#include <unistd.h>        // For close()
#include <sys/socket.h>    // For send() and recv()
#include <openssl/ssl.h>   // For SSL
#include <openssl/err.h>   // For SSL error printing

int main(int argc, char* argv[]) {
    struct Config config;

    // parse command-line arguments
    if (!ParseArguments(argc, argv, &config)) {
        return 1;
    }
    
    // Create raw socket
    int sockfd = create_raw_socket(config.server, config.port);
    if (sockfd < 0) {
        return 1;
    }

    if (config.use_ssl) {
         //secure connection
        initialize_openssl();
        // SSL context
        SSL_CTX *ctx = create_ssl_context(config.certfile, config.certdir);
        if (!ctx) {
            ERR_print_errors_fp(stderr);
            close(sockfd);
            return 1;
        }
        // SSL connection over the raw socket
        SSL *ssl = create_secure_connection(sockfd, ctx);
        if (!ssl) {
            close(sockfd);
            SSL_CTX_free(ctx);
            return 1;
        }
        // secure communication
        if (!SecureCommunication(ssl, &config)) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            return 1;
        }
        // Clean up
        printf("Closing secure connection...\n");
        close_secure_connection(ssl, ctx);
        printf("closed\n");
    } else {
         // unsecure communication
        if (!UnsecureCommunication(sockfd, &config)) {
            close(sockfd);
            return 1;
        }
        // Clean up
        printf("Closing unsecure connection...\n");
        close(sockfd); // Close unsecure socket
        printf("closed\n");
    }
    
    return 0;
}