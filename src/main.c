/**
 * @file main.c
 * @brief Main file for email client using protocol IMAP4rev1
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */
#include "main.h"
#include "parser.h"
#include "connection.h"

int main(int argc, char* argv[]) {
    struct Config config;

    // Parse command-line arguments
    if (!parse_arguments(argc, argv, &config)) {
        return 1;
    }

    // Initialize OpenSSL
    initialize_openssl();

    // Establish a connection to the server
    if (config.use_ssl) {
        SSL_CTX *ctx = NULL;
        BIO *secure_bio = create_secure_connection(&config, &ctx);
        if (secure_bio) {
            // Use the secure connection (send/receive IMAP commands)
            disconnect_secure(secure_bio, ctx);  // Now passing the SSL_CTX
        }
    } else {
        // Convert port (int) to string
        char port_str[6];  // Enough to hold max port number (65535) + null terminator
        snprintf(port_str, sizeof(port_str), "%d", config.port);  // Convert int to string

        BIO *unsecured_bio = create_unsecured_connection(config.server, port_str);
        if (unsecured_bio) {
            // Use the unsecured connection (send/receive IMAP commands)
            disconnect_unsecured(unsecured_bio);
        }
    }

    return 0;
}