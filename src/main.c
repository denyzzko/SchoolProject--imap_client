/**
 * @file main.c
 * @brief Main file for email client performing connection and communication with IMAP server
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

DynamicBuffer* create_buffer(size_t initial_size) {
    DynamicBuffer *buf = (DynamicBuffer *)malloc(sizeof(DynamicBuffer));
    if (!buf) {
        fprintf(stderr, "Error: Memory allocation for buffer struct failed\n");
        exit(1);
    }
    buf->buffer = (char *)malloc(initial_size);
    if (!buf->buffer) {
        fprintf(stderr, "Error: Memory allocation for buffer failed\n");
        free(buf);
        exit(1);
    }
    buf->size = initial_size;
    buf->length = 0;
    buf->buffer[0] = '\0';  // Initialize as an empty string
    return buf;
}

void resize_buffer(DynamicBuffer *buf, size_t new_size) {
    printf("----------------------------------------------resizing\n");
    char *new_buffer = (char *)realloc(buf->buffer, new_size);
    if (!new_buffer) {
        fprintf(stderr, "Error: Memory reallocation failed\n");
        free(buf->buffer);
        free(buf);
        exit(1);
    }
    buf->buffer = new_buffer;
    buf->size = new_size;
}


void write_to_buffer(DynamicBuffer *buf, const char *data) {
    size_t data_len = strlen(data);
    
    // Check if the current buffer can hold the new data, including the null terminator
    if (buf->length + data_len + 1 > buf->size) {
        resize_buffer(buf, buf->length + data_len + 1);  // Resize to exact required size
    }
    
    // Use strncat safely
    strncat(buf->buffer, data, data_len);
    buf->length += data_len;

}


void free_buffer(DynamicBuffer *buf) {
    if (buf) {
        if (buf->buffer) {
            free(buf->buffer);
        }
        free(buf);
    }
}

void initialize_config(struct Config *config) {
    config->server = create_buffer(128);
    config->certfile = create_buffer(128);
    config->certdir = create_buffer(128);
    config->auth_file = create_buffer(128);
    config->mailbox = create_buffer(128);
    config->out_dir = create_buffer(128);
    config->username = create_buffer(128);
    config->password = create_buffer(128);
}

void free_config(struct Config *config) {
    free_buffer(config->server);
    free_buffer(config->certfile);
    free_buffer(config->certdir);
    free_buffer(config->auth_file);
    free_buffer(config->mailbox);
    free_buffer(config->out_dir);
    free_buffer(config->username);
    free_buffer(config->password);
}

int main(int argc, char* argv[]) {
    struct Config config;

    // Initialize the Config structure with dynamic buffers
    initialize_config(&config);

    // Parse command-line arguments
    if (!ParseArguments(argc, argv, &config)) {
        free_config(&config);
        return 1;
    }

    // Create raw socket
    int sockfd = create_raw_socket(config.server->buffer, config.port);  // Use config.server->buffer
    if (sockfd < 0) {
        free_config(&config);
        return 1;
    }

    if (config.use_ssl) {
        // Secure connection
        initialize_openssl();
        // SSL context
        SSL_CTX *ctx = create_ssl_context(config.certfile->buffer, config.certdir->buffer);  // Use dynamic buffers
        if (!ctx) {
            ERR_print_errors_fp(stderr);
            close(sockfd);
            free_config(&config);
            return 1;
        }
        // SSL connection over the raw socket
        SSL *ssl = create_secure_connection(sockfd, ctx);
        if (!ssl) {
            close(sockfd);
            SSL_CTX_free(ctx);
            free_config(&config);
            return 1;
        }
        // Secure communication
        if (!SecureCommunication(ssl, &config)) {
            close_secure_connection(ssl, ctx);
            close(sockfd);
            free_config(&config);
            return 1;
        }
        // Clean up
        printf("Closing secure connection...\n");
        close_secure_connection(ssl, ctx);
        close(sockfd);
        printf("Socket closed\n");
    } else {
        // Unsecure communication
        if (!UnsecureCommunication(sockfd, &config)) {
            printf("Closing unsecure connection...\n");
            close(sockfd);
            free_config(&config);
            return 1;
        }
        // Clean up
        printf("Closing unsecure connection...\n");
        close(sockfd);  // Close unsecure socket
        printf("Socket closed\n");
    }

    // Free allocated memory for the Config structure
    free_config(&config);
    
    return 0;
}