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

#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

DynamicBuffer* create_buffer(size_t initial_size) {
    // Allocate memory for DynamicBuffer structure
    DynamicBuffer *buf = (DynamicBuffer *)malloc(sizeof(DynamicBuffer));
    if (!buf) {
        // Allocation failed
        fprintf(stderr, "Error: Memory allocation for buffer struct failed\n");
        exit(1);
    }
    // Allocate memory for buffer
    buf->buffer = (char *)malloc(initial_size);
    if (!buf->buffer) {
        // Allocation failed
        fprintf(stderr, "Error: Memory allocation for buffer failed\n");
        free(buf);
        exit(1);
    }
    // Initialize buffer
    buf->size = initial_size;
    buf->length = 0;
    buf->buffer[0] = '\0';
    return buf;
}

void resize_buffer(DynamicBuffer *buf, size_t new_size) {
    // Reallocate buffer to new_size
    char *new_buffer = (char *)realloc(buf->buffer, new_size);
    if (!new_buffer) {
        // Reallocation failed
        fprintf(stderr, "Error: Memory reallocation failed\n");
        free(buf->buffer);
        free(buf);
        exit(1);
    }
    // Update buffer pointer and size
    buf->buffer = new_buffer;
    buf->size = new_size;
}

void write_to_buffer(DynamicBuffer *buf, const char *data) {
    size_t data_len = strlen(data);
    
    // Check if current buffer can hold new data
    if (buf->length + data_len + 1 > buf->size) {
        // Resize
        resize_buffer(buf, (buf->length + data_len + 1)*2);
    }
    
    // Append new data to the buffer and update length
    strncat(buf->buffer, data, data_len);
    buf->length += data_len;

}

void free_buffer(DynamicBuffer *buf) {
    if (buf) {
        if (buf->buffer) {
            // Free buffer
            free(buf->buffer);
        }
        // Free DynamicBuffer structure
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

    // Create raw socket and connect to server using TCP
    int sockfd = create_raw_socket(config.server->buffer, config.port);
    if (sockfd < 0) {
        free_config(&config);
        return 1;
    }

    if (config.use_ssl) {
        // SECURE COMMUNICATION
        initialize_openssl();
        // Create SSL context with specified certificates
        SSL_CTX *ctx = create_ssl_context(config.certfile->buffer, config.certdir->buffer);
        if (!ctx) {
            // SSL context creation failed
            ERR_print_errors_fp(stderr);
            close(sockfd);
            free_config(&config);
            return 1;
        }
        // Establish SSL connection over the raw socket
        SSL *ssl = create_secure_connection(sockfd, ctx);
        if (!ssl) {
            // SSL connection failed
            close(sockfd);
            SSL_CTX_free(ctx);
            free_config(&config);
            return 1;
        }
        // Perform secure communication over SSL
        if (!SecureCommunication(ssl, &config)) {
            // Communication failed
            close_secure_connection(ssl, ctx);
            close(sockfd);
            free_config(&config);
            return 1;
        }
        // Closing secure connection
        close_secure_connection(ssl, ctx);
    } else {
        // UNSECURE COMMUNICATION
        if (!UnsecureCommunication(sockfd, &config)) {
            // Unsecure communication failed
            close(sockfd);
            free_config(&config);
            return 1;
        }
    }
    
    // Close the socket after communication
    close(sockfd);

    // Clean allocated memory for the Config structure
    free_config(&config);
    
    return 0;
}