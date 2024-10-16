/**
 * @file main.h
 * @brief Header file for main.c
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdbool.h>
#include <stdlib.h>

#define MAX_STR_LEN 256

// Dynamic string buffer structure
typedef struct {
    char *buffer;     // Pointer to the dynamically allocated buffer
    size_t size;      // Current allocated size of the buffer
    size_t length;    // Current length of data in the buffer
} DynamicBuffer;

// Config structure to hold parsed arguments
struct Config {
    DynamicBuffer *server;
    int port;
    bool use_ssl;
    DynamicBuffer *certfile;
    DynamicBuffer *certdir;
    bool new_only;
    bool headers_only;
    DynamicBuffer *auth_file;
    DynamicBuffer *mailbox;
    DynamicBuffer *out_dir;
    DynamicBuffer *username;
    DynamicBuffer *password;
};

// Function to allocate memory for a buffer
DynamicBuffer* create_buffer(size_t initial_size);
// Function to reallocate the buffer when more space is needed
void resize_buffer(DynamicBuffer *buf, size_t new_size);
// Function to write data into the buffer and resize if needed
void write_to_buffer(DynamicBuffer *buf, const char *data);
// Free the dynamic buffer
void free_buffer(DynamicBuffer *buf);
// Allocate memory for the Config structure
void initialize_config(struct Config *config);
// Free the memory for the Config structure
void free_config(struct Config *config);

#endif