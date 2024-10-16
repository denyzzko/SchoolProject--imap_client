/**
 * @file communication.h
 * @brief Header file for communication.c
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 13.10.2024
 */

#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <openssl/ssl.h>  // For SSL structures and functions
#include "main.h"

#define TIMEOUT_SEC 10

// helper function to extract uids from servers response
bool extract_uids(const char *search_response, char *all_uids, size_t uids_size);
// helper function to store UIDValidity into a file
bool store_uidvalidity(const char *file_path, const char *uidvalidity);
// helper function to compare UIDValidity with stored value
bool compare_uidvalidity(const char *file_path, const char *new_uidvalidity);
// helper function to wait for data
int wait_for_socket(int sockfd, int timeout_sec);

// function that performs LOGIN command
bool loginSecure(SSL *ssl, DynamicBuffer *username, DynamicBuffer *password);
bool loginUnsecure(int sockfd, DynamicBuffer *username, DynamicBuffer *password);
// function that performs SELECT command
bool selectSecure(SSL *ssl, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity);
//bool selectUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity);

bool selectUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity);

// function that performs SEARCH command
bool uidSearchSecure(SSL *ssl, bool new_only, DynamicBuffer *response_buffer);
bool uidSearchUnsecure(int sockfd, bool new_only, DynamicBuffer *response_buffer);
// function that performs FETCH command
bool fetchSecure(SSL *ssl, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all);
bool fetchUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all);
// function that performs LOGOUT command
bool logoutSecure(SSL *ssl);
bool logoutUnsecure(int sockfd);

// main function for secure communication using SSL
bool SecureCommunication(SSL *ssl, const struct Config *config);
// main function for unsecure communication using raw socket
bool UnsecureCommunication(int sockfd, const struct Config *config);

#endif
