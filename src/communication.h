/**
 * @file communication.h
 * @brief Header file for communication.c
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 13.10.2024
 */

#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <openssl/ssl.h>
#include "main.h"

#define TIMEOUT_SEC 10

// Helper function to extract uids from server response
bool extract_uids(const char *search_response, DynamicBuffer *all_uids);
// Helper function to store UIDValidity into a file
bool store_uidvalidity(const char *file_path, const char *uidvalidity);
// Helper function to compare new UIDValidity with stored UIDValidity
bool compare_uidvalidity(const char *file_path, const char *new_uidvalidity);
// Helper function to extract email size from server response
size_t extract_email_size(const char *response);
// Helper function to find start of the email content from server response
int find_email_start(const char* response);
// Helper function to compare strings in case-insensitive way
char *strcasestr(const char *string, const char *keyword);

// Functions that perform LOGIN command
bool loginSecure(SSL *ssl, DynamicBuffer *username, DynamicBuffer *password);
bool loginUnsecure(int sockfd, DynamicBuffer *username, DynamicBuffer *password);
// Functions that perform SELECT command
bool selectSecure(SSL *ssl, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity);
bool selectUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity);
// Functions that perform SEARCH command
bool uidSearchSecure(SSL *ssl, bool new_only, DynamicBuffer *response_buffer);
bool uidSearchUnsecure(int sockfd, bool new_only, DynamicBuffer *response_buffer);
// Functions that perform FETCH command
bool fetchSecure(SSL *ssl, DynamicBuffer *server, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all);
bool fetchUnsecure(int sockfd, DynamicBuffer *server, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all);
// Functions that perform LOGOUT command
bool logoutSecure(SSL *ssl);
bool logoutUnsecure(int sockfd);

// Main function for secure communication using SSL
bool SecureCommunication(SSL *ssl, const struct Config *config);
// Main function for unsecure communication using plain socket
bool UnsecureCommunication(int sockfd, const struct Config *config);

#endif
