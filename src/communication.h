#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <openssl/ssl.h>  // For SSL structures and functions
#include "main.h"

// helper function to extract uids from servers response
bool extract_uids(const char *search_response, char *all_uids, size_t uids_size);
// helper function to extract headers from email
void extract_header(const char *email_content, char *cleaned_email_buffer);
// helper function to extract body from email
void extract_body(const char *email_content, char *cleaned_email);

// command functions
bool loginUnsecure(int sockfd, const char *username, const char *password);
bool loginSecure(SSL *ssl, struct Config *config);
bool selectUnsecure(int sockfd, const char *mailbox);
bool selectSecure(SSL *ssl, const char *mailbox);
bool uidSearchUnsecure(int sockfd, bool new_only, char *buffer, size_t buffer_size);
bool fetchUnsecure(int sockfd, const char *out_dir, bool headers_only, bool new_only);
bool fetchSecure(SSL *ssl, const char *message_id);

// main function for secure IMAP communication using SSL
bool SecureCommunication(SSL *ssl, const struct Config *config);
// main function for unsecure IMAP communication using raw socket
bool UnsecureCommunication(int sockfd, const struct Config *config);

#endif
