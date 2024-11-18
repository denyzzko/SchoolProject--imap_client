/**
 * @file communication.c
 * @brief Implements secure and unsecure IMAP communication by handling the flow of IMAP commands and server responses over both SSL-secured and plain sockets
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 26.10.2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <errno.h>

#include "communication.h"
#include "main.h"

bool extract_uids(const char *search_response, DynamicBuffer *all_uids) {
    char *search_line = strcasestr(search_response, "* SEARCH ");
    if (!search_line) {
        // No emails found
        return true;
    }

    // Move pointer to the list of UIDs (skip "* SEARCH ")
    search_line += 9;

    // Collect and validate UIDs
    char *uid = strtok(search_line, " \r\n");
    bool uid_found = false;
    while (uid) {
        // Ensure the UID is numeric
        bool is_numeric = true;
        for (char *p = uid; *p; p++) {
            if (!isdigit(*p)) {
                is_numeric = false;
                break;
            }
        }

        // If numeric, append to the all_uids buffer
        if (is_numeric) {
            write_to_buffer(all_uids, uid);
            write_to_buffer(all_uids, " ");  // Add space separator
            uid_found = true;
        }

        // Move to the next token
        uid = strtok(NULL, " \r\n");
    }

    if (!uid_found) {
        // No valid UIDs found
        fprintf(stderr, "Error: No valid UIDs found in SEARCH response.\n");
        return false;
    } 

    // Return true if at least one UID was found
    return all_uids->length > 0;
}

bool store_uidvalidity(const char *file_path, const char *uidvalidity) {
    // Open file to write
    FILE *file = fopen(file_path, "w");
    if (!file) {
        // Opening file failed
        fprintf(stderr, "Error: opening file to store UIDValidity failed.\n");
        return false;
    }
    // Store value and close file
    fprintf(file, "%s\n", uidvalidity);
    fclose(file);
    return true;
}

bool compare_uidvalidity(const char *file_path, const char *new_uidvalidity) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        // File doesn't exist, create it
        store_uidvalidity(file_path, new_uidvalidity);
        // Return false to signal full download
        return false;
    }

    char stored_uidvalidity[256];
    fgets(stored_uidvalidity, sizeof(stored_uidvalidity), file);
    fclose(file);

    // Remove the \n at the end of stored UIDValidity
    size_t len = strlen(stored_uidvalidity);
    if (len > 0 && stored_uidvalidity[len - 1] == '\n') {
        stored_uidvalidity[len - 1] = '\0';
    }

    // Compare the stored and new values
    if (strcmp(stored_uidvalidity, new_uidvalidity) == 0) {
        // UIDValidity is the same, no need to download everything
        return true;
    } else {
        // UIDValidity has changed, update file
        store_uidvalidity(file_path, new_uidvalidity);
        // Return false to signal full download
        return false;
    }
}

size_t extract_email_size(const char *response) {
    const char *start = strchr(response, '{');
    if (!start) return 0; // If '{' is not found, return 0 (error case)

    size_t size;
    if (sscanf(start, "{%zu}", &size) == 1) {
        return size; // Return the size of the email content
    }
    return 0; // Error parsing size
}

int find_email_start(const char* response) {
    char* start = strchr(response, '}');
    if (start != NULL) {
        // Check for CRLF after }
        if (*(start + 1) == '\r' && *(start + 2) == '\n') {
            // Skipping '}CRLF'
            return (start - response) + 3;
        } else {
            // Skipping just '}'
            return (start - response) + 1;
        }
    }
    // } not found
    return -1;
}

char *strcasestr(const char *string, const char *keyword) {
    if (!*keyword) {
        return (char *)string;
    }

    for (; *string; string++) {
        if (tolower((unsigned char)*string) == tolower((unsigned char)*keyword)) {
            // Possible match, check rest of the keyword
            const char *s = string + 1;
            const char *k = keyword + 1;
            while (*k && *s && tolower((unsigned char)*s) == tolower((unsigned char)*k)) {
                s++;
                k++;
            }
            if (!*k) {
                // Full match
                return (char *)string;
            }
            // Continue searching
        }
    }
    return NULL;
}

bool loginSecure(SSL *ssl, DynamicBuffer *username, DynamicBuffer *password) {
    // Construct LOGIN command
    size_t login_cmd_size = 10 + username->length + password->length + 3; // B001 LOGIN + ... + \r\n
    DynamicBuffer *login_cmd = create_buffer(login_cmd_size);

    snprintf(login_cmd->buffer, login_cmd->size, "B001 LOGIN %s %s\r\n", username->buffer, password->buffer);
    login_cmd->length = strlen(login_cmd->buffer);

    // Send LOGIN command using SSL
    if (SSL_write(ssl, login_cmd->buffer, login_cmd->length) <= 0) {
        // Sending LOGIN command failed
        fprintf(stderr, "Error: SSL_write() for LOGIN command failed.\n");
        free_buffer(login_cmd);
        return false;
    }

    // Free the login command buffer
    free_buffer(login_cmd);

    // Recieve server response
    DynamicBuffer *response_buffer = create_buffer(512);
    int bytes;

    // Loop to handle potential multi part server response
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response
        
        // Check for server completion responses
        if (strcasestr(response_buffer->buffer, "B001 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                free_buffer(response_buffer);
                return true;  // Success
            } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            }
        } else if (strcasestr(response_buffer->buffer, "B001 NO") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - username or password rejected. (server's response NO)\n");
            free_buffer(response_buffer);
            return false;  // Fail
        } else if (strcasestr(response_buffer->buffer, "B001 BAD") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - command unknown or arguments invalid. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false;  // Fail
        }

        // Resize response buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        // Recieving response failed
        fprintf(stderr, "Error: SSL_read() failed for LOGIN response.\n");
        free_buffer(response_buffer);
        return false;
    }

    // When program got here some other unexpected failure happened
    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in LOGIN command. (possibly wrong server response or connection failure)\n");
    return false;
}


bool loginUnsecure(int sockfd, DynamicBuffer *username, DynamicBuffer *password) {
    /// Construct LOGIN command
    size_t login_cmd_size = 10 + username->length + password->length + 3; // A001 LOGIN + ... + \r\n
    DynamicBuffer *login_cmd = create_buffer(login_cmd_size);

    snprintf(login_cmd->buffer, login_cmd->size, "A001 LOGIN %s %s\r\n", username->buffer, password->buffer);
    login_cmd->length = strlen(login_cmd->buffer);

    // Send LOGIN command using unsecure socket
    if (send(sockfd, login_cmd->buffer, login_cmd->length, 0) < 0) {
        // Sending LOGIN command failed
        fprintf(stderr, "Error: send() for LOGIN command failed.\n");
        free_buffer(login_cmd);
        return false;
    }

    // Free the login command buffer
    free_buffer(login_cmd);

    // Recieve server response
    DynamicBuffer *response_buffer = create_buffer(512);
    int bytes;

    // Loop to handle potential multi part server response
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check for server completion responses
        if (strcasestr(response_buffer->buffer, "A001 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                free_buffer(response_buffer);
                return true;  // Success
            } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            }
        } else if (strcasestr(response_buffer->buffer, "A001 NO") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - username or password rejected. (server's response NO)\n");
            free_buffer(response_buffer);
            return false;  // Fail
        } else if (strcasestr(response_buffer->buffer, "A001 BAD") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - command unknown or arguments invalid. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false;  // Fail
        }

        // Resize response buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes < 0) {
        // Recieving response failed
        fprintf(stderr, "Error: recv() for LOGIN response failed.\n");
        free_buffer(response_buffer);
        return false;
    }

    // When program got here some other unexpected failure happened
    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in LOGIN command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool selectSecure(SSL *ssl, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity) {
    // Construct SELECT command
    size_t select_cmd_size = 12 + mailbox->length + 3;  // "A002 SELECT " + mailbox + "\r\n"
    DynamicBuffer *select_cmd = create_buffer(select_cmd_size);

    snprintf(select_cmd->buffer, select_cmd->size, "B002 SELECT %s\r\n", mailbox->buffer);
    select_cmd->length = strlen(select_cmd->buffer);

    // Send SELECT command using SSL
    if (SSL_write(ssl, select_cmd->buffer, select_cmd->length) <= 0) {
        fprintf(stderr, "Error: SSL_write() for SELECT command failed.\n");
        free_buffer(select_cmd);
        return false;
    }

    free_buffer(select_cmd);

    // Recieve server response
    DynamicBuffer *response_buffer = create_buffer(512);
    int bytes;

    // Loop to handle potential multi part server response
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check for server completion responses
        if (strcasestr(response_buffer->buffer, "B002 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                // Extract UIDVALIDITY from response
                char *uidvalidity_ptr = strcasestr(response_buffer->buffer, "[UIDVALIDITY ");
                if (uidvalidity_ptr) {
                    sscanf(uidvalidity_ptr, "[UIDVALIDITY %[^]]]", uidvalidity->buffer);
                    uidvalidity->length = strlen(uidvalidity->buffer);
                } else {
                    fprintf(stderr, "Error: UIDValidity not found in SELECT response.\n");
                    free_buffer(response_buffer);
                    return false;
                }
                free_buffer(response_buffer);
                return true; // Success
                } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            } 
        } else if (strcasestr(response_buffer->buffer, "B002 NO") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response NO)\n");
            free_buffer(response_buffer);
            return false; // Fail
        } else if (strcasestr(response_buffer->buffer, "B002 BAD") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false; // Fail
        }

        // Resize response buffer if needed
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        // Recieving response failed
        fprintf(stderr, "Error: SSL_read() failed for SELECT response.\n");
        free_buffer(response_buffer);
        return false;
    }

    // When program got here some other unexpected failure happened
    fprintf(stderr, "Error: Unexpected failure in SELECT command. (possibly wrong server response or connection failure)\n");
    free_buffer(response_buffer);
    return false;
}

bool selectUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity) {
    // Construct SELECT command
    size_t select_cmd_size = 12 + mailbox->length + 3;  // "A002 SELECT " + mailbox + "\r\n"
    DynamicBuffer *select_cmd = create_buffer(select_cmd_size);

    snprintf(select_cmd->buffer, select_cmd->size, "A002 SELECT %s\r\n", mailbox->buffer);
    select_cmd->length = strlen(select_cmd->buffer);

    // Send SELECT command using unsecure socket
    if (send(sockfd, select_cmd->buffer, select_cmd->length, 0) < 0) {
        fprintf(stderr, "Error: send() for SELECT command failed.\n");
        free_buffer(select_cmd);
        return false;
    }

    free_buffer(select_cmd);

    // Recieve server response
    DynamicBuffer *response_buffer = create_buffer(512);
    int bytes;

    // Loop to handle potential multi part server response
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check for server completion responses
        if (strcasestr(response_buffer->buffer, "A002 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                // Extract UIDVALIDITY from response
                char *uidvalidity_ptr = strcasestr(response_buffer->buffer, "[UIDVALIDITY ");
                if (uidvalidity_ptr) {
                    sscanf(uidvalidity_ptr, "[UIDVALIDITY %[^]]]", uidvalidity->buffer);
                    uidvalidity->length = strlen(uidvalidity->buffer);
                } else {
                    fprintf(stderr, "Error: UIDValidity not found in SELECT response.\n");
                    free_buffer(response_buffer);
                    return false;
                }
                free_buffer(response_buffer);
                return true; // Success
                } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            }
        } else if (strcasestr(response_buffer->buffer, "A002 NO") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response NO)\n");
            break; // Fail
        } else if (strcasestr(response_buffer->buffer, "A002 BAD") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response BAD)\n");
            break; // Fail
        }

        // Resize response buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes < 0) {
        // Recieving response failed
        fprintf(stderr, "Error: recv() failed for SELECT response.\n");
        free_buffer(response_buffer);
        return false;
    }

    // When program got here some other unexpected failure happened
    fprintf(stderr, "Error: Unexpected failure in SELECT command. (possibly wrong server response or connection failure)\n");
    free_buffer(response_buffer);
    return false;
}


bool uidSearchSecure(SSL *ssl, bool new_only, DynamicBuffer *response_buffer) {
    // Construct SEARCH command
    char search_cmd[64];
    if (new_only) {
        snprintf(search_cmd, sizeof(search_cmd), "B003 UID SEARCH NEW\r\n");
    } else {
        snprintf(search_cmd, sizeof(search_cmd), "B003 UID SEARCH ALL\r\n");
    }

    // Send SEARCH command using SSL
    if (SSL_write(ssl, search_cmd, strlen(search_cmd)) <= 0) {
        fprintf(stderr, "Error: SSL_write() for SEARCH command failed.\n");
        return false;
    }

    int bytes;
    // Loop to handle potential multi part server response
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check for server completion responses
        if (strcasestr(response_buffer->buffer, "B003 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                return true; // Success
                } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            }
        } else if (strcasestr(response_buffer->buffer, "B003 NO") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response NO)\n");
            return false; // Fail
        } else if (strcasestr(response_buffer->buffer, "B003 BAD") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response BAD)\n");
            return false; // Fail
        }

        // Resize buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        // Recieving response failed
        fprintf(stderr, "Error: SSL_read() failed for SEARCH command.\n");
        return false;
    }

    // When program got here some other unexpected failure happened
    fprintf(stderr, "Error: Unexpected failure in SEARCH command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool uidSearchUnsecure(int sockfd, bool new_only, DynamicBuffer *response_buffer) {
    /// Construct SEARCH command
    char search_cmd[64];
    if (new_only) {
        snprintf(search_cmd, sizeof(search_cmd), "A003 UID SEARCH NEW\r\n");
    } else {
        snprintf(search_cmd, sizeof(search_cmd), "A003 UID SEARCH ALL\r\n");
    }

    // Send SEARCH command using unsecure socket
    if (send(sockfd, search_cmd, strlen(search_cmd), 0) < 0) {
        fprintf(stderr, "Error: send() for UID SEARCH command failed.\n");
        return false;
    }

    int bytes;
    // Loop to handle potential multi part server response
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check for server completion responses
        if (strcasestr(response_buffer->buffer, "A003 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                return true; // Success
                } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            }
        } else if (strcasestr(response_buffer->buffer, "A003 NO") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response NO)\n");
            return false;  // Fail
        } else if (strcasestr(response_buffer->buffer, "A003 BAD") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response BAD)\n");
            return false; // Fail
        }

        // Resize buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        // Recieving response failed
        fprintf(stderr, "Error: recv() for UID SEARCH response failed.\n");
        return false;
    }

    // When program got here some other unexpected failure happened
    fprintf(stderr, "Error: Unexpected failure in SEARCH command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool fetchSecure(SSL *ssl, DynamicBuffer *server, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all) {
    DynamicBuffer *search_response_buffer = create_buffer(8192);  // Dynamic buffer for the response
    DynamicBuffer *all_uids = create_buffer(1024);  // Buffer to hold all UIDs
    int email_count = 0;

    // Send UID SEARCH command and get the response
    if (!uidSearchSecure(ssl, new_only, search_response_buffer)) {
        // SEARCH command failed
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Extract UIDs from SEARCH response
    if (!extract_uids(search_response_buffer->buffer, all_uids)) {
        // Extracting UIDs failed
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Fetch content (email or header) for each UID
    char *uid = strtok(all_uids->buffer, " ");
    int tag_counter = 5;

    while (uid) {
        // Construct filename 
        size_t filename_size = out_dir->length + server->length + mailbox->length + strlen(uid) + 30;
        DynamicBuffer *filename_buffer = create_buffer(filename_size);

        if (headers_only) {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_%s_email_%s_header.eml", out_dir->buffer, server->buffer, mailbox->buffer, uid);
        } else {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_%s_email_%s_full.eml", out_dir->buffer, server->buffer, mailbox->buffer, uid);
        }

        // Skip fetching if the email already exists and UIDVALIDITY has not changed
        if (!redownload_all && access(filename_buffer->buffer, F_OK) == 0) {
            // Email already exists in mailbox, skipping download
            free_buffer(filename_buffer);
            uid = strtok(NULL, " \r\n");
            continue;
        }

        // Construct FETCH command
        char fetch_cmd[128];
        char tag[16];
        int written = snprintf(tag, sizeof(tag), "B00%d", tag_counter++);
        if (written >= (int)sizeof(tag)) {
            fprintf(stderr, "Error: Exceeded supported tag length.\n");
        }

        if (headers_only) {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY.PEEK[HEADER]\r\n", tag, uid);
        } else {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY[]\r\n", tag, uid);
        }

        // Send FETCH command using SSL
        if (SSL_write(ssl, fetch_cmd, strlen(fetch_cmd)) <= 0) {
            fprintf(stderr, "Error: SSL_write() for UID FETCH command failed.\n");
            free_buffer(search_response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            return false;
        }

        // Recieving FETCH command response
        DynamicBuffer *response_buffer = create_buffer(4096);
        char email_buffer[4096];
        int email_bytes;
        
        size_t email_size = 0; // Size of email content
        bool size_extracted = false; // Flag if size is extracted
        bool first_crlf = false; // Flag to detect first line of response
        int email_start = 0; // Index of start of email content

        // Loop to handle potential multi part server response
        while ((email_bytes = SSL_read(ssl, email_buffer, sizeof(email_buffer) - 1)) > 0) {
            if (email_bytes > 0) {
                email_buffer[email_bytes] = '\0';
                write_to_buffer(response_buffer, email_buffer);

                if (!first_crlf) {
                    // Look for CRLF to mark end of first response line
                    if (strcasestr(response_buffer->buffer, "\r\n") != NULL) {
                        first_crlf = true;
                    }
                }
                
                // Extract email size and locate start of email content (not before first line was fully read)
                if (first_crlf == true){
                    if (!size_extracted) {
                        email_size = extract_email_size(response_buffer->buffer);
                        email_start = find_email_start(response_buffer->buffer);
                        if (email_start < 0) {
                            // Finding email start failed
                            fprintf(stderr, "Error: Could not find start of email content in first line of servers response.\n");
                            free_buffer(response_buffer);
                            free_buffer(all_uids);
                            free_buffer(filename_buffer);
                            free_buffer(search_response_buffer);
                            return false;
                        }
                        size_extracted = true;
                    }
                }
                
                // Check for server completion responses
                if (strcasestr(response_buffer->buffer, tag) && strcasestr(response_buffer->buffer, "OK") != NULL) {
                    // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
                    // Check if the last two characters in the buffer are \r\n
                    if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                        // Entire OK line has been received
                        break; // Success
                    } 
                    else {
                        // Not at end of response
                        continue;
                    }
                } 
                else if (strcasestr(response_buffer->buffer, tag) && strcasestr(response_buffer->buffer, "NO") != NULL) {
                    fprintf(stderr, "Error: UID FETCH command error. (server's response NO)\n");
                    free_buffer(response_buffer);
                    free_buffer(all_uids);
                    free_buffer(filename_buffer);
                    free_buffer(search_response_buffer);
                    return false; // Fail
                } 
                else if (strcasestr(response_buffer->buffer, tag) && strcasestr(response_buffer->buffer, "BAD") != NULL) {
                    fprintf(stderr, "Error: UID FETCH command error. (server's response BAD)\n");
                    free_buffer(response_buffer);
                    free_buffer(all_uids);
                    free_buffer(filename_buffer);
                    free_buffer(search_response_buffer);
                    return false; // Fail
                }

            }
        }

        if (email_bytes <= 0) {
            // Recieving response failed
            fprintf(stderr, "Error: SSL_read() for UID FETCH command failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        // Open file for writing the email or headers content
        FILE *file = fopen(filename_buffer->buffer, "w");
        if (!file) {
            // Opening file failed
            fprintf(stderr, "Error: opening file for writing email/headers failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        // Write exactly the email_size worth of bytes from the response_buffer
        for (size_t i = email_start; i < email_start + email_size; i++) {
            fputc(response_buffer->buffer[i], file);
        }

        // Completed write for current UID email content
        fclose(file);
        free_buffer(filename_buffer);
        free_buffer(response_buffer);

        email_count++;

        uid = strtok(NULL, " \r\n");
    }

    // Print summary of downloaded emails
    if (headers_only) {
        if (new_only) {
            fprintf(stdout, "Downloaded %d new headers from mailbox %s.\n", email_count, mailbox->buffer);
        } else {
            fprintf(stdout, "Downloaded %d headers from mailbox %s.\n", email_count, mailbox->buffer);
        }
    } else {
        if (new_only) {
            fprintf(stdout, "Downloaded %d new messages from mailbox %s.\n", email_count, mailbox->buffer);
        } else {
            fprintf(stdout, "Downloaded %d messages from mailbox %s.\n", email_count, mailbox->buffer);
        }
    }
    
    // Cleanup
    free_buffer(all_uids);
    free_buffer(search_response_buffer);

    return true;
}

bool fetchUnsecure(int sockfd, DynamicBuffer *server, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all) {
    DynamicBuffer *search_response_buffer = create_buffer(8192);
    DynamicBuffer *all_uids = create_buffer(1024);
    int email_count = 0;

    // Send UID SEARCH command and get the response
    if (!uidSearchUnsecure(sockfd, new_only, search_response_buffer)) {
        // SEARCH command failed
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Extract UIDs from SEARCH response
    if (!extract_uids(search_response_buffer->buffer, all_uids)) {
        // Extracting UIDs failed
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Fetch content (email or header) for each UID
    char *uid = strtok(all_uids->buffer, " ");
    int tag_counter = 5;

    while (uid) {
        // Construct filename 
        size_t filename_size = out_dir->length + server->length + mailbox->length + strlen(uid) + 30;
        DynamicBuffer *filename_buffer = create_buffer(filename_size);

        if (headers_only) {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_%s_email_%s_header.eml", out_dir->buffer, server->buffer, mailbox->buffer, uid);
        } else {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_%s_email_%s_full.eml", out_dir->buffer, server->buffer, mailbox->buffer, uid);
        }

        // Skip fetching if the email already exists and UIDVALIDITY has not changed
        if (!redownload_all && access(filename_buffer->buffer, F_OK) == 0) {
            // Email already exists in mailbox, skipping download
            free_buffer(filename_buffer);
            uid = strtok(NULL, " \r\n");
            continue;
        }

        // Construct FETCH command
        char fetch_cmd[128];
        char tag[16];
        int written = snprintf(tag, sizeof(tag), "A00%d", tag_counter++);
        if (written >= (int)sizeof(tag)) {
            fprintf(stderr, "Error: Exceeded supported tag length.\n");
        }

        if (headers_only) {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY.PEEK[HEADER]\r\n", tag, uid);
        } else {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY[]\r\n", tag, uid);
        }

        // Send FETCH command using unsecure socket
        if (send(sockfd, fetch_cmd, strlen(fetch_cmd), 0) < 0) {
            fprintf(stderr, "Error: send() for UID FETCH command failed.\n");
            free_buffer(search_response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            return false;
        }
        
        // Recieving FETCH command response
        DynamicBuffer *response_buffer = create_buffer(4096);
        char email_buffer[4096];
        int email_bytes;
        
        size_t email_size = 0; // Size of email content
        bool size_extracted = false; // Flag if size is extracted
        bool first_crlf = false; // Flag to detect first line of response
        int email_start = 0; // Index of start of email content

        // Loop to handle potential multi part server response
        while ((email_bytes = recv(sockfd, email_buffer, sizeof(email_buffer) - 1, 0)) > 0) {
            if (email_bytes > 0) {
                email_buffer[email_bytes] = '\0';
                write_to_buffer(response_buffer, email_buffer);

                if (!first_crlf) {
                    // Look for CRLF to mark end of first response line
                    if (strcasestr(response_buffer->buffer, "\r\n") != NULL) {
                        first_crlf = true;
                    }
                }
                    
                // Extract email size and locate start of email content (not before first line was fully read)
                if (first_crlf == true){
                    if (!size_extracted) {
                        email_size = extract_email_size(response_buffer->buffer);
                        email_start = find_email_start(response_buffer->buffer);
                        if (email_start < 0) {
                            // Finding email start failed
                            fprintf(stderr, "Error: Could not find start of email content in first line of servers response.\n");
                            free_buffer(response_buffer);
                            free_buffer(all_uids);
                            free_buffer(filename_buffer);
                            free_buffer(search_response_buffer);
                            return false;
                        }
                        size_extracted = true;
                    }
                }
                // Check for server completion responses
                if (strcasestr(response_buffer->buffer, tag) && strcasestr(response_buffer->buffer, "OK") != NULL) {
                    // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
                    // Check if the last two characters in the buffer are \r\n
                    if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                        // Entire OK line has been received
                        break; // Success
                    } 
                    else {
                        // Not at end of response
                        continue;
                    }
                } 
                else if (strcasestr(response_buffer->buffer, tag) && strcasestr(response_buffer->buffer, "NO") != NULL) {
                    fprintf(stderr, "Error: UID FETCH command error. (server's response NO)\n");
                    free_buffer(response_buffer);
                    free_buffer(all_uids);
                    free_buffer(filename_buffer);
                    free_buffer(search_response_buffer);
                    return false; // Fail
                } 
                else if (strcasestr(response_buffer->buffer, tag) && strcasestr(response_buffer->buffer, "BAD") != NULL) {
                    fprintf(stderr, "Error: UID FETCH command error. (server's response BAD)\n");
                    free_buffer(response_buffer);
                    free_buffer(all_uids);
                    free_buffer(filename_buffer);
                    free_buffer(search_response_buffer);
                    return false; // Fail
                }
            }
        }

        if (email_bytes <= 0) {
            // Recieving response failed
            fprintf(stderr, "Error: recv() for UID FETCH command failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        // Open file for writing the email or headers content
        FILE *file = fopen(filename_buffer->buffer, "w");
        if (!file) {
            // Opening file failed
            fprintf(stderr, "Error: opening file for writing email/headers failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        // Write exactly the email_size worth of bytes from the response_buffer
        for (size_t i = email_start; i < email_start + email_size; i++) {
            fputc(response_buffer->buffer[i], file);
        }

        // Completed write for current UID email content
        fclose(file);
        free_buffer(filename_buffer);
        free_buffer(response_buffer);
        email_count++;
        uid = strtok(NULL, " \r\n");
    }

    // Print summary of downloaded emails
    if (headers_only) {
        if (new_only) {
            fprintf(stdout, "Downloaded %d new headers from mailbox %s.\n", email_count, mailbox->buffer);
        } else {
            fprintf(stdout, "Downloaded %d headers from mailbox %s.\n", email_count, mailbox->buffer);
        }
    } else {
        if (new_only) {
            fprintf(stdout, "Downloaded %d new messages from mailbox %s.\n", email_count, mailbox->buffer);
        } else {
            fprintf(stdout, "Downloaded %d messages from mailbox %s.\n", email_count, mailbox->buffer);
        }
    }

    // Cleanup
    free_buffer(all_uids);
    free_buffer(search_response_buffer);

    return true;
}

bool logoutSecure(SSL *ssl) {
    char logout_cmd[] = "B004 LOGOUT\r\n";

    // Send LOGOUT command using SSL
    if (SSL_write(ssl, logout_cmd, strlen(logout_cmd)) <= 0) {
        fprintf(stderr, "Error: SSL_write() for LOGOUT command failed.\n");
        return false;
    }

    // Recieving LOGOUT command response
    DynamicBuffer *response_buffer = create_buffer(1024);
    int bytes;

    // Loop to handle potential multi part server response
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        if (strcasestr(response_buffer->buffer, "B004 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                free_buffer(response_buffer);
                return true; // Success
                } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            }
        } else if (strcasestr(response_buffer->buffer, "B004 BAD") != NULL) {
            fprintf(stderr, "Error: LOGOUT command failed. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false; // Fail
        }

        // Resize buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        // Recieving response failed
        fprintf(stderr, "Error: SSL_read() failed for LOGOUT response.\n");
        free_buffer(response_buffer);
        return false;
    }

    // When program got here some other unexpected failure happened
    fprintf(stderr, "Error: Unexpected failure in LOGOUT command. (possibly wrong server response or connection failure)\n");
    free_buffer(response_buffer);
    return false;
}

bool logoutUnsecure(int sockfd) {
    char logout_cmd[] = "A004 LOGOUT\r\n";

    // Send LOGOUT command using unsecure socket
    if (send(sockfd, logout_cmd, strlen(logout_cmd), 0) < 0) {
        fprintf(stderr, "Error: send() for LOGOUT command failed.\n");
        return false;
    }

    // Recieving LOGOUT command response
    DynamicBuffer *response_buffer = create_buffer(1024);  // Initial buffer size
    int bytes;

    // Loop to handle potential multi part server response
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check for a successful logout response
        if (strcasestr(response_buffer->buffer, "A004 OK") != NULL) {
            // For cases when recieved "OK" byt som bytes are still left to be read from response (they did not fit to buffer)
            // Check if the last two characters in the buffer are \r\n
            if (response_buffer->buffer[response_buffer->length - 2] == '\r' && response_buffer->buffer[response_buffer->length - 1] == '\n') {
                // Entire OK line has been received
                free_buffer(response_buffer);
                return true; // Success
                } 
            else {
                // Not at end of response
                // Resize response buffer if necessary
                if (response_buffer->length + 1 >= response_buffer->size) {
                    resize_buffer(response_buffer, response_buffer->size * 2);
                }
                continue;
            }
        } else if (strcasestr(response_buffer->buffer, "A004 BAD") != NULL) {
            fprintf(stderr, "Error: LOGOUT command failed. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false; // Fail
        }

        // Resize buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes < 0) {
        // Recieving response failed
        fprintf(stderr, "Error: recv() for LOGOUT command response failed.\n");
        free_buffer(response_buffer);
        return false;
    }

    // When program got here some other unexpected failure happened
    fprintf(stderr, "Error: Unexpected failure in LOGOUT command. (possibly wrong server response or connection failure)\n");
    free_buffer(response_buffer);
    return false;
}

bool SecureCommunication(SSL *ssl, const struct Config *config) {
    DynamicBuffer *uidvalidity = create_buffer(256);
    const char *uidvalidity_file = "uidvalidity.txt";

    // LOGIN with provided username and password
    if (!loginSecure(ssl, config->username, config->password)) {
        // LOGIN failed
        free_buffer(uidvalidity);
        return false;
    }

    // SELECT mailbox and retrieve UIDValidity
    if (!selectSecure(ssl, config->mailbox, uidvalidity)) {
        // SELECT failed
        logoutSecure(ssl);
        free_buffer(uidvalidity);
        return false;
    }

    // Compare uidvalidity to check it is same or not
    bool same_uidvalidity = compare_uidvalidity(uidvalidity_file, uidvalidity->buffer);

    // FETCH emails or headers based on configuration
    if (!fetchSecure(ssl, config-> server, config->mailbox, config->out_dir, config->headers_only, config->new_only, !same_uidvalidity)) {
        // FETCH failed
        logoutSecure(ssl);
        free_buffer(uidvalidity);
        return false;
    }

    // LOGOUT
    if (!logoutSecure(ssl)) {
        // LOGOUT failed
        free_buffer(uidvalidity);
        return false;
    }

    // CLean up
    free_buffer(uidvalidity);
    return true;
}


bool UnsecureCommunication(int sockfd, const struct Config *config) {
    DynamicBuffer *uidvalidity = create_buffer(256);
    const char *uidvalidity_file = "uidvalidity.txt";

    // LOGIN with provided username and password
    if (!loginUnsecure(sockfd, config->username, config->password)) {
        // LOGIN failed
        free_buffer(uidvalidity);
        return false;
    }
    
    // SELECT mailbox and retrieve UIDValidity
    if (!selectUnsecure(sockfd, config->mailbox, uidvalidity)) {
        // SELECT failed
        logoutUnsecure(sockfd);
        free_buffer(uidvalidity);
        return false;
    }

    // Compare uidvalidity to check it is same or not
    bool same_uidvalidity = compare_uidvalidity(uidvalidity_file, uidvalidity->buffer);

    // FETCH emails or headers based on configuration
    if (!fetchUnsecure(sockfd,config->server, config->mailbox, config->out_dir, config->headers_only, config->new_only, !same_uidvalidity)) {
        // FETCH failed
        logoutUnsecure(sockfd);
        free_buffer(uidvalidity);
        return false;
    }

    // LOGOUT
    if (!logoutUnsecure(sockfd)) {
        // LOGOUT failed
        free_buffer(uidvalidity);
        return false;
    }

    // CLean up
    free_buffer(uidvalidity);
    return true;
}