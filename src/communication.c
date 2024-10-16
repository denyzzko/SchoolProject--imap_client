/**
 * @file communication.c
 * @brief Implements secure and unsecure IMAP communication by handling the flow of IMAP commands and server responses over both SSL-secured and plain sockets
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 13.10.2024
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

#include <errno.h>  // For errno

#include "communication.h"
#include "main.h"

bool extract_uids(const char *search_response, char *all_uids, size_t uids_size) {
    char *search_line = strstr(search_response, "* SEARCH ");
    if (!search_line) {
        printf("No new emails found.\n");
        return true;
    }

    // Move pointer to the list of UIDs (skip "* SEARCH ")
    search_line += 9;

    // Collect and validate UIDs
    char *uid = strtok(search_line, " \r\n");
    bool uid_found = false;
    while (uid) {
        // Ensure the UID is numeric (skip invalid UIDs like "A003" or "OK")
        bool is_numeric = true;
        for (char *p = uid; *p; p++) {
            if (!isdigit(*p)) {
                is_numeric = false;
                break;
            }
        }

        // If numeric, append to the all_uids buffer
        if (is_numeric) {
            strncat(all_uids, uid, uids_size - strlen(all_uids) - 1);  // Ensure no overflow
            strncat(all_uids, " ", uids_size - strlen(all_uids) - 1);  // Add a space between UIDs
            uid_found = true;
        } else {
            printf("Skipping invalid UID: %s\n", uid);
        }

        // Move to the next token
        uid = strtok(NULL, " \r\n");
    }

    if (!uid_found) {
        fprintf(stderr, "Error: No valid UIDs found in SEARCH response.\n");
        return false;  // Returning false to indicate failure
    }

    // Print all valid UIDs
    printf("Valid UIDs: %s\n", all_uids);

    return strlen(all_uids) > 0;
}

bool store_uidvalidity(const char *file_path, const char *uidvalidity) {
    FILE *file = fopen(file_path, "w");
    if (!file) {
        fprintf(stderr, "Error: opening file to store UIDValidity failed.\n");
        return false;
    }
    fprintf(file, "%s\n", uidvalidity);
    fclose(file);
    return true;
}

// Function to compare UIDValidity with stored value
bool compare_uidvalidity(const char *file_path, const char *new_uidvalidity) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        // File doesn't exist, so create it and return false to signal full download
        store_uidvalidity(file_path, new_uidvalidity);
        return false;
    }

    char stored_uidvalidity[256];
    fgets(stored_uidvalidity, sizeof(stored_uidvalidity), file);
    fclose(file);

    // Remove the newline character at the end of the stored UIDValidity
    size_t len = strlen(stored_uidvalidity);
    if (len > 0 && stored_uidvalidity[len - 1] == '\n') {
        stored_uidvalidity[len - 1] = '\0';
    }

    // Compare the stored and new UIDValidity values
    if (strcmp(stored_uidvalidity, new_uidvalidity) == 0) {
        printf("UID IS SAME\n");
        return true; // UIDValidity is the same, no need to download everything
    } else {
        // UIDValidity has changed, so update the file and return false
        printf("UID IS NOT SAME\n");
        store_uidvalidity(file_path, new_uidvalidity);
        return false;
    }
}

bool loginSecure(SSL *ssl, DynamicBuffer *username, DynamicBuffer *password) {
    // Create a DynamicBuffer for the login command
    size_t login_cmd_size = 10 + username->length + password->length + 3; // "B001 LOGIN ", " ", "\r\n"
    DynamicBuffer *login_cmd = create_buffer(login_cmd_size);

    // Format the login command dynamically
    snprintf(login_cmd->buffer, login_cmd->size, "B001 LOGIN %s %s\r\n", username->buffer, password->buffer);
    login_cmd->length = strlen(login_cmd->buffer);  // Update the length after formatting

    // Send the login command using SSL
    if (SSL_write(ssl, login_cmd->buffer, login_cmd->length) <= 0) {
        fprintf(stderr, "Error: SSL_write() for LOGIN command failed.\n");
        free_buffer(login_cmd);
        return false;
    }

    printf("Sent login command: %s", login_cmd->buffer);

    // Free the login command buffer
    free_buffer(login_cmd);

    // Use DynamicBuffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(512);  // Initial buffer size
    int bytes;

    // Loop to handle potentially multi-part server responses
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        if (strstr(response_buffer->buffer, "B001 OK") != NULL) {
            printf("Login successful\n");
            free_buffer(response_buffer);
            return true;  // Success
        } else if (strstr(response_buffer->buffer, "B001 NO") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - username or password rejected. (server's response NO)\n");
            free_buffer(response_buffer);
            return false;  // Failure
        } else if (strstr(response_buffer->buffer, "B001 BAD") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - command unknown or arguments invalid. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false;  // Failure
        }

        // Resize the response buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        fprintf(stderr, "Error: SSL_read() failed for LOGIN response.\n");
        free_buffer(response_buffer);
        return false;
    }

    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in LOGIN command. (possibly wrong server response or connection failure)\n");
    return false;
}


bool loginUnsecure(int sockfd, DynamicBuffer *username, DynamicBuffer *password) {
    // Create a DynamicBuffer for the login command
    size_t login_cmd_size = 10 + username->length + password->length + 3; // "A001 LOGIN ", " ", "\r\n"
    DynamicBuffer *login_cmd = create_buffer(login_cmd_size);

    // Format the login command dynamically
    snprintf(login_cmd->buffer, login_cmd->size, "A001 LOGIN %s %s\r\n", username->buffer, password->buffer);
    login_cmd->length = strlen(login_cmd->buffer);  // Update the length after formatting

    // Send the login command using the unsecure socket
    if (send(sockfd, login_cmd->buffer, login_cmd->length, 0) < 0) {
        fprintf(stderr, "Error: send() for LOGIN command failed.\n");
        free_buffer(login_cmd);
        return false;
    }

    printf("Sent login command: %s", login_cmd->buffer);

    // Free the login command buffer
    free_buffer(login_cmd);

    // Use DynamicBuffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(512);  // Initial buffer size
    int bytes;

    // Loop to handle potentially multi-part server responses
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        printf("Server login response: %s\n", response_buffer->buffer);

        // Check for success or failure in the response
        if (strstr(response_buffer->buffer, "A001 OK") != NULL) {
            printf("Login successful\n");
            free_buffer(response_buffer);
            return true;  // Success
        } else if (strstr(response_buffer->buffer, "A001 NO") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - username or password rejected. (server's response NO)\n");
            free_buffer(response_buffer);
            return false;  // Failure
        } else if (strstr(response_buffer->buffer, "A001 BAD") != NULL) {
            fprintf(stderr, "Error: LOGIN failure - command unknown or arguments invalid. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false;  // Failure
        }

        // Resize the response buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    // Error handling if recv returns -1 (error)
    if (bytes < 0) {
        fprintf(stderr, "Error: recv() for LOGIN response failed.\n");
        free_buffer(response_buffer);
        return false;
    }

    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in LOGIN command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool selectSecure(SSL *ssl, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity) {
    // Create a dynamic buffer for the SELECT command
    size_t select_cmd_size = 10 + mailbox->length + 3;  // "B002 SELECT " + mailbox + "\r\n"
    DynamicBuffer *select_cmd = create_buffer(select_cmd_size);
    
    // Format the SELECT command
    snprintf(select_cmd->buffer, select_cmd->size, "B002 SELECT %s\r\n", mailbox->buffer);
    select_cmd->length = strlen(select_cmd->buffer);

    // Send the SELECT command using SSL
    if (SSL_write(ssl, select_cmd->buffer, select_cmd->length) <= 0) {
        fprintf(stderr, "Error: SSL_write() for SELECT command failed.\n");
        free_buffer(select_cmd);
        return false;
    }

    printf("Sent select command: %s", select_cmd->buffer);
    free_buffer(select_cmd);

    // Create a dynamic buffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(512);
    int bytes;

    // Read the server's response
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check for successful response
        if (strstr(response_buffer->buffer, "B002 OK") != NULL) {
            char *uidvalidity_ptr = strstr(response_buffer->buffer, "[UIDVALIDITY ");
            if (uidvalidity_ptr) {
                sscanf(uidvalidity_ptr, "[UIDVALIDITY %[^]]]", uidvalidity->buffer);
                uidvalidity->length = strlen(uidvalidity->buffer);
                printf("Extracted UIDVALIDITY: '%s'\n", uidvalidity->buffer);
            } else {
                fprintf(stderr, "Error: UIDValidity not found in SELECT response.\n");
                free_buffer(response_buffer);
                return false;
            }
            free_buffer(response_buffer);
            return true;
        } else if (strstr(response_buffer->buffer, "B002 NO") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response NO)\n");
            free_buffer(response_buffer);
            return false;
        } else if (strstr(response_buffer->buffer, "B002 BAD") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false;
        }

        // Resize the response buffer if needed
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        fprintf(stderr, "Error: SSL_read() failed for SELECT response.\n");
        free_buffer(response_buffer);
        return false;
    }

    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in SELECT command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool listMailboxesUnsecure(int sockfd) {
    // Create a dynamic buffer for the LIST command
    DynamicBuffer *list_cmd = create_buffer(32);
    snprintf(list_cmd->buffer, list_cmd->size, "A003 LIST \"\" \"*\"\r\n");
    list_cmd->length = strlen(list_cmd->buffer);

    // Send the LIST command
    if (send(sockfd, list_cmd->buffer, list_cmd->length, 0) < 0) {
        fprintf(stderr, "Error: send() for LIST command failed.\n");
        free_buffer(list_cmd);
        return false;
    }

    printf("Sent list command: '%s'\n", list_cmd->buffer);
    free_buffer(list_cmd);

    // Create a dynamic buffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(1024);
    int bytes;

    // Read the server's response
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        printf("Server LIST response: %s\n", response_buffer->buffer);

        // Check for "A003 OK" indicating the end of the response
        if (strstr(response_buffer->buffer, "A003 OK") != NULL) {
            printf("Mailbox listing completed.\n");
            free_buffer(response_buffer);
            return true;
        }

        // Resize the buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        fprintf(stderr, "Error: recv() failed for LIST response.\n");
    }

    free_buffer(response_buffer);
    return false;
}
/*
bool selectUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity) {
    // Create a dynamic buffer for the SELECT command
    size_t select_cmd_size = 10 + mailbox->length + 3;  // "A002 SELECT " + mailbox + "\r\n"
    DynamicBuffer *select_cmd = create_buffer(select_cmd_size);
    
    // Format the SELECT command
    snprintf(select_cmd->buffer, select_cmd->size, "A002 SELECT %s\r\n", mailbox->buffer);
    select_cmd->length = strlen(select_cmd->buffer);

    // Send the SELECT command
    if (send(sockfd, select_cmd->buffer, select_cmd->length, 0) < 0) {
        fprintf(stderr, "Error: send() for SELECT command failed.\n");
        free_buffer(select_cmd);
        return false;
    }

    printf("Sent select command: '%s'\n", select_cmd->buffer);
    free_buffer(select_cmd);

    // Create a dynamic buffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(1024);
    int bytes;

    // Loop to handle potentially multi-part server responses
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        printf("Server select response: %s\n", response_buffer->buffer);

        // Check if the server responded with OK
        if (strstr(response_buffer->buffer, "A002 OK") != NULL) {
            char *uidvalidity_ptr = strstr(response_buffer->buffer, "[UIDVALIDITY ");
            if (uidvalidity_ptr) {
                sscanf(uidvalidity_ptr, "[UIDVALIDITY %[^]]]", uidvalidity->buffer);
                uidvalidity->length = strlen(uidvalidity->buffer);
                printf("Extracted UIDVALIDITY: '%s'\n", uidvalidity->buffer);
            } else {
                fprintf(stderr, "Error: UIDValidity not found in SELECT response.\n");
                free_buffer(response_buffer);
                return false;
            }
            free_buffer(response_buffer);
            return true;
        } else if (strstr(response_buffer->buffer, "A002 NO") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response NO)\n");
            break;
        } else if (strstr(response_buffer->buffer, "A002 BAD") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response BAD)\n");
            break;
        }

        // Resize the response buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes < 0) {
        fprintf(stderr, "Error: recv() failed for SELECT response.\n");
    }

    free_buffer(response_buffer);
    return false;
}

*/

bool selectUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *uidvalidity) {
    // Prepare the SELECT command
    char select_cmd[512];
    snprintf(select_cmd, sizeof(select_cmd), "A002 SELECT %s\r\n", mailbox->buffer);

    // Send the SELECT command
    if (send(sockfd, select_cmd, strlen(select_cmd), 0) < 0) {
        fprintf(stderr, "Error: send() for SELECT command failed.\n");
        return false;
    }

    printf("Sent select command: %s\n", select_cmd);

    
    // Create a dynamic buffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(512);
    int bytes;

    // Loop to handle potentially multi-part server responses
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        printf("Server select response: %s\n", response_buffer->buffer);

        // Check if the server responded with OK
        if (strstr(response_buffer->buffer, "A002 OK") != NULL) {
            char *uidvalidity_ptr = strstr(response_buffer->buffer, "[UIDVALIDITY ");
            if (uidvalidity_ptr) {
                sscanf(uidvalidity_ptr, "[UIDVALIDITY %[^]]]", uidvalidity->buffer);
                uidvalidity->length = strlen(uidvalidity->buffer);
                printf("Extracted UIDVALIDITY: '%s'\n", uidvalidity->buffer);
            } else {
                fprintf(stderr, "Error: UIDValidity not found in SELECT response.\n");
                free_buffer(response_buffer);
                return false;
            }
            free_buffer(response_buffer);
            return true;
        } else if (strstr(response_buffer->buffer, "A002 NO") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response NO)\n");
            break;
        } else if (strstr(response_buffer->buffer, "A002 BAD") != NULL) {
            fprintf(stderr, "Error: SELECT command failed. (server's response BAD)\n");
            break;
        }

        // Resize the response buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes < 0) {
        fprintf(stderr, "Error: recv() failed for SELECT response.\n");
    }

    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in SELECT command. (possibly wrong server response or connection failure)\n");
    return false;
}


bool uidSearchSecure(SSL *ssl, bool new_only, DynamicBuffer *response_buffer) {
    // Static buffer for the SEARCH command
    char search_cmd[64];

    // Prepare the correct SEARCH command
    if (new_only) {
        snprintf(search_cmd, sizeof(search_cmd), "B003 UID SEARCH UNSEEN\r\n");
    } else {
        snprintf(search_cmd, sizeof(search_cmd), "B003 UID SEARCH ALL\r\n");
    }

    // Send the SEARCH command
    if (SSL_write(ssl, search_cmd, strlen(search_cmd)) <= 0) {
        fprintf(stderr, "Error: SSL_write() for SEARCH command failed.\n");
        return false;
    }

    printf("Sent UID SEARCH command: %s", search_cmd);

    int bytes;
    // Read the server's response using the dynamic response buffer
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check if the response is OK or an error
        if (strstr(response_buffer->buffer, "B003 OK") != NULL) {
            return true;
        } else if (strstr(response_buffer->buffer, "B003 NO") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response NO)\n");
            return false;
        } else if (strstr(response_buffer->buffer, "B003 BAD") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response BAD)\n");
            return false;
        }

        // Resize the buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        fprintf(stderr, "Error: SSL_read() failed for SEARCH command.\n");
        return false;
    }

    fprintf(stderr, "Error: Unexpected failure in SEARCH command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool uidSearchUnsecure(int sockfd, bool new_only, DynamicBuffer *response_buffer) {
    // Static buffer for the SEARCH command
    char search_cmd[64];

    // Prepare the correct SEARCH command
    if (new_only) {
        snprintf(search_cmd, sizeof(search_cmd), "A003 UID SEARCH UNSEEN\r\n");
    } else {
        snprintf(search_cmd, sizeof(search_cmd), "A003 UID SEARCH ALL\r\n");
    }

    // Send the SEARCH command
    if (send(sockfd, search_cmd, strlen(search_cmd), 0) < 0) {
        fprintf(stderr, "Error: send() for UID SEARCH command failed.\n");
        return false;
    }

    printf("Sent UID SEARCH command: %s", search_cmd);

    int bytes;
    // Read the server's response into the dynamic response buffer
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        // Check if the response is OK or an error
        if (strstr(response_buffer->buffer, "A003 OK") != NULL) {
            return true;
        } else if (strstr(response_buffer->buffer, "A003 NO") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response NO)\n");
            return false;
        } else if (strstr(response_buffer->buffer, "A003 BAD") != NULL) {
            fprintf(stderr, "Error: UID SEARCH command error. (server's response BAD)\n");
            return false;
        }

        // Resize the buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        fprintf(stderr, "Error: recv() for UID SEARCH response failed.\n");
        return false;
    }

    fprintf(stderr, "Error: Unexpected failure in SEARCH command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool fetchSecure(SSL *ssl, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all) {
    DynamicBuffer *search_response_buffer = create_buffer(4096);  // Dynamic buffer for the response
    DynamicBuffer *all_uids = create_buffer(1024);  // Buffer to hold all UIDs
    int email_count = 0;

    // Step 1: Send UID SEARCH command and get the response
    if (!uidSearchSecure(ssl, new_only, search_response_buffer)) {
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Step 2: Extract UIDs from the response
    if (!extract_uids(search_response_buffer->buffer, all_uids->buffer, all_uids->size)) {
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Step 3: Fetch each email or header using the UIDs
    char *uid = strtok(all_uids->buffer, " ");
    int tag_counter = 5;

    if (redownload_all) {
        printf("UIDValidity changed. Redownloading all emails.\n");
    }

    while (uid) {
        // Dynamically construct the filename buffer
        size_t filename_size = out_dir->length + mailbox->length + strlen(uid) + 30;
        DynamicBuffer *filename_buffer = create_buffer(filename_size);

        if (headers_only) {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_header_%s.txt", out_dir->buffer, mailbox->buffer, uid);
        } else {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_email_%s.eml", out_dir->buffer, mailbox->buffer, uid);
        }

        if (!redownload_all && access(filename_buffer->buffer, F_OK) == 0) {
            printf("Email %s already exists in mailbox %s. Skipping download.\n", uid, mailbox->buffer);
            free_buffer(filename_buffer);
            uid = strtok(NULL, " \r\n");
            continue;
        }

        printf("Fetching %s for UID: %s in mailbox: %s\n", headers_only ? "headers" : "full email", uid, mailbox->buffer);

        // Use a fixed-size buffer for the fetch command
        char fetch_cmd[128];
        char tag[8];
        snprintf(tag, sizeof(tag), "B%03d", tag_counter++);

        if (headers_only) {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY.PEEK[HEADER]\r\n", tag, uid);
        } else {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY[]\r\n", tag, uid);
        }

        if (SSL_write(ssl, fetch_cmd, strlen(fetch_cmd)) <= 0) {
            fprintf(stderr, "Error: SSL_write() for UID FETCH command failed.\n");
            free_buffer(search_response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            return false;
        }

        DynamicBuffer *response_buffer = create_buffer(8192);
        char email_buffer[8192];  // Fixed-size buffer for SSL reading
        int email_bytes;
        size_t line_count = 0;

        while ((email_bytes = SSL_read(ssl, email_buffer, sizeof(email_buffer) - 1)) > 0) {
            email_buffer[email_bytes] = '\0';
            write_to_buffer(response_buffer, email_buffer);  // Write received data to dynamic response buffer

            // Count the number of lines
            for (int i = 0; i < email_bytes; i++) {
                if (email_buffer[i] == '\n') {
                    line_count++;
                }
            }

            if (strstr(email_buffer, tag) && strstr(email_buffer, "OK UID FETCH completed") != NULL) {
                break;  // Done receiving this email
            } else if (strstr(email_buffer, tag) && strstr(email_buffer, "NO") != NULL) {
                fprintf(stderr, "Error: UID FETCH command error. (server's response NO)\n");
                free_buffer(response_buffer);
                free_buffer(all_uids);
                free_buffer(filename_buffer);
                free_buffer(search_response_buffer);
                return false;
            } else if (strstr(email_buffer, tag) && strstr(email_buffer, "BAD") != NULL) {
                fprintf(stderr, "Error: UID FETCH command error. (server's response BAD)\n");
                free_buffer(response_buffer);
                free_buffer(all_uids);
                free_buffer(filename_buffer);
                free_buffer(search_response_buffer);
                return false;
            }
        }

        if (email_bytes <= 0) {
            fprintf(stderr, "Error: SSL_read() for UID FETCH command failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        // Open file for writing the email or headers
        FILE *file = fopen(filename_buffer->buffer, "w");
        if (!file) {
            fprintf(stderr, "Error: opening file for writing email/headers failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        size_t current_line = 0;
        bool writing_started = false;

        for (size_t i = 0; i < response_buffer->length; i++) {
            if (response_buffer->buffer[i] == '\n') {
                current_line++;
            }

            if (current_line > 0 && current_line < line_count - 2) {
                if (!writing_started && response_buffer->buffer[i] == '\n') {
                    continue;
                }
                fputc(response_buffer->buffer[i], file);  // Write actual content to the file
                writing_started = true;
            }
        }

        fclose(file);
        free_buffer(filename_buffer);
        free_buffer(response_buffer);

        printf("Completed write for UID: %s\n", uid);
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

    free_buffer(all_uids);
    free_buffer(search_response_buffer);

    return true;
}

bool fetchUnsecure(int sockfd, DynamicBuffer *mailbox, DynamicBuffer *out_dir, bool headers_only, bool new_only, bool redownload_all) {
    DynamicBuffer *search_response_buffer = create_buffer(8192);  // Dynamic buffer for the response
    DynamicBuffer *all_uids = create_buffer(1024);  // Dynamic buffer to hold all UIDs
    int email_count = 0;

    // Step 1: Send UID SEARCH command and get the response
    if (!uidSearchUnsecure(sockfd, new_only, search_response_buffer)) {
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Step 2: Extract UIDs from the response
    if (!extract_uids(search_response_buffer->buffer, all_uids->buffer, all_uids->size)) {
        free_buffer(search_response_buffer);
        free_buffer(all_uids);
        return false;
    }

    // Step 3: Fetch each email or header using the UIDs
    char *uid = strtok(all_uids->buffer, " ");
    int tag_counter = 5;

    if (redownload_all) {
        printf("UIDValidity changed. Redownloading all emails.\n");
    }

    while (uid) {
        // Dynamically construct the filename buffer
        size_t filename_size = out_dir->length + mailbox->length + strlen(uid) + 30;
        DynamicBuffer *filename_buffer = create_buffer(filename_size);

        if (headers_only) {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_header_%s.txt", out_dir->buffer, mailbox->buffer, uid);
        } else {
            snprintf(filename_buffer->buffer, filename_buffer->size, "%s/%s_email_%s.eml", out_dir->buffer, mailbox->buffer, uid);
        }

        if (!redownload_all && access(filename_buffer->buffer, F_OK) == 0) {
            printf("Email %s already exists in mailbox %s. Skipping download.\n", uid, mailbox->buffer);
            free_buffer(filename_buffer);
            uid = strtok(NULL, " \r\n");
            continue;
        }

        printf("Fetching %s for UID: %s in mailbox: %s\n", headers_only ? "headers" : "full email", uid, mailbox->buffer);

        // Use a fixed-size buffer for the fetch command
        char fetch_cmd[128];
        char tag[8];
        snprintf(tag, sizeof(tag), "A%03d", tag_counter++);

        if (headers_only) {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY.PEEK[HEADER]\r\n", tag, uid);
        } else {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY[]\r\n", tag, uid);
        }

        if (send(sockfd, fetch_cmd, strlen(fetch_cmd), 0) < 0) {
            fprintf(stderr, "Error: send() for UID FETCH command failed.\n");
            free_buffer(search_response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            return false;
        }

        DynamicBuffer *response_buffer = create_buffer(4096);
        char email_buffer[8192];  // Dynamic buffer for email content
        int email_bytes;
        size_t line_count = 0;

        while ((email_bytes = recv(sockfd, email_buffer, sizeof(email_buffer) - 1, 0)) > 0) {
            email_buffer[email_bytes] = '\0';
            write_to_buffer(response_buffer, email_buffer);  // Null-terminate the received data

            // Count the number of lines
            for (int i = 0; i < email_bytes; i++) {
                if (email_buffer[i] == '\n') {
                    line_count++;
                }
            }

            if (strstr(email_buffer, tag) && strstr(email_buffer, "OK UID FETCH completed") != NULL) {
                break;  // Done receiving this email
            } else if (strstr(email_buffer, tag) && strstr(email_buffer, "NO") != NULL) {
                fprintf(stderr, "Error: UID FETCH command error. (server's response NO)\n");
                free_buffer(response_buffer);
                free_buffer(all_uids);
                free_buffer(filename_buffer);
                free_buffer(search_response_buffer);
                return false;
            } else if (strstr(email_buffer, tag) && strstr(email_buffer, "BAD") != NULL) {
                fprintf(stderr, "Error: UID FETCH command error. (server's response BAD)\n");
                free_buffer(response_buffer);
                free_buffer(all_uids);
                free_buffer(filename_buffer);
                free_buffer(search_response_buffer);
                return false;
            }
        }

        if (email_bytes <= 0) {
            fprintf(stderr, "Error: recv() for UID FETCH command failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        // Open file for writing the email or headers
        FILE *file = fopen(filename_buffer->buffer, "w");
        if (!file) {
            fprintf(stderr, "Error: opening file for writing email/headers failed.\n");
            free_buffer(response_buffer);
            free_buffer(all_uids);
            free_buffer(filename_buffer);
            free_buffer(search_response_buffer);
            return false;
        }

        size_t current_line = 0;
        bool writing_started = false;

        for (size_t i = 0; i < response_buffer->length; i++) {
            if (response_buffer->buffer[i] == '\n') {
                current_line++;
            }

            if (current_line > 0 && current_line < line_count - 2) {
                if (!writing_started && response_buffer->buffer[i] == '\n') {
                    continue;
                }
                fputc(response_buffer->buffer[i], file);  // Write actual content to the file
                writing_started = true;
            }
        }

        fclose(file);
        free_buffer(filename_buffer);
        free_buffer(response_buffer);

        printf("Completed write for UID: %s\n", uid);
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

    free_buffer(all_uids);
    free_buffer(search_response_buffer);

    return true;
}


bool logoutSecure(SSL *ssl) {
    char logout_cmd[] = "B004 LOGOUT\r\n";

    // Send the LOGOUT command
    if (SSL_write(ssl, logout_cmd, strlen(logout_cmd)) <= 0) {
        fprintf(stderr, "Error: SSL_write() for LOGOUT command failed.\n");
        return false;
    }

    printf("Sent logout command: %s", logout_cmd);

    // Create dynamic buffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(1024);  // Initial buffer size
    int bytes;

    // Receive the server's response
    while ((bytes = SSL_read(ssl, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        printf("Server logout response: %s\n", response_buffer->buffer);

        if (strstr(response_buffer->buffer, "B004 OK") != NULL) {
            printf("Logout completed.\n");
            free_buffer(response_buffer);
            return true;
        } else if (strstr(response_buffer->buffer, "B004 BAD") != NULL) {
            fprintf(stderr, "Error: LOGOUT command failed. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false;
        }

        // Resize the buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    if (bytes <= 0) {
        fprintf(stderr, "Error: SSL_read() failed for LOGOUT response.\n");
        free_buffer(response_buffer);
        return false;
    }

    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in LOGOUT command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool logoutUnsecure(int sockfd) {
    char logout_cmd[] = "A004 LOGOUT\r\n";  // IMAP LOGOUT command

    // Send the LOGOUT command
    if (send(sockfd, logout_cmd, strlen(logout_cmd), 0) < 0) {
        fprintf(stderr, "Error: send() for LOGOUT command failed.\n");
        return false;
    }

    printf("Sent logout command: %s", logout_cmd);

    // Create dynamic buffer for the server's response
    DynamicBuffer *response_buffer = create_buffer(1024);  // Initial buffer size
    int bytes;

    // Receive the server's response
    while ((bytes = recv(sockfd, response_buffer->buffer + response_buffer->length, response_buffer->size - response_buffer->length - 1, 0)) > 0) {
        response_buffer->length += bytes;
        response_buffer->buffer[response_buffer->length] = '\0';  // Null-terminate the response

        printf("Server logout response: %s\n", response_buffer->buffer);

        // Check for a successful logout response
        if (strstr(response_buffer->buffer, "A004 OK") != NULL) {
            printf("Logout completed.\n");
            free_buffer(response_buffer);
            return true;
        }

        // Handle failure or errors during logout
        if (strstr(response_buffer->buffer, "A004 BAD") != NULL) {
            fprintf(stderr, "Error: LOGOUT command failed. (server's response BAD)\n");
            free_buffer(response_buffer);
            return false;
        }

        // Resize the buffer if necessary
        if (response_buffer->length + 1 >= response_buffer->size) {
            resize_buffer(response_buffer, response_buffer->size * 2);
        }
    }

    // Error handling if recv returns -1 (error)
    if (bytes < 0) {
        fprintf(stderr, "Error: recv() for LOGOUT command response failed.\n");
        free_buffer(response_buffer);
        return false;
    }

    free_buffer(response_buffer);
    fprintf(stderr, "Error: Unexpected failure in LOGOUT command. (possibly wrong server response or connection failure)\n");
    return false;
}

bool SecureCommunication(SSL *ssl, const struct Config *config) {
    DynamicBuffer *uidvalidity = create_buffer(256);
    const char *uidvalidity_file = "uidvalidity.txt";

    // LOGIN
    if (!loginSecure(ssl, config->username, config->password)) {
        free_buffer(uidvalidity);
        return false;
    }

    // SELECT
    if (!selectSecure(ssl, config->mailbox, uidvalidity)) {
        logoutSecure(ssl);
        free_buffer(uidvalidity);
        return false;
    }

    // compare uidvalidity to check it is same or not
    bool same_uidvalidity = compare_uidvalidity(uidvalidity_file, uidvalidity->buffer);

    // FETCH
    if (!fetchSecure(ssl, config->mailbox, config->out_dir, config->headers_only, config->new_only, !same_uidvalidity)) {
        logoutSecure(ssl);
        free_buffer(uidvalidity);
        return false;
    }

    // LOGOUT
    if (!logoutSecure(ssl)) {
        free_buffer(uidvalidity);
        return false;
    }

    free_buffer(uidvalidity);
    return true;
}


bool UnsecureCommunication(int sockfd, const struct Config *config) {
    DynamicBuffer *uidvalidity = create_buffer(256);
    const char *uidvalidity_file = "uidvalidity.txt";

    // LOGIN
    if (!loginUnsecure(sockfd, config->username, config->password)) {
        free_buffer(uidvalidity);
        return false;
    }

    //listMailboxesUnsecure(sockfd);
    
    // SELECT
    if (!selectUnsecure(sockfd, config->mailbox, uidvalidity)) {
        logoutUnsecure(sockfd);
        free_buffer(uidvalidity);
        return false;
    }

    printf("selected\n");

    // compare uidvalidity to check it is same or not
    bool same_uidvalidity = compare_uidvalidity(uidvalidity_file, uidvalidity->buffer);

    // FETCH
    if (!fetchUnsecure(sockfd, config->mailbox, config->out_dir, config->headers_only, config->new_only, !same_uidvalidity)) {
        logoutUnsecure(sockfd);
        free_buffer(uidvalidity);
        return false;
    }

    // LOGOUT
    if (!logoutUnsecure(sockfd)) {
        free_buffer(uidvalidity);
        return false;
    }

    free_buffer(uidvalidity);
    return true;
}