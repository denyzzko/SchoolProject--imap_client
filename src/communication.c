#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "communication.h"
#include "main.h"

bool extract_uids(const char *search_response, char *all_uids, size_t uids_size) {
    char *search_line = strstr(search_response, "* SEARCH ");
    if (!search_line) {
        printf("No new emails found.\n");
        return false;
    }

    // Move pointer to the list of UIDs (skip "* SEARCH ")
    search_line += 9;

    // Collect and validate UIDs
    char *uid = strtok(search_line, " \r\n");
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
        } else {
            printf("Skipping invalid UID: %s\n", uid);
        }

        // Move to the next token
        uid = strtok(NULL, " \r\n");
    }

    // Print all valid UIDs
    printf("Valid UIDs: %s\n", all_uids);

    return strlen(all_uids) > 0;
}

void extract_header(const char *email_content, char *cleaned_buffer) {
    const char *headers[] = {"Date:", "From:", "To:", "Subject:", "Message-Id:", "Message-ID:"};
    char line[1024];
    const char *line_start = email_content;

    // Clear the cleaned buffer before extracting new headers
    cleaned_buffer[0] = '\0';

    // Read email content line by line
    while (sscanf(line_start, "%[^\r\n]\r\n", line) == 1) {
        line_start += strlen(line) + 2;  // Move pointer to the next line

        // Check for each header and extract it
        for (int i = 0; i < 6; i++) {
            if (strncmp(line, headers[i], strlen(headers[i])) == 0) {
                // Append the header value to the cleaned buffer
                strncat(cleaned_buffer, line, 1024);
                strncat(cleaned_buffer, "\n", 1024);
            }
        }

        // Stop processing after finding an empty line (indicates the end of headers)
        if (strlen(line) == 0) {
            break;
        }
    }
}

bool loginUnsecure(int sockfd, const char *username, const char *password) {
    char login_cmd[512];
    snprintf(login_cmd, sizeof(login_cmd), "A001 LOGIN %s %s\r\n", username, password);
    // Send the login command and check if it was successful
    if (send(sockfd, login_cmd, strlen(login_cmd), 0) < 0) {
        fprintf(stderr, "Error sending IMAP LOGIN command.\n");
        return false;
    }

    printf("Sent login command: %s", login_cmd);

    // server response
    char buffer[1024];
    int bytes;
    while ((bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';  // Null-terminate the response
        printf("Server login response: %s\n", buffer);

        if (strstr(buffer, "A001 OK") != NULL) {
            printf("Login successful\n");
            return true;  // succes
        }
        else if (strstr(buffer, "A001 NO") != NULL) {
            fprintf(stderr, "Error: login failure - user name or password rejected. (NO)");
            return false; // fail
        }
        else if (strstr(buffer, "A001 BAD") != NULL) {
            fprintf(stderr, "Error: command unknown or arguments invalid. (BAD)");
            return false; // fail
        }
    }

    // Error handling if recv returns -1 (error)
    if (bytes < 0) {
        fprintf(stderr, "Error receiving IMAP response");
    }

    return false;
}

bool selectUnsecure(int sockfd, const char *mailbox) {
    char select_cmd[512];
    snprintf(select_cmd, sizeof(select_cmd), "A002 SELECT %s\r\n", mailbox);

    if (send(sockfd, select_cmd, strlen(select_cmd), 0) < 0) {
        fprintf(stderr, "Error sending IMAP SELECT command.\n");
        return false;
    }

    printf("Sent select command: %s", select_cmd);

    char buffer[1024];
    int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server select response: %s\n", buffer);

        if (strstr(buffer, "A002 OK") != NULL) {
            return true;
        }
        else if (strstr(buffer, "A002 NO") != NULL) {
            fprintf(stderr, "Error: select failure - now in authenticated state: no such mailbox, cant access mailbox. (NO)");
            return false; // fail
        }
        else if (strstr(buffer, "A002 BAD") != NULL) {
            fprintf(stderr, "Error: command unknown or arguments invalid. (BAD)");
            return false; // fail
        }
    }
    return false;
}

bool uidSearchUnsecure(int sockfd, bool new_only, char *buffer, size_t buffer_size) {
    char search_cmd[512];

    // Prepare the correct SEARCH command
    if (new_only) {
        snprintf(search_cmd, sizeof(search_cmd), "A003 UID SEARCH NEW\r\n");
    } else {
        snprintf(search_cmd, sizeof(search_cmd), "A003 UID SEARCH ALL\r\n");
    }

    // Send the SEARCH command
    if (send(sockfd, search_cmd, strlen(search_cmd), 0) < 0) {
        fprintf(stderr, "Error sending UID SEARCH command\n");
        return false;
    }

    // Receive the server's response
    int bytes = recv(sockfd, buffer, buffer_size - 1, 0);
    if (bytes <= 0) {
        fprintf(stderr, "Error receiving UID SEARCH response\n");
        return false;
    }

    buffer[bytes] = '\0';
    printf("Server uid search response: %s\n", buffer);

    // Check if the response is OK or an error
    if (strstr(buffer, "A003 OK") != NULL) {
        return true;
    } else if (strstr(buffer, "A003 NO") != NULL) {
        fprintf(stderr, "Error: UID SEARCH command error. (NO)\n");
        return false;
    } else if (strstr(buffer, "A003 BAD") != NULL) {
        fprintf(stderr, "Error: UID SEARCH command error. (BAD)\n");
        return false;
    }

    return false;
}

bool fetchUnsecure(int sockfd, const char *out_dir, bool headers_only, bool new_only) { 
    char buffer[4096];
    char all_uids[1024] = {0};  // Buffer to hold all UIDs

    // Step 1: Send UID SEARCH command and get the response
    if (!uidSearchUnsecure(sockfd, new_only, buffer, sizeof(buffer))) {
        return false;
    }

    // Step 2: Extract UIDs from the response
    if (!extract_uids(buffer, all_uids, sizeof(all_uids))) {
        return false;
    }

    // Step 3: Fetch each email or header using the UIDs
    char *uid = strtok(all_uids, " ");
    int tag_counter = 5;

    while (uid) {
        printf("Fetching %s for UID: %s\n", headers_only ? "headers" : "full email", uid);

        char fetch_cmd[512];
        char tag[8];
        snprintf(tag, sizeof(tag), "A%03d", tag_counter++);

        // Create the appropriate fetch command for headers or full email
        if (headers_only) {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY[HEADER]\r\n", tag, uid);
        } else {
            snprintf(fetch_cmd, sizeof(fetch_cmd), "%s UID FETCH %s BODY[]\r\n", tag, uid);
        }

        // Send the FETCH command
        if (send(sockfd, fetch_cmd, strlen(fetch_cmd), 0) < 0) {
            fprintf(stderr, "Error sending UID FETCH command\n");
            return false;
        }

        // 4. Receive the email data or headers from the server
        char email_buffer[8192];
        int email_bytes;
        char filename[512];
        size_t line_count = 0;  // Line counter

        // Allocate buffer for the full response
        char *full_response = (char *)malloc(sizeof(char) * 65536);
        full_response[0] = '\0';  // Initialize empty string

        while ((email_bytes = recv(sockfd, email_buffer, sizeof(email_buffer) - 1, 0)) > 0) {
            email_buffer[email_bytes] = '\0';
            strncat(full_response, email_buffer, email_bytes);  // Append the received data to the full buffer

            // Count the number of lines
            for (int i = 0; i < email_bytes; i++) {
                if (email_buffer[i] == '\n') {
                    line_count++;
                }
            }

            // Check for "OK UID FETCH completed"
            if (strstr(email_buffer, tag) && strstr(email_buffer, "OK UID FETCH completed") != NULL) {
                // Tag and OK response found
                break;  // We're done receiving for this email
            } else if (strstr(email_buffer, tag) && strstr(email_buffer, "NO") != NULL) {
                fprintf(stderr, "Error: UID command error. (NO)\n");
                free(full_response);
                return false;
            } else if (strstr(email_buffer, tag) && strstr(email_buffer, "BAD") != NULL) {
                fprintf(stderr, "Error: UID command error. (BAD)\n");
                free(full_response);
                return false;
            }
        }

        // If recv returns <= 0, handle as an error
        if (email_bytes <= 0) {
            fprintf(stderr, "Error receiving email data\n");
            free(full_response);
            return false;
        }

        // Open file for writing the email or headers
        if (headers_only) {
            snprintf(filename, sizeof(filename), "%s/Xheader_%s.txt", out_dir, uid);
        } else {
            snprintf(filename, sizeof(filename), "%s/Xemail_%s.eml", out_dir, uid);
        }

        FILE *file = fopen(filename, "w");
        if (!file) {
            fprintf(stderr, "Error opening file for writing email/headers\n");
            free(full_response);
            return false;
        }

        // Process the full response, skipping first and last two lines
        size_t current_line = 0;
        bool writing_started = false;  // Track when to start writing

        for (size_t i = 0; i < strlen(full_response); i++) {
            if (full_response[i] == '\n') {
                current_line++;
            }

            // Skip the first line (line 0) and the last two lines (line_count - 1, line_count - 2)
            if (current_line > 0 && current_line < line_count - 2) {
                // Avoid extra newline as the first character
                if (!writing_started && full_response[i] == '\n') {
                    continue;
                }

                // Start writing the actual content
                fputc(full_response[i], file);
                writing_started = true;  // Set flag after writing begins
            }
        }

        // Clean up and close the file
        fclose(file);
        free(full_response);

        // Move to the next UID in the list
        uid = strtok(NULL, " \r\n");
    }

    return true;
}






bool logoutUnsecure(int sockfd) {
    char logout_cmd[] = "A004 LOGOUT\r\n";  // IMAP LOGOUT command

    // Send the logout command
    if (send(sockfd, logout_cmd, strlen(logout_cmd), 0) < 0) {
        fprintf(stderr, "Error sending IMAP LOGOUT command");
        return false;
    }

    printf("Sent logout command: %s", logout_cmd);

    // Server response buffer
    char buffer[1024];
    int bytes;

    // Receive the server response
    while ((bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';  // Null-terminate the response
        printf("Server logout response: %s\n", buffer);

        // Check for a successful logout response
        if (strstr(buffer, "A004 OK") != NULL) {
            printf("Logout completed.\n");
            return true;
        }

        // Handle failure or errors during logout
        if (strstr(buffer, "A004 BAD") != NULL) {
            fprintf(stderr, "Error: Logout failed - command unknown or arguments invalid.\n");
            return false;
        }
    }

    // Error handling if recv returns -1 (error)
    if (bytes < 0) {
        fprintf(stderr, "Error receiving IMAP logout response");
    }

    return false;
}



bool SecureCommunication(SSL *ssl, const struct Config *config) {
    char login_cmd[1024];
    snprintf(login_cmd, sizeof(login_cmd), "A001 LOGIN %s %s\r\n", config->username, config->password);
    SSL_write(ssl, login_cmd, strlen(login_cmd));

    // Read server response
    char buffer[1024];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server response: %s\n", buffer);
    }

    return true;
}

bool UnsecureCommunication(int sockfd, const struct Config *config) {
    if (!loginUnsecure(sockfd, config->username, config->password)) {
            return false;
        }
    if (!selectUnsecure(sockfd, config->mailbox)) {
            return false;
        }
    
    if (!fetchUnsecure(sockfd, config->out_dir, config->headers_only, config->new_only)) {
            return false;
        }

    if (!logoutUnsecure(sockfd)) {
            return false;
        }

    return true;
}
