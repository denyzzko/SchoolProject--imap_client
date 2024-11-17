/**
 * @file parser.c
 * @brief Handles parsing user input data 
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "parser.h"
#include "main.h"

bool load_auth_file(const char *auth_file, struct Config *config) {
    // Open auth_file for read
    FILE *file = fopen(auth_file, "r");
    if (file == NULL) {
        // Opening file failed
        fprintf(stderr, "Error: Unable to open auth_file %s.\n", auth_file);
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // Handle username
        if (strncmp(line, "username = ", 11) == 0) {
            write_to_buffer(config->username, line + 11);
            config->username->buffer[strcspn(config->username->buffer, "\n")] = '\0';  // Remove newline
        }
        // Handle password
        else if (strncmp(line, "password = ", 11) == 0) {
            write_to_buffer(config->password, line + 11);
            config->password->buffer[strcspn(config->password->buffer, "\n")] = '\0';  // Remove newline
        }
    }

    fclose(file);

    // Ensure both values are set
    if (config->username->length == 0 || config->password->length == 0) {
        fprintf(stderr, "Error: Username or password missing in auth_file.\n");
        return false;
    }

    return true;
}

void printUsage() {
    printf("\nUSAGE: ./imapcl server [-p port] [-T [-c certfile] [-C certdir]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir\n\n");

    printf(" * server:\n");
    printf("              - Server name (IP address or domain name) of the desired resource. (mandatory)\n");

    printf(" * -p port:\n");
    printf("              - Parameter that specifies the port number on the server. (optional)\n");
    printf("              - Default value is 143 (993 with parameter -T).\n");

    printf(" * -T:\n");
    printf("              - Enables encryption (IMAPS). (optional)\n");

    printf(" * -c certfile:\n");
    printf("              - Parameter specifying the file with certificates used to verify the validity of server's certificte. (optional)\n");

    printf(" * -C certdir:\n");
    printf("              - Parameter specifying the directory in which to search for certificates used to verify the validity of server's certificte. (optional)\n");
    printf("              - Default value is /etc/ssl/certs.\n");

    printf(" * -n:\n");
    printf("              - Only new messages will be processed. (optional)\n");

    printf(" * -h:\n");
    printf("              - Only message headers will be downloaded. (optional)\n");

    printf(" * -a auth_file:\n");
    printf("              - Parameter that refers to the file with authentication information. (mandatory)\n");

    printf(" * -b MAILBOX:\n");
    printf("              - Parameter that specifies the name of the mailbox to work with on the server. (optional)\n");
    printf("              - Default value is INBOX.\n");

    printf(" * -o out_dir:\n");
    printf("              - Parameter that specifies the output directory into which the program should save the downloaded messages. (mandatory)\n");
}

bool ParseArguments(int argc, char* argv[], struct Config *config) {
    // Default values
    config->port = 143;
    config->use_ssl = false;
    write_to_buffer(config->certdir, "/etc/ssl/certs");
    config->new_only = false;
    config->headers_only = false;
    write_to_buffer(config->mailbox, "INBOX");

    int opt;
    bool port_set = false;
    bool cert_provided = false;

    // Parsing arguments
    while ((opt = getopt(argc, argv, "p:Tc:C:nha:b:o:")) != -1) {
        switch (opt) {
            case 'p':
                {
                    char *endptr;
                    long port = strtol(optarg, &endptr, 10);
        
                    if (*endptr != '\0' || port <= 0 || port > 65535) {
                        fprintf(stderr, "Error: Invalid port number '%s'.\n", optarg);
                        printUsage();
                        return false;
                    }
        
                    config->port = (int) port;
                    port_set = true;
                }
                break;
            case 'T':
                config->use_ssl = true;
                break;
            case 'c':
                write_to_buffer(config->certfile, optarg);
                cert_provided = true;
                break;
            case 'C':
                config->certdir->length = 0;
                memset(config->certdir->buffer, 0, config->certdir->size);
                write_to_buffer(config->certdir, optarg);
                cert_provided = true;
                break;
            case 'n':
                config->new_only = true;
                break;
            case 'h':
                config->headers_only = true;
                break;
            case 'a':
                write_to_buffer(config->auth_file, optarg);
                break;
            case 'b':
                config->mailbox->length = 0;
                memset(config->mailbox->buffer, 0, config->mailbox->size);
                write_to_buffer(config->mailbox, optarg);
                break;
            case 'o':
                write_to_buffer(config->out_dir, optarg);
                break;
            default:
                printUsage();
                return false;
        }
    }

    if (cert_provided == true){
        if (config->use_ssl == false){
            // Parameters -c or -C were used without parameter -T which makes no sense
            fprintf(stderr, "Error: Parameter -c or -C used without parameter -T.\n");
            printUsage();
            return false;
        }
    }

    // Set default port for secure connection
    if (config->use_ssl && !port_set) {
        config->port = 993;
    }

    // Remaining non-option argument (the server)
    if (optind < argc) {
        if (optind + 1 == argc) {
            write_to_buffer(config->server, argv[optind]);
        } else {
            // Wrong number of arguments
            fprintf(stderr, "Error: Invalid number of arguments.\n");
            printUsage();
            return false;
        }
    } else {
        // No server
        fprintf(stderr, "Error: Missing required server argument.\n");
        printUsage();
        return false;
    }

    // Check for required arguments
    if (config->auth_file->length == 0 || config->out_dir->length == 0) {
        fprintf(stderr, "Error: Missing required argument auth_file or out_dir.\n");
        printUsage();
        return false;
    }

    // Load username and password
    if (!load_auth_file(config->auth_file->buffer, config)) {
        return false;
    }

    return true;
}