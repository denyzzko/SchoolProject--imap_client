#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "parser.h"
#include "main.h"

// ******************************************
// * add automatic port 443 when -T us used *
// ******************************************
bool load_auth_file(const char *auth_file, struct Config *config) {
    FILE *file = fopen(auth_file, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open auth_file %s.\n", auth_file);
        return false;
    }

    char line[MAX_STR_LEN];
    while (fgets(line, sizeof(line), file)) {
        //username
        if (strncmp(line, "username = ", 11) == 0) {
            strncpy(config->username, line + 11, MAX_STR_LEN - 1);
            config->username[strcspn(config->username, "\n")] = '\0';  // remove newline
        }
        //password
        else if (strncmp(line, "password = ", 11) == 0) {
            strncpy(config->password, line + 11, MAX_STR_LEN - 1);
            config->password[strcspn(config->password, "\n")] = '\0';
        }
    }

    fclose(file);

    // ensure both values are set
    if (strlen(config->username) == 0 || strlen(config->password) == 0) {
        fprintf(stderr, "Error: Username or password missing in auth_file.\n");
        return false;
    }

    return true;
}

void printUsage() {
    printf("USAGE: imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir\n");
}

bool ParseArguments(int argc, char* argv[], struct Config *config) {
    // default values
    config->port = 143;
    config->use_ssl = false;
    strcpy(config->certdir, "/etc/ssl/certs");
    config->new_only = false;
    config->headers_only = false;
    strcpy(config->mailbox, "INBOX");

    int opt;

    // parsing
    while ((opt = getopt(argc, argv, "p:Tc:C:nha:b:o:")) != -1) {
        switch (opt) {
            case 'p':
                config->port = atoi(optarg);
                break;
            case 'T':
                config->use_ssl = true;
                break;
            case 'c':
                strncpy(config->certfile, optarg, MAX_STR_LEN - 1);
                break;
            case 'C':
                strncpy(config->certdir, optarg, MAX_STR_LEN - 1);
                break;
            case 'n':
                config->new_only = true;
                break;
            case 'h':
                config->headers_only = true;
                break;
            case 'a':
                strncpy(config->auth_file, optarg, MAX_STR_LEN - 1);
                break;
            case 'b':
                strncpy(config->mailbox, optarg, MAX_STR_LEN - 1);
                break;
            case 'o':
                strncpy(config->out_dir, optarg, MAX_STR_LEN - 1);
                break;
            default:
                printUsage();
                return false;
        }
    }

    // remaining non-option argument (the server)
    if (optind < argc) {
        if (optind + 1 == argc) {
            strncpy(config->server, argv[optind], MAX_STR_LEN - 1);
        } else {
            printf("Error: Invalid number of arguments.\n");
            printUsage();
            return false;
        }
    } else {
        printf("Error: Missing required server argument.\n");
        printUsage();
        return false;
    }

    // check for auth_file and out_dir
    if (strlen(config->auth_file) == 0 || strlen(config->out_dir) == 0) {
        printf("Error: Missing required argument auth_file or out_dir.\n");
        printUsage();
        return false;
    }

    // load username and password
    if (!load_auth_file(config->auth_file, config)) {
        return 1;
    }

    return true;
}