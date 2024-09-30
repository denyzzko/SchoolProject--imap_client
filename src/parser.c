#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "parser.h"
#include "main.h"

void print_usage() {
    printf("USAGE: imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir\n");
}

bool parse_arguments(int argc, char* argv[], struct Config *config) {
    // Set default values
    config->port = 143;
    config->use_ssl = false;
    strcpy(config->certdir, "/etc/ssl/certs");
    config->new_only = false;
    config->headers_only = false;
    strcpy(config->mailbox, "INBOX");

    int opt;

    // Parse command-line options using getopt
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
                print_usage();
                return false;
        }
    }

    // Check for remaining non-option argument (the server)
    if (optind < argc) {
        if (optind + 1 == argc) {
            strncpy(config->server, argv[optind], MAX_STR_LEN - 1);
        } else {
            printf("Error: Invalid number of arguments.\n");
            print_usage();
            return false;
        }
    } else {
        printf("Error: Missing required server argument.\n");
        print_usage();
        return false;
    }

    // Check for mandatory arguments auth file and out dir
    if (strlen(config->auth_file) == 0 || strlen(config->out_dir) == 0) {
        printf("Error: Missing required argument auth_file or out_dir.\n");
        print_usage();
        return false;
    }

    return true;
}