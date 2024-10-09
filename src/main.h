/**
 * @file main.h
 * @brief Header file for email client using protocol IMAP4rev1
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdbool.h>

#define MAX_STR_LEN 256

// Config structure to hold parsed arguments
struct Config {
    char server[MAX_STR_LEN];
    int port;
    bool use_ssl;
    char certfile[MAX_STR_LEN];
    char certdir[MAX_STR_LEN];
    bool new_only;
    bool headers_only;
    char auth_file[MAX_STR_LEN];
    char mailbox[MAX_STR_LEN];
    char out_dir[MAX_STR_LEN];
    char username[MAX_STR_LEN];
    char password[MAX_STR_LEN];
};

#endif