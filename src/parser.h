/**
 * @file parser.h
 * @brief Header file for parser.c 
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#ifndef PARSER_H
#define PARSER_H

#include "main.h"

// Helper function to load username and password
bool load_auth_file(const char *auth_file, struct Config *config);
// Function that prints usage
void printUsage();
// Function to parse input arguments and populate Config structure
bool ParseArguments(int argc, char* argv[], struct Config *config);

#endif