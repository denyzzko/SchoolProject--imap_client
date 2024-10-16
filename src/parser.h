/**
 * @file parser.h
 * @brief Header file for parser.c 
 * @author Denis Milistenfer <xmilis00@stud.fit.vutbr.cz>
 * @date 27.9.2024
 */

#ifndef PARSER_H
#define PARSER_H

#include "main.h"

// helper function to load username and password
bool load_auth_file(const char *auth_file, struct Config *config);
// function that prints usage
void printUsage();
// function to parse input arguments
bool ParseArguments(int argc, char* argv[], struct Config *config);

#endif