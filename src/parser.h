#ifndef PARSER_H
#define PARSER_H

#include "main.h"

void print_usage();
bool parse_arguments(int argc, char* argv[], struct Config *config);

#endif