/*
 *
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:	Marco Mellia, Andrea Carpani, Luca Muscariello, Dario Rossi
 * 		Telecomunication Networks Group
 * 		Politecnico di Torino
 * 		Torino, Italy
 *              http://www.tlc-networks.polito.it/index.html
 *		mellia@mail.tlc.polito.it, rossi@mail.tlc.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/
#include "tstat.h"
#include "dump.h"
#include <string.h>

typedef void ini_section_handler(char * param_name, int param_value);
struct ini_section {
    char *name;
    ini_section_handler *handler;
};
static struct ini_section ini_sections[] = {
    {"[dump]", dump_parse_ini_arg},
    {"[log]", log_parse_ini_arg},
};
#define INI_SECTION_LEN (sizeof(ini_sections) / sizeof(struct ini_section))
#define BUF_SIZE 50
#define INI_PARAM_VALUE_DEFAULT -1000

char * readline(FILE *fp) {
    static char *buf = NULL;
    static int buf_size = 0;
    static int next_pos = 0;
    char *tmp, curr_c;

    if (buf == NULL) {
        buf = malloc(BUF_SIZE * sizeof(char));
        buf_size = BUF_SIZE;
        next_pos = 0;
    }

    while (1) {
        if (next_pos + 1 == buf_size) {
            buf_size += BUF_SIZE;
            tmp = malloc(buf_size * sizeof(char));
            strcpy(tmp, buf);
            free(buf);
            buf = tmp;
        }

        curr_c = fgetc(fp);
        if (feof(fp)) {
            buf[next_pos] = '\0';
            break;
        }

        buf[next_pos] = curr_c;
        buf[next_pos + 1] = '\0';
        next_pos++;
        if (curr_c == '\n')
            break;
    }
    next_pos = 0;
    if (buf[0] == '\0')
        return NULL;
    return buf;
}

void ini_read(char *fname) {
    FILE *fp;
    char *line, *word, *param_name;
    int param_value;
    int i, len;
    ini_section_handler *handler;


    fp = fopen(fname, "r");
    if (fp == NULL) {
        fprintf (fp_stderr, "inireader: '%s' - No such file\n", fname);
        exit(1);
    }

    handler = NULL;
    while (1) {
        line = readline(fp);
        if (line == NULL)
            break;

        word = strtok(line, " \t\n");
        param_name = NULL;
        param_value = INI_PARAM_VALUE_DEFAULT;
        while(word != NULL) {
            //skip comments and void lines
            if (word[0] == '#' || word[0] == '\0')
                break;
           
            //search for the handler related to the current section
            if (word[0] == '[') { 
                handler = NULL;
                for (i = 0; i < INI_SECTION_LEN; i++) {
                    if (strcmp(word, ini_sections[i].name) == 0)
                        break;
                }
                if (i == INI_SECTION_LEN) {
                    fprintf (fp_stderr, "inireader: '%s' - syntax error\n", word);
                    exit(1);
                }
                handler = ini_sections[i].handler;
            }
            //parse section parameter and call handler
            else if (word[0] != '=') {
                if (!param_name)
                    param_name = word;
                else if (param_value == INI_PARAM_VALUE_DEFAULT) {
                    len = strlen(word);
                    for (i = 0; i < len && isdigit(word[i]); i++)
                        ;
                    if (i != len) {
                        fprintf (fp_stderr, "inireader: '%s' - syntax error\n", word);
                        exit(1);
                    }
                    param_value = atoi(word);
                }
                else {
                    fprintf (fp_stderr, "inireader: '%s' - syntax error\n", word);
                    exit(1);
                }

            }
            word = strtok(NULL, " \t\n");
        }

        if (handler != NULL && param_name != NULL) {
            if (param_value == INI_PARAM_VALUE_DEFAULT)
                param_value = 1;
            handler(param_name, param_value);
        }
    }
    fclose(fp);
}

