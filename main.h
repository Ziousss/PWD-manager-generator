#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sodium.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include "defs.h"
#include <stdbool.h>

bool pwd_verif(unsigned char *key_out);
void add_pwd(unsigned char *key_out);
void first_time(unsigned char *key_out);
void see_pwd(unsigned char *key_out);
void search_pwd(unsigned char *key_out, unsigned char *name);
void change_pwd(unsigned char *key_out);
void delete_pwd(unsigned char *key_out);

typedef struct
{
    char name[NAME_SIZE];
    char username[NAME_SIZE];
    unsigned char pwd[crypto_secretbox_MACBYTES + PWD_LENGTH];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
} Record;

#endif