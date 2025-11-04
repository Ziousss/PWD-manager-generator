#ifndef MAIN_H
#define MAIN_H

#include "defs.h"

bool pwd_verif(unsigned char *key_out);
void add_pwd(unsigned char *key_out);
void first_time(unsigned char *key_out);
void see_pwd(unsigned char *key_out);
void search_pwd(unsigned char *key_out, unsigned char *name);
bool part_of(char *search, char *name);
void change_pwd(unsigned char *key_out);
void delete_pwd(unsigned char *key_out);
int print_names(unsigned char *name);
char *pwd_level(unsigned char *pwd);
char *pwd_generator();

typedef struct
{
    char name[NAME_SIZE];
    char username[NAME_SIZE];
    unsigned char pwd[crypto_secretbox_MACBYTES + PWD_LENGTH];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
} Record;

#endif