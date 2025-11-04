#ifndef DEFS_H
#define DEFS_H

#include <sodium.h>

#define MAX_RECORD 256
#define NAME_SIZE 50
#define SALT_SIZE 16
#define NONCE_SIZE 24
#define PWD_LENGTH 50
#define HEADER_SIZE (SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH)
#define MAX_RECORD 256
#define NAME_SIZE 50
#define SALT_SIZE 16
#define NONCE_SIZE 24
#define PWD_LENGTH 50
#define HEADER_SIZE (SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH)

#endif 