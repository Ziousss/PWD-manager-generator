/* Includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sodium.h>

/* Definitions */
#define MAX_SIZE 256
#define MAX_RECORD 256

#define SALT_SIZE 16
#define NONCE_SIZE 24
#define VERIF_CIPHER_SIZE 100
#define HEADER_SIZE (SALT_SIZE + NONCE_SIZE + VERIF_CIPHER_SIZE + 4)

#define NAME_SIZE 50
#define ENTRY_CIPHER_SIZE 100
#define ENTRY_SIZE (NAME_SIZE + NONCE_SIZE + ENTRY_CIPHER_SIZE)
/* Function signatures*/
bool pwd_verif();
void add_pwd();
void first_time();

/* Struct */
typedef struct {
    char name[MAX_SIZE];
    char pwd[MAX_SIZE]; // will be encrypted w their nonce
    unsigned char nonce [crypto_secretbox_NONCEBYTES];
} Record;

/* Function's code */

// need to change pwd form csv to wb for storage of salt and nonce
int main(int argc, char* argv[]){
    if (argc != 1){
        return 1;
    }
    while(1){
        char myNum[1];
        int realNum = atoi(myNum);
        char row[100];
        FILE *file = fopen("database.bin", "rb");
        unsigned char key[crypto_secretbox_KEYBYTES];
        if(file == NULL){
            first_time(key);
        }
        else{
            fclose(file);
            bool found = pwd_verif();
            if(!found){
                int i = 0;
                do {
                    i++;
                    printf("Wrong password, %d tries left\n", 3-i);
                    found = pwd_verif();
                } while(!found && i!= 3);
                if(!found){
                    return -1;
                }
            }
        }
        printf("What do you want to do ?\n"); 
        printf("1. Add new password\n2. See current password\n3. Change existing password\n4. Delete a password from the list\n5. exit\n");
        fgets(myNum,sizeof(myNum),stdin);

        if (realNum == 1){
            char* new_pwd;      
            add_pwd();

            new_pwd;
        }
        else if (realNum == 2){
            //see curent pwd
        }
        else if (realNum == 3){
            //change current pwd
        }
        else if (realNum == 4){
            //delete the pwd for a specific thing
        }
        else if (realNum == 5){
            break;
        }
        else{
            printf("Invalid number\n");
        }
    }
}



bool pwd_verif(){
    Record records[MAX_RECORD];
    int count = 0;
    char user_input[MAX_SIZE];
    bool found = false;

    printf("Password: ");
    fgets(user_input, sizeof(user_input), stdin);

    user_input[strcspn(user_input, "\n")] = '\0';

    FILE *file = fopen("database.bin","rb");

    unsigned char salt[SALT_SIZE];
    fread(salt, 1, SALT_SIZE, file);

    unsigned char nonce[NONCE_SIZE];
    fread(nonce, 1, NONCE_SIZE, file);

    unsigned char cyphertext[VERIF_CIPHER_SIZE];
    fread(cyphertext,1,VERIF_CIPHER_SIZE, file);

    fclose(file);
    char* compare = "orignal_pwd";
    if(strcmp(records[0].name, "orignal_pwd") == 0){
        if(strcmp(records[0].pwd, user_input) == 0){
            found = true;
        }
    }
    return found;
}

void add_pwd(){
    char new_name[50];
    printf("For what is this password for ? [name]\n");
    fgets(new_name, sizeof(new_name), stdin);

    char new_pwd[50];

    //will add the option of generate a new password later

    printf("What is the password?\n");
    fgets(new_pwd, sizeof(new_pwd), stdin);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce)); 
    FILE *file = fopen("database.bin","ab");
    if(file == NULL){
        printf("ERROR: could not open the file.\n");
        return;
    }

    fprintf(file, "%s,%s,", new_name, new_pwd);
    for (int i = 0; i <crypto_secretbox_NONCEBYTES; i++){
        fprintf(file, "%02x", nonce[i]);
    }
    fclose(file);
}

void first_time(unsigned char *key_out){
    char pwd[30];
    char conf_pwd[30];

    printf("This is the first time you open this program.\n");
    printf("Please set a password. This one will be asked every time you open the program so be sure to remember it!\n");
    fgets(pwd, sizeof(pwd), stdin);
    do {
        //ok will become the level of the pwd
        printf("This password is ok. Please confirm by retyping it. Press 1 to change the original password: ");
        fgets(conf_pwd, sizeof(conf_pwd), stdin);

        if(strcmp(conf_pwd,"1") == 0){ //doesn t work gotta improve
            printf("Change orignial password: ");
            fgets(pwd, sizeof(pwd), stdin);
        }

    } while (strcmp(pwd,conf_pwd) != 0);

    if (sodium_init() < 0) {
        return;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t pwd_len = strlen(pwd);
    unsigned char key[crypto_secretbox_KEYBYTES];

    if (crypto_pwhash(key, sizeof(key),
                  pwd, strlen(pwd),
                  salt,
                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                  crypto_pwhash_MEMLIMIT_INTERACTIVE,
                  crypto_pwhash_ALG_ARGON2ID13) != 0) {
    printf("Key derivation failed\n");
    return;
    }

    
    unsigned char ciphertext[crypto_secretbox_MACBYTES + pwd_len];
    printf("\n");
    crypto_secretbox_easy(ciphertext, pwd, pwd_len, nonce, key);

    
    FILE *file = fopen("database.bin","wb");
    fwrite(salt, 1, SALT_SIZE, file);
    fwrite(nonce, 1, NONCE_SIZE, file);
    fwrite(ciphertext, 1, sizeof(ciphertext), file);


    fclose(file);
    return;
}