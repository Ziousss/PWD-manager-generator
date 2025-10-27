/* Includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sodium.h>
#include <time.h>

/* Definitions */
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
    char name[NAME_SIZE];
    char pwd[NAME_SIZE]; 
    unsigned char nonce [crypto_secretbox_NONCEBYTES];
} Record;

/* Function's code */
int main(int argc, char* argv[]){
    if (argc != 1){
        return 1;
    }
    while(1){
        char myNum[10];
        unsigned char key[crypto_secretbox_KEYBYTES];
        char row[100];

        FILE *file = fopen("database.bin", "rb");
        if(file == NULL){
            first_time(key);
        } 
        else{
            fclose(file);
            bool found = pwd_verif(key);
            if(!found){
                int i = 0;
                do {
                    i++;
                    time_t start = time(NULL);
                    while (time(NULL) - start < 3) {
                        //wait
                    }

                    printf("Wrong password, %d tries left\n", 3-i);
                    found = pwd_verif(key);
                } while(!found && i!= 3);
                if(!found){
                    return -1;
                }
            }
        }
        int realNum;
        do {
            printf("What do you want to do ?\n"); 
            printf("1. Add new password\n2. See current password\n3. Change existing password\n4. Delete a password from the list\n5. exit\n");
            fgets(myNum,sizeof(myNum),stdin);
            int realNum = atoi(myNum);
            
            if (realNum == 1){     
                add_pwd();
            }
            else if (realNum == 2){
                //search curent pwd
            }
            else if (realNum == 3){
                //change current pwd
            }
            else if (realNum == 4){
                //delete the pwd for a specific thing
            }
            else if (realNum == 5){
                return 1;
            }
            else{
                printf("Invalid number\n");
            }
        } while(realNum != 5);
    }
}

bool pwd_verif(unsigned char *key_out){
    Record records[MAX_RECORD];
    char user_input[NAME_SIZE];

    printf("Password: ");
    fgets(user_input, sizeof(user_input), stdin);

    user_input[strcspn(user_input, "\n")] = '\0';

    FILE *file = fopen("database.bin","rb");
    if (file == NULL) {
        printf("ERROR: Could not open database\n");
        return false;
    }

    unsigned char salt[SALT_SIZE];
    fread(salt, 1, SALT_SIZE, file);

    unsigned char nonce[NONCE_SIZE];
    fread(nonce, 1, NONCE_SIZE, file);

    unsigned char ciphertext[VERIF_CIPHER_SIZE];
    size_t ciphertext_len = fread(ciphertext,1,VERIF_CIPHER_SIZE, file);
    fclose(file);

    if (crypto_pwhash(key_out, crypto_secretbox_KEYBYTES,
                      user_input, strlen(user_input), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        printf("Key derivation failed\n");
        return false;
    }

    unsigned char decrypted[100];

    if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key_out) != 0) {
        // Decryption failed - wrong password
        return false;
    }

    sodium_memzero(user_input, sizeof(user_input));

    return true;
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
    char user_pwd[30];
    char conf_user_pwd[30];

    printf("This is the first time you open this program.\n");
    printf("Please set a password. This one will be asked every time you open the program so be sure to remember it!\n");
    printf("Password: ");
    fgets(user_pwd, sizeof(user_pwd), stdin);
    user_pwd[strcspn(user_pwd, "\n")] = '\0';

    do {
        //ok will become the level of the user_pwd
        printf("This password is ok. Please confirm by retyping it. Press 1 to change the original password.");
        printf("Password: ");
        fgets(conf_user_pwd, sizeof(conf_user_pwd), stdin);
        conf_user_pwd[strcspn(conf_user_pwd, "\n")] = '\0';

        if(strcmp(conf_user_pwd,"1\n") == 0){ //doesn t work gotta improve
            printf("Change orignial password: ");
            fgets(user_pwd, sizeof(user_pwd), stdin);
            user_pwd[strcspn(user_pwd, "\n")] = '\0';
        }

    } while (strcmp(user_pwd,conf_user_pwd) != 0);

    if (sodium_init() < 0) {
        return;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t verification_len = strlen(user_pwd);

    if (crypto_pwhash(key_out, crypto_secretbox_KEYBYTES,
                  user_pwd, strlen(user_pwd), salt,
                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                  crypto_pwhash_MEMLIMIT_INTERACTIVE,
                  crypto_pwhash_ALG_ARGON2ID13) != 0) {
        printf("Key derivation failed\n");
        return;
    }

    const char *verification_msg = "Val1D_Passw0Rd";
    unsigned char ciphertext[crypto_secretbox_MACBYTES + verification_len];
    crypto_secretbox_easy(ciphertext, verification_msg, verification_len, nonce, key_out);
    
    FILE *file = fopen("database.bin","wb");
    fwrite(salt, 1, SALT_SIZE, file);
    fwrite(nonce, 1, NONCE_SIZE, file);
    fwrite(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);

    sodium_memzero(user_pwd, sizeof(user_pwd));
    sodium_memzero(key_out, sizeof(key_out));
}