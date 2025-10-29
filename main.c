/* Includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sodium.h>
#include <time.h>
#include <ctype.h>

/* Definitions */
#define MAX_RECORD 256
#define NAME_SIZE 50
#define SALT_SIZE 16
#define NONCE_SIZE 24
#define PWD_LENGTH 50
#define HEADER_SIZE (SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH)

/* Function signatures*/
bool pwd_verif(unsigned char *key_out);
void add_pwd(unsigned char *key_out);
void first_time(unsigned char *key_out);
void see_pwd(unsigned char *key_out);
void search_pwd(unsigned char *key_out);
bool part_of(char *search, char *name);


/* Struct */
typedef struct {
    char name[NAME_SIZE];
    char username[NAME_SIZE];
    char crypted_pwd[NAME_SIZE];
    char pwd[NAME_SIZE]; 
    unsigned char nonce [crypto_secretbox_NONCEBYTES];
} Record;

/* Function's code */
int main(int argc, char* argv[]){
    if (argc != 1){
        return 1;
    }
    unsigned char key[crypto_secretbox_KEYBYTES];
    

    char myNum[10];

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

                printf("\nWrong password, %d tries left\n", 3-i);
                found = pwd_verif(key);
            } while(!found && i != 3);
            return -1;
        }
    }
    while(1){
        printf("\nWhat do you want to do ?\n"); 
        printf("1. Add new password\n2. See current password\n3. Search password\n4. Change existing password\n5. Delete a password from the list\n6. exit\n");
        fgets(myNum,sizeof(myNum),stdin);
        int realNum = atoi(myNum);

        FILE *file = fopen("database.bin", "rb");
        if(file == NULL){
            printf("no file detected.\n");
            return -1;
        }
        
        if (realNum == 1){     
            add_pwd(key);
        }
        else if (realNum == 2){
            see_pwd(key);
        }
        else if (realNum == 3){
            search_pwd(key);
        }
        else if (realNum == 4){
            //change password
        }
        else if (realNum == 5){
            //delete the pwd for a specific thing
        }
        else if (realNum == 6){
            sodium_memzero(key, crypto_secretbox_KEYBYTES);
            return 0;
        }
        else{
            printf("Invalid number\n");
        }

    }
}

bool pwd_verif(unsigned char *key_out){
    Record records[MAX_RECORD];
    char user_input[NAME_SIZE];
    memset(user_input, 0, NAME_SIZE);

    system("stty -echo");
    printf("Password: \n");
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

    unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    size_t ciphertext_len = fread(ciphertext,1,sizeof(ciphertext), file);
    fclose(file);

    if (crypto_pwhash(key_out, crypto_secretbox_KEYBYTES,
                      user_input, strlen(user_input), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        printf("Key derivation failed\n");
        system("stty echo");
        return false;
    }

    unsigned char decrypted[PWD_LENGTH];

    if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key_out) != 0) {
        system("stty echo");
        return false;
    }

    sodium_memzero(user_input, sizeof(user_input));

    system("stty echo");
    return true;
}

void add_pwd(unsigned char *key_out){
    FILE *file;
    Record records[MAX_RECORD];
    
    char new_name[NAME_SIZE];
    memset(new_name, 0, NAME_SIZE);
    printf("For what is this password for ? [name]\n");
    fgets(new_name, sizeof(new_name), stdin);
    new_name[strcspn(new_name, "\n")] = '\0';

    file = fopen("database.bin", "rb");
    if(file == NULL){
        printf("Could not open the file.\n");
        return;
    }

    unsigned char header[SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH];
    fread(header, 1, HEADER_SIZE, file);

    int count  = 0;
    while(count < MAX_RECORD){
        if(fread(records[count].name, 1, NAME_SIZE, file) != NAME_SIZE) {
            break;
        } records[count].name[NAME_SIZE - 1] = '\0';

        if(fread(records[count].username, 1, NAME_SIZE, file) != NAME_SIZE) {
            break;
        } records[count].username[NAME_SIZE - 1] = '\0';

        if(fread(records[count].nonce, 1, NONCE_SIZE, file) != NONCE_SIZE) {
            break;
        }
            
        unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
        if(fread(ciphertext, 1, sizeof(ciphertext), file) != sizeof(ciphertext)) {
            break;
        } count++;
    }
    fclose(file);

    for(int i = 0; i < count; i++){
        if(strcmp(records[i].name, new_name) == 0){
            printf("This name already has a password.\n");
            return;
        }
    }

    char new_username[NAME_SIZE];
    memset(new_username, 0, NAME_SIZE);
    printf("What is your username/e-mail address for this app ?\n");
    fgets(new_username, sizeof(new_username), stdin);
    new_username[strcspn(new_username, "\n")] = '\0';

    char new_pwd[50];
    memset(new_pwd, 0, PWD_LENGTH);
    printf("What is the password?\n");
    fgets(new_pwd, sizeof(new_pwd), stdin);
    new_pwd[strcspn(new_pwd, "\n")] = '\0';

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce)); 

    unsigned char pwd_padded[PWD_LENGTH];
    memset(pwd_padded, 0, PWD_LENGTH);
    memcpy(pwd_padded, new_pwd, strlen(new_pwd));

    unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    crypto_secretbox_easy(ciphertext, pwd_padded, PWD_LENGTH, nonce, key_out);

    file = fopen("database.bin","ab");
    if(file == NULL){
        printf("ERROR: could not open the file.\n");
        return;
    }

    fwrite(new_name, 1, sizeof(new_name), file);
    fwrite(new_username, 1, sizeof(new_name), file);
    fwrite(nonce, 1, NONCE_SIZE, file); 
    fwrite(ciphertext, 1, sizeof(ciphertext), file);  
    fclose(file);
    for (int i = 0; i < NONCE_SIZE; i++){
        printf("%02x", nonce[i]);
    }

    sodium_memzero(ciphertext, sizeof(ciphertext));
    sodium_memzero(nonce, NONCE_SIZE);
}

void first_time(unsigned char *key_out){
    char user_pwd[PWD_LENGTH];
    char conf_user_pwd[PWD_LENGTH];
    memset(user_pwd, 0, PWD_LENGTH);
    memset(conf_user_pwd, 0, PWD_LENGTH);

    printf("This is the first time you open this program.\n");
    printf("Please set a password. This one will be asked every time you open the program so be sure to remember it!\n");
    printf("Password: ");
    fgets(user_pwd, PWD_LENGTH, stdin);
    user_pwd[strcspn(user_pwd, "\n")] = '\0';

    do {
        //ok will become the level of the user_pwd
        printf("This password is ok. Please confirm by retyping it. Press 1 to change the original password.");
        printf("Password: ");
        fgets(conf_user_pwd, PWD_LENGTH, stdin);
        conf_user_pwd[strcspn(conf_user_pwd, "\n")] = '\0';

        if(strcmp(conf_user_pwd,"1\0") == 0){ 
            printf("Change orignial password: ");
            fgets(user_pwd, PWD_LENGTH, stdin);
            user_pwd[strcspn(user_pwd, "\n")] = '\0';
        }

    } while (strcmp(user_pwd,conf_user_pwd) != 0);

    if (sodium_init() < 0) {
        return;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, SALT_SIZE);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, NONCE_SIZE);

    if (crypto_pwhash(key_out, crypto_secretbox_KEYBYTES,
                  user_pwd, strlen(user_pwd), salt,
                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                  crypto_pwhash_MEMLIMIT_INTERACTIVE,
                  crypto_pwhash_ALG_ARGON2ID13) != 0) {
        printf("Key derivation failed\n");
        return;
    }

    const char *verification_msg = "Val1D_Passw0Rd";
    unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    crypto_secretbox_easy(ciphertext, verification_msg,PWD_LENGTH, nonce, key_out);
    
    FILE *file = fopen("database.bin","wb");
    if(file == NULL){
        printf("Could not open the file.\n");
        return;
    }

    fwrite(salt, 1, SALT_SIZE, file);
    fwrite(nonce, 1, NONCE_SIZE, file);
    fwrite(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);
    for (int i = 0; i < crypto_secretbox_KEYBYTES; i++){
        printf("%02x", key_out[i]);
    }

    sodium_memzero(user_pwd, sizeof(user_pwd));
}

void see_pwd(unsigned char *key_out){
    Record records[MAX_RECORD];
    FILE *file = fopen("database.bin","rb");
    if(file == NULL){
        printf("Could not open the file.\n");
        return;
    }

    unsigned char header[SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH];
    fread(header, 1, HEADER_SIZE, file);

    int count  = 0;
    
    while(count < MAX_RECORD){
        if(fread(records[count].name, 1, NAME_SIZE, file) != NAME_SIZE) {
            break;
        } records[count].name[NAME_SIZE - 1] = '\0';

        if(fread(records[count].username, 1, NAME_SIZE, file) != NAME_SIZE) {
            break;
        } records[count].username[NAME_SIZE - 1] = '\0';

        if(fread(records[count].nonce, 1, NONCE_SIZE, file) != NONCE_SIZE) {
            break;
        }
            
        unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
        if(fread(ciphertext, 1, crypto_secretbox_MACBYTES+PWD_LENGTH, file) != crypto_secretbox_MACBYTES+PWD_LENGTH) {
            break;
        }
        if (crypto_secretbox_open_easy(records[count].pwd, ciphertext, crypto_secretbox_MACBYTES+PWD_LENGTH, records[count].nonce, key_out) != 0) {
            printf("%s !!! %s", records[count].pwd,ciphertext);
            fclose(file);
            return;
        }
        printf("\n");
        count++;
    } 

    if (count == 0){
        printf("You have stored no password yet.\n");
    }
    fclose(file);

    printf(" name / username-email / password\n");
    printf("==================================\n");
    for(int i = 0; i<count; i++){
        printf("%s {%s, %s}\n", records[i].name,records[i].username,records[i].pwd);
    }
    printf("\nYou have %d password stored. you have enough space for %d more.\n", count, MAX_RECORD - count);
}

void search_pwd(unsigned char *key_out){
    Record records[MAX_RECORD];

    char name[NAME_SIZE];
    printf("For what app are you looking for / What username are you looking for: ");
    fgets(name,sizeof(name),stdin);
    name[strcspn(name, "\n")] = '\0';

    FILE *file = fopen("database.bin","rb");
    if(file == NULL){
        printf("Could not open the file.\n");
        return;
    }

    unsigned char header[SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH];
    fread(header, 1, HEADER_SIZE, file);

    int count  = 0;
    int consider[] = {};
    int index = 0;
    bool found = false;
    while(count < MAX_RECORD){
        found = false;
        if(fread(records[count].name, 1, NAME_SIZE, file) != NAME_SIZE) {
            break;
        } records[count].name[NAME_SIZE - 1] = '\0';
        if (part_of(name, records[count].name)){
            consider[index] = count;
            index++;
            found = true;
        }   

        if(fread(records[count].username, 1, NAME_SIZE, file) != NAME_SIZE) {
            break;
        } records[count].username[NAME_SIZE - 1] = '\0';
        if (part_of(name, records[count].username)){
            consider[index] = count;
            index++;
            found = true;
        }   

        if(fread(records[count].nonce, 1, NONCE_SIZE, file) != NONCE_SIZE) {
            break;
        } 

        unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
        if(fread(ciphertext, 1, crypto_secretbox_MACBYTES+PWD_LENGTH, file) != crypto_secretbox_MACBYTES+PWD_LENGTH) {
            break;
        }
        if(found){
            if (crypto_secretbox_open_easy(records[count].pwd, ciphertext, crypto_secretbox_MACBYTES+PWD_LENGTH, records[count].nonce, key_out) != 0) {
                printf("%s !!! %s", records[count].pwd,ciphertext);
                fclose(file);
                return;
            }
        }
        count++;
    }

    fclose(file);

    if(index == 0){
        printf("No result.\n");
        return;
    }


    printf(" name / username-email / password\n");
    printf("==================================\n");
    for(int i = 0; i < index; i++){
        printf("%s {%s, %s}\n", records[consider[i]].name,records[consider[i]].username,records[consider[i]].pwd);
    }
}

bool part_of(char *search, char *name){
    char name_lower[NAME_SIZE];
    char search_lower[NAME_SIZE];
    strncpy(name_lower, name, NAME_SIZE);
    strncpy(search_lower, search, NAME_SIZE);
    int search_len = strlen(search_lower);
    int name_len = strlen(name_lower);
    for(int i =0; i<name_len; i++) {
        name_lower[i] = tolower(name_lower[i]);
    }
    for(int i =0; i<search_len; i++) {
        search_lower[i] = tolower(search_lower[i]);
    }

    for (int i = 0; i <= name_len - search_len; i++){
        int j;
        for(j = 0; j < search_len; j++){
            if(name_lower[i+j] != search_lower[j]){
                break;
            }
        }
        if(j == search_len){
            return true;
        }
    }
    return false;
}
