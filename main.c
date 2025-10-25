/* Includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sodium.h>

/* Definitions */
#define MAX_SIZE 256
#define MAX_RECORD 100

/* Function signatures*/
bool pwd_verif();
void add_pwd();

/* Struct */
typedef struct {
    char name[MAX_SIZE];
    char pwd[MAX_SIZE]; // will be encrypted w their nonce
    // need to implement nonce
} Record;

/* Function's code */

// need to change pwd form csv to wb for storage of salt and nonce
int main(int argc, char* argv[]){
    if (argc != 1){
        return 1;
    }
    int myNum;
    char row[100];
    FILE *file = fopen("pwd.csv", "r");
    if(fgets(row, 100, file) == NULL){
        first_time();
    }
    fclose(file);
    printf("What do you want to do ?\n"); 
    printf("1. Add new password\n 2. See current password\n 3. Change existing password\n 4. Delete a password from the list\n");
    scanf("%d", &myNum); 

    if (myNum == 1){
        if(!pwd_verif()){
            return 2;
        }
        char* new_pwd;      
        add_pwd();

        encrypt(new_pwd);
    }
    else if (myNum == 2){
        //see curent pwd
    }
    else if (myNum == 3){
        //change current pwd
    }
    else if (myNum == 4){
        //delete the pwd for a specific thing
    }
    else{
        return -1;
    }
}


bool pwd_verif(){
    Record records[MAX_RECORD];
    char row[100];
    int count = 0;
    char* user_input;
    bool found = false;

    printf("Password: ");
    scanf("%s", &user_input);

    FILE *file = fopen("pwd.csv","r");
    fgets(row, 100, file);
    row[strcspn(row, "\n")] = 0;
    char* token = strtok(row,",");
    if(token){
        strcpy(records[0].name,token);
        records[0].name[MAX_SIZE-1] = '\0';
        token = strtok(NULL, ",");

        if(token){
            strcpy(records[0].pwd,token);
            records[0].pwd[MAX_SIZE-1] = '\0';
        }
    }
    fclose(file);
    char* compare = "orignal_pwd";
    if(strcmp(records[0].name, "orignal_pwd") == 0){
        if(strcmp(decode(records[0].pwd), user_input) == 0){
            found = true;
        }
    }
    return found;
}

void add_pwd(){
    char new_name[50];
    printf("For what is this password for ? [name]\n");
    scanf("%s", new_name);
    char new_pwd[50];

    //will add the option of generate a new password later

    printf("What is the password?\n");
    scanf("%s", new_pwd);

    FILE *file = fopen("pwd.csv","a");
    if(file == NULL){
        printf("ERROR: could not open the file.\n");
        return 3;
    }

    fprintf(file, "%s,%s", new_name, new_pwd);
    fclose(file);
}

void first_time(){
    char pwd[30];
    char conf_pwd[30];

    printf("This is the first time you open this program.\n");
    printf("Please set a password. This one will be asked every time you open the program so be sure to remember it!\n");
    scanf("%s", pwd);

    char* level = pwd_level();
    do {
        char* level = pwd_level();
        printf("This password is %s. Please confirm by retyping it. Press 1 to change the original password: ", level);
        scanf("%s", conf_pwd);

        if(strcmp(conf_pwd,"1") == 0){
            printf("Change orignial password: ");
            scanf("%s", pwd);
        }

    } while (strcmp(pwd,conf_pwd) != 0);

    if (sodium_init() < 0) {
        return 1;
    }
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    FILE *file = fopen("pwd.csv","a");
    fprintf(file, "salt,");
    for (int i = 0; i < crypto_pwhash_SALTBYTES; i++) {
        fprintf(file, "%02x", salt[i]);
    }
    fprintf(file, "\n");
    fclose(file);

    // need to implement nonces
    // needs to derive a key from pwd and salt
    // still needs to encrypt a string like "verif_cypher" to try key when connecting


    return;
}