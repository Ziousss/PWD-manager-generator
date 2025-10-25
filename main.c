/* Includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/* Definitions */
#define MAX_SIZE 256
#define MAX_RECORD 100

/* Function signatures*/
bool pwd_verif();
void add_pwd();

/* Struct */
typedef struct {
    char name[MAX_SIZE];
    char pwd[MAX_SIZE];
} Record;

/* Function's code */
int main(int argc, char* argv[]){
    if (argc != 1){
        return 1;
    }
    int usage = 0;
    int myNum;

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

/*
things to implement
    pwd evaluation; strong, medium, weak.
*/