#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sodium.h>
#include <time.h>
#include <ctype.h>
#include <math.h>

#include "main.h"
#include "defs.h"
#include "helperFunction.h"

/* Function's code */
int main(int argc, char *argv[])
{
    if (argc != 1)
    {
        return 1;
    }
    unsigned char key[crypto_secretbox_KEYBYTES];

    char myNum[10];

    FILE *file = fopen("database.bin", "rb");
    if (file == NULL)
    {
        first_time(key);
    }
    else
    {
        fclose(file);
        bool found = pwd_verif(key);
        if (!found)
        {
            int i = 0;
            do
            {
                i++;
                time_t start = time(NULL);
                while (time(NULL) - start < 3)
                {
                    // wait
                }

                printf("\nWrong password, %d tries left\n", 3 - i);
                found = pwd_verif(key);
            } while (!found && i != 3);
            if (i == 3)
            {
                return -1;
            }
        }
    }
    while (1)
    {
        printf("\nWhat do you want to do ?\n");
        printf("1. Add new password\n2. See current password\n3. Search password\n4. Change existing password\n5. Delete a password from the list\n6. Generate a strong password\n7. Exit\n");
        fgets(myNum, sizeof(myNum), stdin);
        int realNum = atoi(myNum);

        FILE *file = fopen("database.bin", "rb");
        if (file == NULL)
        {
            printf("no file detected.\n");
            return -1;
        }
        switch (realNum)
        {
        case 1:
            add_pwd(key);
            break;
        case 2:
            see_pwd(key);
            break;
        case 3:
            search_pwd(key,NULL);
            break;
        case 4:
            change_pwd(key);
            break;
        case 5:
            delete_pwd(key);
            break;
        case 6:
            char *pwd = pwd_generator();
            free(pwd);
            break;
        default:
            printf("Invalid number");
            break;
        }
    }
}

bool pwd_verif(unsigned char *key_out)
{
    Record records[MAX_RECORD];
    char user_input[NAME_SIZE];
    memset(user_input, 0, NAME_SIZE);

    system("stty -echo");
    printf("Password: \n");
    fgets(user_input, sizeof(user_input), stdin);
    user_input[strcspn(user_input, "\n")] = '\0';

    FILE *file = fopen("database.bin", "rb");
    if (file == NULL)
    {
        printf("ERROR: Could not open database\n");
        return false;
    }

    unsigned char salt[SALT_SIZE];
    fread(salt, 1, SALT_SIZE, file);

    unsigned char nonce[NONCE_SIZE];
    fread(nonce, 1, NONCE_SIZE, file);

    unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    size_t ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);

    if (crypto_pwhash(key_out, crypto_secretbox_KEYBYTES,
                      user_input, strlen(user_input), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        printf("Key derivation failed\n");
        system("stty echo");
        return false;
    }

    unsigned char decrypted[PWD_LENGTH];

    if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key_out) != 0)
    {
        system("stty echo");
        return false;
    }

    sodium_memzero(user_input, sizeof(user_input));

    system("stty echo");
    return true;
}

void add_pwd(unsigned char *key_out)
{
    FILE *file;
    Record records[MAX_RECORD];

    char new_name[NAME_SIZE];
    memset(new_name, 0, NAME_SIZE);
    printf("For what is this password for ? [name]\n");
    fgets(new_name, sizeof(new_name), stdin);
    new_name[strcspn(new_name, "\n")] = '\0';

    file = fopen("database.bin", "rb");
    if (file == NULL)
    {
        printf("Could not open the file.\n");
        return;
    }

    unsigned char header[SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH];
    fread(header, 1, HEADER_SIZE, file);

    int count = 0;
    while (count < MAX_RECORD)
    {
        if (fread(records[count].name, 1, NAME_SIZE, file) != NAME_SIZE)
        {
            break;
        }
        records[count].name[NAME_SIZE - 1] = '\0';

        if (fread(records[count].username, 1, NAME_SIZE, file) != NAME_SIZE)
        {
            break;
        }
        records[count].username[NAME_SIZE - 1] = '\0';

        if (fread(records[count].nonce, 1, NONCE_SIZE, file) != NONCE_SIZE)
        {
            break;
        }

        unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
        if (fread(ciphertext, 1, sizeof(ciphertext), file) != sizeof(ciphertext))
        {
            break;
        }
        count++;
    }
    fclose(file);

    for (int i = 0; i < count; i++)
    {
        if (strcmp(records[i].name, new_name) == 0)
        {
            printf("This name already has a password.\n");
            return;
        }
    }

    char new_username[NAME_SIZE];
    memset(new_username, 0, NAME_SIZE);
    printf("What is your username/e-mail address for this app ?\n");
    fgets(new_username, sizeof(new_username), stdin);
    new_username[strcspn(new_username, "\n")] = '\0';

    char answer[3];
    do
    {
        printf("Do you want the password to be auto-generated? [Y/N]\n");
        fgets(answer, sizeof(answer), stdin);
    } while (strcmp(answer, "n\n") != 0 && strcmp(answer, "N\n") != 0 && strcmp(answer, "y\n") != 0 && strcmp(answer, "Y\n") != 0);

    char new_pwd[PWD_LENGTH];
    memset(new_pwd, 0, PWD_LENGTH);
    char *pwd;
    if (strcmp(answer, "Y\n") == 0 || strcmp(answer, "y\n") == 0)
    {
        do
        {
            pwd = pwd_generator();
            printf("\nDo you like this password? [Y/N] Press 1 to return.\n");
            fgets(answer, sizeof(answer), stdin);
            if (strcmp("1\n", answer) == 0)
            {
                return;
            }
        } while (strcmp(answer, "Y\n") != 0 && strcmp(answer, "y\n") != 0);
        strcpy(new_pwd, pwd);
        free(pwd);
    }
    else
    {
        system("stty -echo");
        printf("What is the password?\n");
        fgets(new_pwd, sizeof(new_pwd), stdin);
        new_pwd[strcspn(new_pwd, "\n")] = '\0';
        char *level = pwd_level(new_pwd);
        if (strcmp(level, "invalid") == 0)
        {
            printf("invalid password.\n");
            return;
        }
        system("stty echo");

        printf("This password is %s. Do you want to keep it? [Y/N]\n", level);
        fgets(answer, sizeof(answer), stdin);

        while (strcmp(answer, "Y\n") != 0 && strcmp(answer, "y\n") != 0 && strcmp(answer, "N\n") != 0 && strcmp(answer, "n\n") != 0)
        {
            printf("Invalid input. Please enter Y or N:\n");
            fgets(answer, sizeof(answer), stdin);
        }

        if (strcmp(answer, "Y\n") == 0 || strcmp(answer, "y\n") == 0)
        {
            printf("Password kept.\n");
        }
        else
        {
            printf("Password discarded.\n");
            return;
        }

        system("stty -echo");
        char new_pwd_conf[PWD_LENGTH];
        memset(new_pwd_conf, 0, PWD_LENGTH);
        printf("Please confirm your password?\n");
        fgets(new_pwd_conf, sizeof(new_pwd_conf), stdin);
        new_pwd_conf[strcspn(new_pwd_conf, "\n")] = '\0';
        if (strcmp(new_pwd, new_pwd_conf) != 0)
        {
            printf("Not matching.\n");
            return;
        }
        system("stty echo");
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char pwd_padded[PWD_LENGTH];
    memset(pwd_padded, 0, PWD_LENGTH);
    memcpy(pwd_padded, new_pwd, strlen(new_pwd));

    unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    crypto_secretbox_easy(ciphertext, pwd_padded, PWD_LENGTH, nonce, key_out);

    file = fopen("database.bin", "ab");
    if (file == NULL)
    {
        printf("ERROR: could not open the file.\n");
        return;
    }

    fwrite(new_name, 1, sizeof(new_name), file);
    fwrite(new_username, 1, sizeof(new_name), file);
    fwrite(nonce, 1, NONCE_SIZE, file);
    fwrite(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);

    sodium_memzero(ciphertext, sizeof(ciphertext));
    sodium_memzero(nonce, NONCE_SIZE);
}

void first_time(unsigned char *key_out)
{
    char user_pwd[PWD_LENGTH];
    char conf_user_pwd[PWD_LENGTH];
    memset(user_pwd, 0, PWD_LENGTH);
    memset(conf_user_pwd, 0, PWD_LENGTH);

    printf("This is the first time you open this program.\n");
    printf("Please set a password. This one will be asked every time you open the program so be sure to remember it!\n");
    printf("Password: ");
    fgets(user_pwd, PWD_LENGTH, stdin);
    user_pwd[strcspn(user_pwd, "\n")] = '\0';
    char *level = pwd_level(user_pwd);

    while (1)
    {
        while (strcmp(level, "Invalid") == 0)
        {
            printf("Invalid password. Please enter again: ");
            fgets(user_pwd, PWD_LENGTH, stdin);
            level = pwd_level(user_pwd);
        }

        user_pwd[strcspn(user_pwd, "\n")] = '\0';
        printf("This password is %s. Please confirm by retyping it. Press 1 to change the original password.\n", level);
        printf("Password: ");
        fgets(conf_user_pwd, PWD_LENGTH, stdin);
        conf_user_pwd[strcspn(conf_user_pwd, "\n")] = '\0';

        if (strcmp(conf_user_pwd, "1\0") == 0)
        {
            printf("Change orignial password: ");
            fgets(user_pwd, PWD_LENGTH, stdin);
            user_pwd[strcspn(user_pwd, "\n")] = '\0';
        }
        else if (strcmp(user_pwd, conf_user_pwd) == 0)
        {
            break;
        }
    }

    if (sodium_init() < 0)
    {
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
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        printf("Key derivation failed\n");
        return;
    }

    const char *verification_msg = "Val1D_Passw0Rd";
    unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    crypto_secretbox_easy(ciphertext, verification_msg, PWD_LENGTH, nonce, key_out);

    FILE *file = fopen("database.bin", "wb");
    if (file == NULL)
    {
        printf("Could not open the file.\n");
        return;
    }

    fwrite(salt, 1, SALT_SIZE, file);
    fwrite(nonce, 1, NONCE_SIZE, file);
    fwrite(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);

    sodium_memzero(user_pwd, sizeof(user_pwd));
}

void see_pwd(unsigned char *key_out)
{
    Record records[MAX_RECORD];
    FILE *file = fopen("database.bin", "rb");
    if (file == NULL)
    {
        printf("Could not open the file.\n");
        return;
    }

    unsigned char header[HEADER_SIZE];
    fread(header, 1, HEADER_SIZE, file);

    int count = 0;

    while (count < MAX_RECORD)
    {
        if (fread(records[count].name, 1, NAME_SIZE, file) != NAME_SIZE)
        {
            break;
        }
        records[count].name[NAME_SIZE - 1] = '\0';

        if (fread(records[count].username, 1, NAME_SIZE, file) != NAME_SIZE)
        {
            break;
        }
        records[count].username[NAME_SIZE - 1] = '\0';

        if (fread(records[count].nonce, 1, NONCE_SIZE, file) != NONCE_SIZE)
        {
            break;
        }

        unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
        if (fread(ciphertext, 1, crypto_secretbox_MACBYTES + PWD_LENGTH, file) != crypto_secretbox_MACBYTES + PWD_LENGTH)
        {
            break;
        }
        if (crypto_secretbox_open_easy(records[count].pwd, ciphertext, crypto_secretbox_MACBYTES + PWD_LENGTH, records[count].nonce, key_out) != 0)
        {
            fclose(file);
            return;
        }
        printf("\n");
        count++;
    }

    if (count == 0)
    {
        printf("You have stored no password yet.\n");
    }
    fclose(file);

    printf(" name / username-email / password\n");
    printf("==================================\n");
    for (int i = 0; i < count; i++)
    {
        printf("%s {%s, %s (%s)}\n", records[i].name, records[i].username, records[i].pwd, pwd_level(records[i].pwd));
    }
    printf("\nYou have %d password stored. you have enough space for %d more.\n", count, MAX_RECORD - count);
}

void search_pwd(unsigned char *key_out, unsigned char *name)
{
    Record records[MAX_RECORD];

    char name_buf[NAME_SIZE];
    unsigned char *search_name;

    if (name == NULL)
    {
        printf("For what app are you looking for / What username are you looking for: ");
        fgets(name_buf, sizeof(name_buf), stdin);
        name_buf[strcspn(name_buf, "\n")] = '\0';
        search_name = (unsigned char *)name_buf;
    }
    else
    {
        search_name = name;
    }

    FILE *file = fopen("database.bin", "r+b");
    if (file == NULL)
    {
        printf("Could not open the file.\n");
        return;
    }

    unsigned char header[HEADER_SIZE];
    fread(header, 1, HEADER_SIZE, file);

    int count = 0;
    int consider[MAX_RECORD];
    int index = 0;
    bool found = false;
    while (count < MAX_RECORD)
    {
        found = false;
        if (fread(records[count].name, 1, NAME_SIZE, file) != NAME_SIZE)
        {
            break;
        }
        records[count].name[NAME_SIZE - 1] = '\0';
        if (part_of(search_name, records[count].name))
        {
            consider[index] = count;
            index++;
            found = true;
        }

        if (fread(records[count].username, 1, NAME_SIZE, file) != NAME_SIZE)
        {
            break;
        }
        records[count].username[NAME_SIZE - 1] = '\0';
        if (part_of(search_name, records[count].username))
        {
            for (int i = 0; i < index - 1; i++)
            {
                if (consider[i] == index)
                {
                    bool found = true;
                }
                if (!found)
                {
                    consider[index] = count;
                    index++;
                }
            }
        }

        if (fread(records[count].nonce, 1, NONCE_SIZE, file) != NONCE_SIZE)
        {
            break;
        }

        unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
        if (fread(ciphertext, 1, crypto_secretbox_MACBYTES + PWD_LENGTH, file) != crypto_secretbox_MACBYTES + PWD_LENGTH)
        {
            break;
        }
        if (found)
        {
            if (crypto_secretbox_open_easy(records[count].pwd, ciphertext, crypto_secretbox_MACBYTES + PWD_LENGTH, records[count].nonce, key_out) != 0)
            {
                printf("fail");
                fclose(file);
                return;
            }
        }
        count++;
    }

    fclose(file);

    if (index == 0)
    {
        printf("No result.\n");
        return;
    }

    printf(" name / username-email / password\n");
    printf("==================================\n");
    for (int i = 0; i < index; i++)
    {
        printf("%s {%s, %s (%s)}\n", records[consider[i]].name, records[consider[i]].username, records[consider[i]].pwd, pwd_level(records[consider[i]].pwd));
    }
}

void change_pwd(unsigned char *key_out)
{
    char name_search[NAME_SIZE];
    printf("Which password would you like to change? Type the name of the application which has this password.\n");
    fgets(name_search, NAME_SIZE, stdin);
    name_search[strcspn(name_search, "\n")] = '\0';

    int count = 0;
    Record records[MAX_RECORD];
    int index = -1;
    bool found = false;

    FILE *file = fopen("database.bin", "r+b");
    unsigned char header[SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH];
    fread(header, 1, HEADER_SIZE, file);

    unsigned char ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    long record_pos;
    for (int i = 0; i < MAX_RECORD; i++)
    {
        long start_pos = ftell(file);

        if (fread(records[i].name, 1, NAME_SIZE, file) != NAME_SIZE)
            break;
        fread(records[i].username, 1, NAME_SIZE, file);
        fread(records[i].nonce, 1, NONCE_SIZE, file);
        fread(ciphertext, 1, sizeof(ciphertext), file);

        if (strcmp(records[i].name, name_search) == 0)
        {
            index = i;
            record_pos = start_pos;
            break;
        }
    }

    if (index == -1)
    {
        printf("No result.\n");
        printf("Did you mean one of those ?\n");
        search_pwd(key_out, name_search);
        fclose(file);
        return;
    }

    if ((crypto_secretbox_open_easy(records[index].pwd, ciphertext, sizeof(ciphertext), records[index].nonce, key_out)) != 0)
    {
        fclose(file);
        return;
    }

    printf(" name / username-email / password\n");
    printf("==================================\n");

    printf("%s {%s, %s (%s)}\n", records[index].name, records[index].username, records[index].pwd, pwd_level(records[index].pwd));

    char answer[3];
    do
    {
        printf("Is this what you want to change? [Y/N]");
        fgets(answer, sizeof(answer), stdin);
    } while (strcmp(answer, "n\n") != 0 && strcmp(answer, "N\n") != 0 && strcmp(answer, "y\n") != 0 && strcmp(answer, "Y\n") != 0);
    if (strcmp(answer, "n\n") == 0 || strcmp(answer, "N\n") == 0)
    {
        return;
    }

    char new_username[NAME_SIZE];
    printf("What is the new username?\n");
    fgets(new_username, sizeof(new_username), stdin);
    new_username[strcspn(new_username, "\n")] = '\0';

    char new_pwd[PWD_LENGTH];
    char conf_new_pwd[PWD_LENGTH];
    do
    {
        printf("Do you want to auto generate it? [Y/N]\n");
        fgets(answer, sizeof(answer), stdin);
    } while (strcmp(answer, "N\n") != 0 && strcmp(answer, "n\n") != 0 && strcmp(answer, "Y\n") != 0 && strcmp(answer, "y\n") != 0);
    char *pwd;
    if (strcmp(answer, "Y\n") == 0 || strcmp(answer, "y\n") == 0)
    {
        do
        {
            pwd = pwd_generator();
            printf("\nDo you like this password? [Y/N] Press 1 to return.\n");
            fgets(answer, sizeof(answer), stdin);
            if (strcmp("1\n", answer) == 0)
            {
                return;
            }
        } while (strcmp(answer, "Y\n") != 0 && strcmp(answer, "y\n") != 0);
        strcpy(new_pwd, pwd);
        free(pwd);
    }
    else
    {
        printf("What is the new password?\n");
        system("stty -echo");
        fgets(new_pwd, sizeof(new_pwd), stdin);
        new_pwd[strcspn(new_pwd, "\n")] = '\0';
        if (strcmp(new_pwd, records[index].pwd) == 0)
        {
            do
            {
                printf("New password cannot be the same as the prious one.\n");
                fgets(new_pwd, sizeof(new_pwd), stdin);
                new_pwd[strcspn(new_pwd, "\n")] = '\0';

            } while (strcmp(new_pwd, records[index].pwd) == 0);
        }

        char *level = pwd_level(new_pwd);
        printf("This password is %s, confirm it.\n", level);
        fgets(conf_new_pwd, sizeof(conf_new_pwd), stdin);
        conf_new_pwd[strcspn(conf_new_pwd, "\n")] = '\0';

        if (strcmp(conf_new_pwd, new_pwd) != 0 || strcmp(new_pwd, records[index].pwd) == 0)
        {
            do
            {
                printf("Both password do not match. Press 1 to change the original password.\n");
                fgets(conf_new_pwd, sizeof(conf_new_pwd), stdin);
                conf_new_pwd[strcspn(conf_new_pwd, "\n")] = '\0';
                if (strcmp(conf_new_pwd, "1") == 0)
                {
                    printf("What is the new password?\n");
                    fgets(new_pwd, sizeof(new_pwd), stdin);
                    new_pwd[strcspn(new_pwd, "\n")] = '\0';
                }

            } while (strcmp(conf_new_pwd, new_pwd) != 0 || strcmp(new_pwd, records[index].pwd) == 0);
        }
    }

    unsigned char new_ciphertext[crypto_secretbox_MACBYTES + PWD_LENGTH];
    crypto_secretbox_easy(new_ciphertext, new_pwd, PWD_LENGTH, records[index].nonce, key_out);

    fseek(file, record_pos, SEEK_SET);
    fwrite(records[index].name, 1, NAME_SIZE, file);
    fwrite(new_username, 1, NAME_SIZE, file);
    fwrite(records[index].nonce, 1, NONCE_SIZE, file);
    fwrite(new_ciphertext, 1, crypto_secretbox_MACBYTES + PWD_LENGTH, file);

    fclose(file);
    system("stty echo");
    sodium_memzero(ciphertext, sizeof(ciphertext));
    sodium_memzero(records[index].nonce, NONCE_SIZE);

    return;
}

void delete_pwd(unsigned char *key_out)
{
    Record records[MAX_RECORD];
    unsigned char to_delete[NAME_SIZE];
    printf("What is the name of the app/program you want to delete?\n");
    fgets(to_delete, NAME_SIZE, stdin);
    to_delete[strcspn(to_delete, "\n")] = '\0';

    int index = -1;

    FILE *file = fopen("database.bin", "rb");

    unsigned char header[HEADER_SIZE];
    fread(header, 1, HEADER_SIZE, file);

    int count = 0;
    for (int i = 0; i < MAX_RECORD; i++)
    {
        if (fread(records[i].name, 1, NAME_SIZE, file) != NAME_SIZE)
            break;
        if (fread(records[i].username, 1, NAME_SIZE, file) != NAME_SIZE)
            break;
        if (fread(records[i].nonce, 1, NONCE_SIZE, file) != NONCE_SIZE)
            break;
        if (fread(records[i].pwd, 1, crypto_secretbox_MACBYTES + PWD_LENGTH, file) != crypto_secretbox_MACBYTES + PWD_LENGTH)
            break;
        count++;

        if (strcmp(records[i].name, to_delete) == 0)
        {
            index = i;
        }
    }

    fclose(file);
    if (index == -1)
    {
        printf("No results found\n");
        if (print_names(to_delete) == 0)
        {
            printf("Did you mean one of these? [complete name/N]\n");
            return;
        }
    }
    char answer[3];
    printf("Are you sure you want to delete %s? [Y/N]\n", records[index].name);
    fgets(answer, sizeof(answer), stdin);

    if (strcmp(answer, "n\n") == 0 || strcmp(answer, "N\n") == 0)
    {
        return;
    }

    printf("Total records: %d, Delete index: %d\n", count, index);

    int write = 0;
    file = fopen("database.bin", "wb");
    fwrite(header, 1, HEADER_SIZE, file);
    for (int i = 0; i < count; i++)
    {
        if (i != index)
        {
            fwrite(records[i].name, 1, NAME_SIZE, file);
            fwrite(records[i].username, 1, NAME_SIZE, file);
            fwrite(records[i].nonce, 1, NONCE_SIZE, file);
            fwrite(records[i].pwd, 1, crypto_secretbox_MACBYTES + PWD_LENGTH, file);
            write++;
        }
    }

    fflush(file);
    fclose(file);

    printf("Wrote back %d records (deleted 1)\n", write);
}