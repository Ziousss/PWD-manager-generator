#include "main.h"
#include <stdbool.h>
#include <math.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>


bool part_of(char *search, char *name)
{
    char name_lower[NAME_SIZE];
    char search_lower[NAME_SIZE];
    strncpy(name_lower, name, NAME_SIZE);
    strncpy(search_lower, search, NAME_SIZE);
    int search_len = strlen(search_lower);
    int name_len = strlen(name_lower);
    for (int i = 0; i < name_len; i++)
    {
        name_lower[i] = tolower(name_lower[i]);
    }
    for (int i = 0; i < search_len; i++)
    {
        search_lower[i] = tolower(search_lower[i]);
    }

    for (int i = 0; i <= name_len - search_len; i++)
    {
        int j;
        for (j = 0; j < search_len; j++)
        {
            if (name_lower[i + j] != search_lower[j])
            {
                break;
            }
        }
        if (j == search_len)
        {
            return true;
        }
    }
    return false;
}

int print_names(unsigned char *name)
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
        return -1;
    }

    unsigned char header[SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES + PWD_LENGTH];
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
        }

        if (fread(records[count].username, 1, NAME_SIZE, file) != NAME_SIZE)
        {
            break;
        }
        records[count].username[NAME_SIZE - 1] = '\0';
        if (part_of(search_name, records[count].username))
        {
            if (!part_of(records[count].name, records[count].username))
            {
                consider[index] = count;
                index++;
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
        count++;
    }

    fclose(file);

    if (index == 0)
    {
        return 1;
    }

    printf(" name / username-email\n");
    printf("=======================\n");
    for (int i = 0; i < index; i++)
    {
        printf("%s / %s\n", records[consider[i]].name, records[consider[i]].username);
    }
    return 0;
}

char *pwd_level(unsigned char *pwd)
{
    int lowercase = 0;
    int uppercase = 0;
    int digit = 0;
    int specialcase = 0;
    for (int i = 0; i < strlen(pwd); i++)
    {
        if (pwd[i] >= 'a' && pwd[i] <= 'z')
        {
            lowercase = 26;
        }
        else if (pwd[i] >= 'A' && pwd[i] <= 'Z')
        {
            uppercase = 26;
        }
        else if (pwd[i] == ' ')
        {
            return "Invalid";
        }
        else if (isdigit(pwd[i]))
        {
            digit = 10;
        }
        else
        {
            specialcase = 32;
        }
    }

    int level = strlen(pwd) * log(lowercase + uppercase + specialcase + digit);

    if (level < 28)
        return "Very Weak";
    else if (level < 36)
        return "Weak";
    else if (level < 60)
        return "Moderate";
    else if (level < 90)
        return "Strong";
    else
        return "Very Strong";
}

char *pwd_generator()
{   
    srand(time(NULL));
    char *possibleChar = "2z9+ib|meLVw6>W/&C?!@r$d<8SPxTGOkl,hK%%-4NF.0nca)5DqZJQ3U(XMAvgtj*s=I7B^1_pYfyHoE;";
    int length = 15 + rand() % 5;
    char *pwd = malloc(length + 1);
    int len_pos = strlen(possibleChar);
    do
    {
        for (int i = 0; i < length; i++)
        {
            int value = rand() % len_pos;
            pwd[i] = possibleChar[value];
        }
        pwd[length] = '\0';
    } while (strcmp("Strong", pwd_level(pwd)) != 0 && strcmp("Very strong", pwd_level(pwd)) != 0);
    printf("%s %s", pwd, pwd_level(pwd));
    return pwd;
}