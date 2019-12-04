#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include <sys/types.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//Code taken from online
typedef union uwb {
    unsigned w;
    unsigned char b[4];
} WBunion;
//Code taken from online
typedef unsigned Digest[4];
//Code taken from online
unsigned f0(unsigned abcd[])
{
    return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);
}
//Code taken from online
unsigned f1(unsigned abcd[])
{
    return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);
}
//Code taken from online
unsigned f2(unsigned abcd[])
{
    return abcd[1] ^ abcd[2] ^ abcd[3];
}
//Code taken from online
unsigned f3(unsigned abcd[])
{
    return abcd[2] ^ (abcd[1] | ~abcd[3]);
}
//Code taken from online
typedef unsigned (*DgstFctn)(unsigned a[]);

//Code taken from online
unsigned *calcKs(unsigned *k)
{
    double s, pwr;
    int i;

    pwr = pow(2, 32);
    for (i = 0; i < 64; i++)
    {
        s = fabs(sin(1 + i));
        k[i] = (unsigned)(s * pwr);
    }
    return k;
}

//Code taken from online
// ROtate v Left by amt bits
unsigned rol(unsigned v, short amt)
{
    unsigned msk1 = (1 << amt) - 1;
    return ((v >> (32 - amt)) & msk1) | ((v << amt) & ~msk1);
}
//Code taken from online
unsigned *md5(const char *msg, int mlen)
{
    static Digest h0 = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    static DgstFctn ff[] = {&f0, &f1, &f2, &f3};
    static short M[] = {1, 5, 3, 7};
    static short O[] = {0, 1, 5, 0};
    static short rot0[] = {7, 12, 17, 22};
    static short rot1[] = {5, 9, 14, 20};
    static short rot2[] = {4, 11, 16, 23};
    static short rot3[] = {6, 10, 15, 21};
    static short *rots[] = {rot0, rot1, rot2, rot3};
    static unsigned kspace[64];
    static unsigned *k;

    static Digest h;
    Digest abcd;
    DgstFctn fctn;
    short m, o, g;
    unsigned f;
    short *rotn;
    union {
        unsigned w[16];
        char b[64];
    } mm;
    int os = 0;
    int grp, grps, q, p;
    unsigned char *msg2;

    if (k == NULL)
        k = calcKs(kspace);

    for (q = 0; q < 4; q++)
        h[q] = h0[q]; // initialize

    {
        grps = 1 + (mlen + 8) / 64;
        msg2 = malloc(64 * grps);
        memcpy(msg2, msg, mlen);
        msg2[mlen] = (unsigned char)0x80;
        q = mlen + 1;
        while (q < 64 * grps)
        {
            msg2[q] = 0;
            q++;
        }
        {
            //            unsigned char t;
            WBunion u;
            u.w = 8 * mlen;
            //            t = u.b[0]; u.b[0] = u.b[3]; u.b[3] = t;
            //            t = u.b[1]; u.b[1] = u.b[2]; u.b[2] = t;
            q -= 8;
            memcpy(msg2 + q, &u.w, 4);
        }
    }

    for (grp = 0; grp < grps; grp++)
    {
        memcpy(mm.b, msg2 + os, 64);
        for (q = 0; q < 4; q++)
            abcd[q] = h[q];
        for (p = 0; p < 4; p++)
        {
            fctn = ff[p];
            rotn = rots[p];
            m = M[p];
            o = O[p];
            for (q = 0; q < 16; q++)
            {
                g = (m * q + o) % 16;
                f = abcd[1] + rol(abcd[0] + fctn(abcd) + k[q + 16 * p]
                                  + mm.w[g],
                                  rotn[q % 4]);

                abcd[0] = abcd[3];
                abcd[3] = abcd[2];
                abcd[2] = abcd[1];
                abcd[1] = f;
            }
        }
        for (p = 0; p < 4; p++)
            h[p] += abcd[p];
        os += 64;
    }

    if (msg2)
        free(msg2);

    return h;
}

/**
 * Hashes a string with the provided hash.
 */
void strhash(char *hash, const char *msg)
{
    int j, k;
    unsigned *d = md5(msg, strlen(msg));
    WBunion u;

    hash[0] = 0;
    sprintf(hash, "= 0x");
    for (j = 0; j < 4; j++)
    {
        u.w = d[j];
        char temp_str[10];
        for (k = 0; k < 4; k++)
        {
            sprintf(temp_str, "%02x", u.b[k]);
            strcat(hash, temp_str);
            temp_str[0] = 0;
        }
    }
}

/**
 * Hashes a singular file, and stores it in the provided hash.
 */
int filehash(char *hash, char *filename)
{
    FILE *fp;
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        printf("File cannot be opened");
        return -1;
    }
    char total_hash[100];
    total_hash[0] = 0;

    char buffer[100];
    buffer[0] = 0;

    char buffer_hash[100];
    buffer_hash[0] = 0;

    int buffer_count = 0;
    while (!feof(fp))
    {
        while (buffer_count < 100)
        {
            buffer[buffer_count] = fgetc(fp);
            buffer_count++;
        }
        //Put a hash of the current buffer into buffer_hash
        strhash(buffer_hash, buffer);
        //Create a new string to store a combination in
        char comb_hash[100];
        comb_hash[0] = 0;
        //Add the buffer hash to the combined hash
        strcat(comb_hash, buffer_hash);
        //Add the total hash to the combined hash
        strcat(comb_hash, total_hash);
        //Put the combined hash into the total hash
        strhash(total_hash, comb_hash);
        //Reset our buffer
        buffer_count = 0;
        buffer[0] = 0;
        buffer_hash[0] = 0;
        comb_hash[0] = 0;
    }
    hash[0] = 0;
    strcat(hash, total_hash);
    return 0;
}

/**
 * Lists all files and sub-directories at given path, and hashes them
 * appropriately.
 */
void dirHash(char *hash, char *basePath)
{
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);

    // Unable to open directory stream
    if (!dir)
        return;

    printf("Scanning directory \"%s\"...\n", basePath);

    // While we have files to read, keep reading
    while ((dp = readdir(dir)) != NULL)
    {
        // If the directory isn't . or .., do stuff with it
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {
            // Construct new path from our base path
            strcpy(path, basePath);
            strcat(path, "/");
            strcat(path, dp->d_name);
            printf("Found: %s\n", path);

            // Used to check whether something is a file or directory
            struct stat path_stat;
            stat(path, &path_stat);

            // Temp hash to store this file's hash
            char tempHash[100];
            tempHash[0] = '0';

            // If it is a file, do a filehash. Otherwise, don't hash.
            if (S_ISDIR(path_stat.st_mode) == 0){
                filehash(tempHash, path);
                printf("    File's hash is: %s\n", tempHash);
            } else {
                printf("    Is directory, do not hash, but don't ignore\n");

            }

            // Told to make sure not to ask like a folder doesn't exist,
            // so must be outside the if/else rather than inside the if
            // Concat the two hashes and hash that string
            char catHash[200];
            catHash[0] = 0;
            strcpy(catHash, hash);
            strcat(catHash, tempHash);
            strhash(hash, catHash);
            printf("    Combined hash is %s\n", hash);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[])
{
    printf("Welcome to our hashing program! Enter however many files or "
           "directories you want,\nand we will hash them! Keep in mind that "
           "entering the same file more than once,\nor changing the order "
           "your enter the files will change the resulting top hash. Enjoy!\n");
    // For storing the user entered path
    char path[1000];
    // Used to check if user wants to exit and get their hash
    int exitLoop = 0;

    char finalHash[100];
    finalHash[0] = 0;

    // Input path from user
    while(exitLoop == 0){
        printf("\nEnter path to list files. To exit and get your top hash, type "
               "!exit :");
        scanf("%s", path);

        if(strcmp(path, "!exit") == 0){
            printf("Your final top hash is: %s\n", finalHash);
            printf("Exiting.");
            return 0;
        }

        // Used to check if path is a file or directory
        struct stat path_stat;
        stat(path, &path_stat);

        char tempHash[100];
        tempHash[0] = 0;

        int validFile;

        if (S_ISDIR(path_stat.st_mode) != 0) {
            dirHash(tempHash, path);

            if(tempHash[0] == 0){
                printf("Invalid directory!\n");
            }
            else{
                printf("\n--Final hash for %s: %s\n", path, tempHash);
            }
        } else {
            // If the file is a valid file, validFile = 0
            validFile = filehash(tempHash, path);
            if(tempHash[0] == 0){
                printf("\nInvalid file!\n");
            }
            else{
                printf("\n--Hash for %s: %s\n", path, tempHash);
            }
        }
        // Makes sure if invalid file entered, does not change top hash
        if (validFile != -1) {
            char catHash[200];
            catHash[0] = 0;
            strcpy(catHash, finalHash);
            strcat(catHash, tempHash);
            strhash(finalHash, catHash);
        }
    }
    return 0;
}
