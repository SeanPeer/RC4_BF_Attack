// Cryptography Course Assignment - Attacking RC4 with brute force 
// Written By Sean Peer.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


void KSA(unsigned char *key, int key_length, unsigned char *S);
unsigned char PRGA(unsigned char *S, unsigned char *i, unsigned char *j);
void RC4(unsigned char *key, int key_length, unsigned char *plaintext, unsigned char *ciphertext);
void encrypt_decrypt(unsigned char *message, unsigned char *key, unsigned char *result);
void brute_force(unsigned char *ciphertext, unsigned char *message, size_t message_len);

// Function implementations
void KSA(unsigned char *key, int key_length, unsigned char *S)
{
    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        S[i] = i;
    }
    for (int i = 0; i < 256; i++)
    {
        j = (j + S[i] + key[i % key_length]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

unsigned char PRGA(unsigned char *S, unsigned char *i, unsigned char *j)
{
    *i = (*i + 1) % 256;
    *j = (*j + S[*i]) % 256;
    unsigned char temp = S[*i];
    S[*i] = S[*j];
    S[*j] = temp;
    return S[(S[*i] + S[*j]) % 256];
}

void RC4(unsigned char *key, int key_length, unsigned char *plaintext, unsigned char *ciphertext)
{
    unsigned char S[256];
    KSA(key, key_length, S);
    unsigned char i = 0, j = 0;
    for (size_t n = 0, len = strlen((char *)plaintext); n < len; n++)
    {
        unsigned char k = PRGA(S, &i, &j);
        ciphertext[n] = plaintext[n] ^ k;
    }
    ciphertext[strlen((char *)plaintext)] = '\0';
}

void encrypt_decrypt(unsigned char *message, unsigned char *key, unsigned char *result)
{
    int key_length = strlen((char *)key);
    RC4(key, key_length, message, result);
}

void brute_force(unsigned char *ciphertext, unsigned char *message, size_t message_len)
{
    unsigned char decryptedtext[256];
    unsigned char str_key[6] = {0}; // 5 characters + null terminator
    unsigned long long start_time, end_time;

    start_time = clock();
    int found = 0;

    // ASCII printable characters from 32 (space) to 126 (tilde)
    for (int i = 32; i <= 126 && !found; i++)
    {
        for (int j = 32; j <= 126 && !found; j++)
        {
            for (int k = 32; k <= 126 && !found; k++)
            {
                for (int l = 32; l <= 126 && !found; l++)
                {
                    for (int r = 32; r <= 126 && !found; r++)
                    {
                        str_key[0] = i;
                        str_key[1] = j;
                        str_key[2] = k;
                        str_key[3] = l;
                        str_key[4] = r;
                        str_key[5] = '\0'; // Ensure the string is null-terminated

                        encrypt_decrypt(ciphertext, str_key, decryptedtext);

                        if (memcmp(message, decryptedtext, message_len) == 0)
                        {
                            printf("SUCCESS! Key found: %s\n", str_key);
                            found = 1;
                        }
                    }
                }
            }
        }
    }

    if (!found)
    {
        printf("Key not found within the given range.\n");
    }

    end_time = clock();
    double cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Time For Brute Force: %f Seconds\n", cpu_time_used);
}

int main()
{
    unsigned char message[] = "Unlock the mysteries of the universe with boundless curiosity";
    unsigned char key[] = "Abc@!";
    unsigned char ciphertext[256];

    encrypt_decrypt(message, key, ciphertext);
    printf("Original Message: %s\n", message);
    printf("Cipher Message: %s\n", ciphertext);
    brute_force(ciphertext, message, strlen((char *)message)); // Pass the message length

    return 0;
}
