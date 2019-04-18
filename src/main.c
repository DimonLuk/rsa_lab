#include "../lib/include/rsa.h"
#include "include/src.h"
#include <stdio.h>
#include <string.h>


int main(int argc, char *argv[]) {
    key_pair *kp = key_pair_alloc();
    printf("Type a message: ");
    char *msg;
    scanf("%m[^\n]s", &msg);

    message *data = create_message((void*)msg, strlen(msg));
    message *encrypted = message_alloc();
    message *decrypted = message_alloc();
    generate_key_pair(kp);

    printf("Base: %u\n", kp->base);
    printf("Public key: %u\n", kp->public_key);
    printf("Private key: %u\n", kp->private_key);

    encrypt(data, encrypted, kp);
    decrypt(encrypted, decrypted, kp);

    printf("Original: '%s'\n", (char*)data->message);
    printf("Encrypted: '%s'\n", (char*)encrypted->message);
    printf("Decrypted: '%s'\n", (char*)decrypted->message);


    free(msg);
    free_key_pair(kp);
    free_message(data);
    free_message(encrypted);
    free_message(decrypted);
    return 0;
}
