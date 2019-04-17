#include "../lib/include/rsa.h"
#include "include/src.h"
#include <stdio.h>
#include <string.h>


int main() {
    key_pair *kp = key_pair_alloc();
    char *msg = "Test";
    char *pmsg = (char*)malloc(strlen(msg));
    strcpy(pmsg, msg);
    message *data = create_message((void*)pmsg, strlen(msg));
    message *encrypted = message_alloc();
    message *decrypted = message_alloc();
    generate_key_pair(kp);

    printf("Base: %u\n", kp->base);
    printf("Public key: %u\n", kp->public_key);
    printf("Private key: %u\n", kp->private_key);

    encrypt(
            data,
            encrypted,
            kp
            );
    decrypt(
            encrypted,
            decrypted,
            kp
            );

    printf("Original: '%s'\n", (char*)data->message);
    printf("Encrypted: '%s'\n", (char*)encrypted->message);
    printf("Decrypted: '%s'\n", (char*)decrypted->message);

    printf("LANG_LOCAL: %s\n", LANG_LOCAL);
    printf("LOAD_AS %d\n", LOAD_AS);


    free(pmsg);
    free_key_pair(kp);
    free_message(data);
    free_message(encrypted);
    free_message(decrypted);
    return 0;
}
