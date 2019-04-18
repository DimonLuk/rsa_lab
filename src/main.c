#include "../lib/include/rsa.h"
#include "include/src.h"
#include <stdio.h>
#include <string.h>


int main(int argc, char *argv[]) {
    key_pair *kp = key_pair_alloc();
    printf("%s", INVITE);
    char *msg;
    scanf("%m[^\n]s", &msg);

    message *data = create_message((void*)msg, strlen(msg));
    message *encrypted = message_alloc();
    message *decrypted = message_alloc();
    generate_key_pair(kp);

    printf("%s%u\n", BASE, kp->base);
    printf("%s%u\n", PUBLIC_KEY, kp->public_key);
    printf("%s%u\n", PRIVATE_KEY, kp->private_key);

    encrypt(data, encrypted, kp);
    decrypt(encrypted, decrypted, kp);

    printf("%s'%s'\n", ORIGINAL, (char*)data->message);
    printf("%s'%s'\n", ENCRYPTED, (char*)encrypted->message);
    printf("%s'%s'\n", DECRYPTED, (char*)decrypted->message);


    free(msg);
    free_key_pair(kp);
    free_message(data);
    free_message(encrypted);
    free_message(decrypted);
    return 0;
}
