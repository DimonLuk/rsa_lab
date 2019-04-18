// I was doing this lab too fast so no error checks
#include "include/src.h"
#include <stdio.h>
#include <string.h>


#if LOAD_AS == LIBRARY
void demonstrate(char *msg) {
    printf("%s\n", MODE_STYLE_L);
    key_pair *kp = key_pair_alloc();
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
}
#endif // LOAD_AS == LIBRARY

#if LOAD_AS == MODULE
void demonstrate(char *msg) {
    printf("%s\n", MODE_STYLE_M);
    void *handle = dlopen("../lib/librsa.so", RTLD_LAZY);
    key_pair* (*m_key_pair_alloc)(void) = dlsym(handle, "key_pair_alloc");
    message* (*m_create_message)(void*, size_t) = dlsym(handle, "create_message");
    message* (*m_message_alloc)(void) = dlsym(handle, "message_alloc");
    void (*m_generate_key_pair)(key_pair*) = dlsym(handle, "generate_key_pair");
    void (*m_encrypt)(message*, message*, key_pair*) = dlsym(handle, "encrypt");
    void (*m_decrypt)(message*, message*, key_pair*) = dlsym(handle, "decrypt");
    void (*m_free_key_pair)(key_pair*) = dlsym(handle, "free_key_pair");
    void (*m_free_message)(message*) = dlsym(handle, "free_message");


    key_pair *kp = (*m_key_pair_alloc)();
    message *data = (*m_create_message)((void*)msg, strlen(msg));
    message *encrypted = (*m_message_alloc)();
    message *decrypted = (*m_message_alloc)();
    (*m_generate_key_pair)(kp);

    printf("%s%u\n", BASE, kp->base);
    printf("%s%u\n", PUBLIC_KEY, kp->public_key);
    printf("%s%u\n", PRIVATE_KEY, kp->private_key);

    (*m_encrypt)(data, encrypted, kp);
    (*m_decrypt)(encrypted, decrypted, kp);

    printf("%s'%s'\n", ORIGINAL, (char*)data->message);
    printf("%s'%s'\n", ENCRYPTED, (char*)encrypted->message);
    printf("%s'%s'\n", DECRYPTED, (char*)decrypted->message);


    free(msg);
    (*m_free_key_pair)(kp);
    (*m_free_message)(data);
    (*m_free_message)(encrypted);
    (*m_free_message)(decrypted);
}
#endif // LOAD_AS == MODULE


int main(int argc, char *argv[]) {
    printf("%s", INVITE);
    char *msg;
    scanf("%m[^\n]s", &msg);
    demonstrate(msg);
    return 0;
}
