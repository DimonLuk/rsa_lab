#ifndef _LIBRSA_H // Not to include this header twice
#define _LIBRSA_H
#include <stdint.h>
#include <stdlib.h>

typedef uint16_t __key_parent_t_; // Defin unsigned 16 bit integer as __key_parent_t_
typedef uint32_t __key_t_;

typedef struct key_pairs { // Define structure as type which stores keys
    __key_t_ public_key;
    __key_t_ private_key;
    __key_t_ base;
} key_pair;


typedef struct messages {
    size_t size;
    void *message;
    uint8_t is_byte_added: 1; // size of this var is 1 bit
} message;

void generate_key_pair(key_pair *kp);

void encrypt(
        message *original_raw_data,
        message *buffer,
        key_pair *kp
        );

void decrypt(
        message *original_encrypted_data,
        message *buffer,
        key_pair *kp
        );

key_pair* key_pair_alloc(); // create empty key_pait structure

message* message_alloc();

message* create_message(void *msg, size_t msg_size);

void free_message(message *msg); // free memory when it's not required

void free_key_pair(key_pair* kp);

#endif
