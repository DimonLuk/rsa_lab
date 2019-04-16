#ifndef _LIBRSA_H
#define _LIBRSA_H
#include <stdint.h>
#include <stdlib.h>

typedef uint16_t __key_parent_t_;
typedef uint32_t __key_t_;

typedef struct key_pairs {
    __key_t_ public_key;
    __key_t_ private_key;
    __key_t_ base;
} key_pair;


const volatile uint32_t LENGTH_MULTIPLIER = 2;


int is_prime(__key_parent_t_ number);
void get_two_different_prime_numbers(__key_parent_t_ *buf);
void get_augment(__key_parent_t_ first_prime, __key_parent_t_ second_prime, key_pair *kp);
__key_t_ get_euler_number(__key_parent_t_ first_prime, __key_parent_t_ second_prime);
int gcd(__key_t_ first_num, __key_t_ second_num);
void generate_key_pair(key_pair *kp);
void multiply(__key_parent_t_ multiplier, __key_parent_t_ *result, uint32_t *length);
uint64_t pow_(uint64_t number, uint64_t degree, uint64_t mod);
void encrypt(
        void *original_raw_data,
        void *buffer,
        uint32_t length,
        key_pair *kp
        );
void decrypt(
        void *original_encrypted_data,
        void *buffer,
        uint32_t number_of_bytes,
        key_pair *kp
        );
#endif
