#ifndef _LIBRSA_H
#define _LIBRSA_H
#include <stdint.h>
#include <stdlib.h>

typedef uint16_t __key_t_;

typedef struct key_pairs {
    __key_t_ public_key;
    __key_t_ private_key;
    uint16_t base;
} key_pair;

const uint8_t FIRST_FOUR_BITS_MASK = 0x0F;


int is_prime(uint8_t number);
void get_two_different_prime_numbers(uint8_t *buf);
void get_augment(uint8_t first_prime, uint8_t second_prime, key_pair *kp);
uint16_t get_euler_number(uint8_t first_prime, uint8_t second_prime);
int gcd(uint16_t first_num, uint16_t second_num);
void generate_key_pair(key_pair *kp);
void multiply(uint8_t multiplier, uint8_t *result, uint32_t *length);
uint64_t pow_(uint64_t number, uint64_t degree);
void encrypt(
        void *original_raw_data,
        void *buffer,
        uint32_t length,
        key_pair *kp
        );
void decrypt(
        void *original_encrypted_data,
        void *buffer,
        size_t size_of_raw_data,
        uint16_t chunks,
        key_pair *kp
        );
#endif
