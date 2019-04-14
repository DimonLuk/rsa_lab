#ifndef _LIBRSA_H
#define _LIBRSA_H
#include <stdint.h>

typedef uint16_t __key_t__;

struct keys {
    __key_t__ public_key;
    __key_t__ private_key;
};
typedef struct keys key_pair;

const uint8_t FIRST_FOUR_BITS_MASK = 0x0F;


inline int is_prime(uint8_t number);
void get_two_different_prime_numbers(uint8_t *buf);
inline uint16_t get_augment(uint8_t first_prime, uint8_t second_prime);
inline uint16_t get_euler_number(uint8_t first_prime, uint8_t second_prime);
inline int gcd(uint16_t first_num, uint16_t second_num);
inline void generate_key_pair(key_pair *kp);
char* encrypt(char* message, key_pair *kp);
char* decrypt(char* encrypted_message, key_pair* kp);
#endif
