#ifndef _LIBRSA_H
#define _LIBRSA_H

typedef unsigned int public_key_t;
typedef unsigned int private_key_t;

inline unsigned int* get_two_different_prime_numbers();
inline unsigned int get_euler_number(unsigned int first_prime, unsigned int second_prime);
inline public_key_t get_public_key(unsigned int prime);
inline private_key_t get_private_key(unsigned int prime, public_key_t public_key);
char* encrypt(char* message, public_key_t public_key);
char* decrypt(char* encrypted_message, private_key_t private_key);
#endif
