#ifndef _LIBRSA_PRIVATE_H_
#define _LIBRSA_PRIVATE_H_
#include "rsa.h"
#include <stdint.h>
#include <stdlib.h>

int is_prime(__key_parent_t_ number);
void get_two_different_prime_numbers(__key_parent_t_ *buf);
void get_augment(__key_parent_t_ first_prime, __key_parent_t_ second_prime, key_pair *kp); // Create base
__key_t_ get_euler_number(__key_parent_t_ first_prime, __key_parent_t_ second_prime);
int gcd(__key_t_ first_num, __key_t_ second_num);
uint64_t pow_(uint64_t number, uint64_t degree, uint64_t mod);
#endif
