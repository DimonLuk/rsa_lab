#include "./include/rsa.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/random.h>


extern inline int is_prime(uint8_t number) {
    int flag = 1;
    for(int i=2; i < number/2; i++) {
        if(number % i == 0) {
            flag = 0;
            return flag;
        }
    }
    return flag;
}


void get_two_differenet_prime_numbers(uint8_t *buf) {
    uint8_t first_prime = 0;
    uint8_t second_prime = 0;

    while(1) {
        getentropy(&first_prime, sizeof(uint8_t));
        first_prime &= FIRST_FOUR_BITS_MASK;
        if(first_prime > 1 && is_prime(first_prime)) break;
    }
    buf[0] = first_prime;

    while(1) {
        getentropy(&second_prime, sizeof(uint8_t));
        second_prime &= FIRST_FOUR_BITS_MASK;
        if(second_prime > 1 && is_prime(second_prime) && second_prime != first_prime) break;
    }
    buf[1] = second_prime;
}


extern inline uint16_t get_augment(uint8_t first_prime, uint8_t second_prime) {
    uint8_t fp = (uint16_t)first_prime;
    uint8_t sp = (uint16_t)second_prime;
    return fp * sp;
}


extern inline uint16_t get_euler_number(uint8_t first_prime, uint8_t second_prime) {
    uint16_t fp = (uint16_t)(first_prime - 1);
    uint16_t sp = (uint16_t)(second_prime - 1);
    return fp * sp;
}


extern inline int gcd(uint16_t first_num, uint16_t second_num) {
    if(second_num == 0) return first_num;
    return gcd(second_num, first_num % second_num);
}


void generate_key_pair(key_pair *kp) {
}


int main() {
    uint8_t* numbers = (uint8_t*)malloc(2*sizeof(uint8_t));
    get_two_differenet_prime_numbers(numbers);
    printf("Number 1: %u\n", numbers[0]);
    printf("Number 2: %u\n", numbers[1]);

    uint16_t augment = get_augment(numbers[0], numbers[1]);
    printf("Augment: %u\n", augment);

    uint8_t euler_number = get_euler_number(numbers[0], numbers[1]);
    printf("Euler number: %u\n", euler_number);

    free(numbers);
    return 0;
}
