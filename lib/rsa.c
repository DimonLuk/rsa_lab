#include "./include/rsa.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <math.h>


int is_prime(uint8_t number) {
    int flag = 1;
    for(int i=2; i < number; i++) {
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
        if(first_prime > 3 && is_prime(first_prime)) break;
    }
    buf[0] = first_prime;

    while(1) {
        getentropy(&second_prime, sizeof(uint8_t));
        second_prime &= FIRST_FOUR_BITS_MASK;
        if(second_prime > 5 && is_prime(second_prime) && second_prime != first_prime) break;
    }
    buf[1] = second_prime;
}


void get_augment(uint8_t first_prime, uint8_t second_prime, key_pair *kp) {
    uint8_t fp = (uint16_t)first_prime;
    uint8_t sp = (uint16_t)second_prime;
    kp->base = fp * sp;
}


uint16_t get_euler_number(uint8_t first_prime, uint8_t second_prime) {
    uint16_t fp = (uint16_t)(first_prime - 1);
    uint16_t sp = (uint16_t)(second_prime - 1);
    return fp * sp;
}


int gcd(uint16_t first_num, uint16_t second_num) {
    if(second_num == 0) return first_num;
    return gcd(second_num, first_num % second_num);
}


void generate_key_pair(key_pair *kp) {
    uint8_t* numbers = (uint8_t*)malloc(2*sizeof(uint8_t));
    get_two_differenet_prime_numbers(numbers);
    get_augment(numbers[0], numbers[1], kp);
    uint16_t euler_number = get_euler_number(numbers[0], numbers[1]);
    kp->public_key = 1;
    do {
        kp->public_key += 1;
        while(kp->public_key < euler_number) {
            if(gcd(euler_number, kp->public_key) == 1) break;
            kp->public_key += 1;
        }
        if(kp->public_key == euler_number) {
            get_two_differenet_prime_numbers(numbers);
            get_augment(numbers[0], numbers[1], kp);
            euler_number = get_euler_number(numbers[0], numbers[1]);
            kp->public_key = 1;
            kp->private_key = 0;
            continue;
        }
        kp->private_key = (__key_t_)((1 + euler_number) / kp->public_key);
        if(kp->private_key == 1) continue;
    } while((kp->public_key * kp->private_key) % euler_number != 1);
    free(numbers);
}





int main() {
    key_pair *kp = (key_pair*)malloc(sizeof(key_pair));
    char *data = "Test";
    char *encrypted = (char*)malloc(2*strlen(data));
    char *decrypted = (char*)malloc(strlen(data));

    generate_key_pair(kp);

    printf("Public key: %u\n", kp->public_key);
    printf("Private key: %u\n", kp->private_key);


    printf("Original: '%s'\n", data);
    printf("Encrypted: '%s'\n", encrypted);
    printf("Decrypted: '%s'\n", decrypted);

    free(kp);
    free(encrypted);
    free(decrypted);
    return 0;
}
