#include "./include/rsa.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>


int is_prime(__key_parent_t_ number) {
    int flag = 1;
    for(int i=2; i < number; i++) {
        if(number % i == 0) {
            flag = 0;
            return flag;
        }
    }
    return flag;
}


void get_two_differenet_prime_numbers(__key_parent_t_ *buf) {
    __key_parent_t_ first_prime = 0;
    __key_parent_t_ second_prime = 0;

    while(1) {
        getentropy(&first_prime, sizeof(__key_parent_t_));
        if(first_prime > 3 && is_prime(first_prime)) break;
    }
    buf[0] = first_prime;

    while(1) {
        getentropy(&second_prime, sizeof(__key_parent_t_));
        if(second_prime > 5 && is_prime(second_prime) && second_prime != first_prime) break;
    }
    buf[1] = second_prime;
}


void get_augment(__key_parent_t_ first_prime, __key_parent_t_ second_prime, key_pair *kp) {
    __key_parent_t_ fp = (__key_t_)first_prime;
    __key_parent_t_ sp = (__key_t_)second_prime;
    kp->base = fp * sp;
}


__key_t_ get_euler_number(__key_parent_t_ first_prime, __key_parent_t_ second_prime) {
    __key_t_ fp = (__key_t_)(first_prime - 1);
    __key_t_ sp = (__key_t_)(second_prime - 1);
    return fp * sp;
}


int gcd(__key_t_ first_num, __key_t_ second_num) {
    if(second_num == 0) return first_num;
    return gcd(second_num, first_num % second_num);
}


void generate_key_pair(key_pair *kp) {
    __key_parent_t_* numbers = (__key_parent_t_*)malloc(2*sizeof(__key_parent_t_));
    get_two_differenet_prime_numbers(numbers);
    get_augment(numbers[0], numbers[1], kp);
    __key_t_ euler_number = get_euler_number(numbers[0], numbers[1]);
    uint32_t safety_counter = 0;
    do {
        getentropy(&(kp->public_key), sizeof(__key_t_)/2);
        while(kp->public_key < euler_number && safety_counter <= 100000000) {
            if(gcd(euler_number, kp->public_key) == 1) break;
            kp->public_key += 1;
            safety_counter++;
        }
        if(kp->public_key >= euler_number || kp->public_key == 1 || safety_counter >= 1000) {
            get_two_differenet_prime_numbers(numbers);
            get_augment(numbers[0], numbers[1], kp);
            euler_number = get_euler_number(numbers[0], numbers[1]);
            kp->public_key = 0;
            kp->private_key = 0;
            safety_counter = 0;
            continue;
        }
        kp->private_key = (__key_t_)((1 + euler_number) / kp->public_key);
        if(kp->private_key == kp->public_key || kp->private_key == 1) {
            kp->private_key = 0;
            safety_counter = 0;
        }
    } while((kp->public_key * kp->private_key) % euler_number != 1);
    free(numbers);
}


uint64_t pow_(uint64_t number, uint64_t degree, uint64_t mod) {
    uint64_t result = 1;
    while(degree > 0) {
        if(degree % 2 == 1) {
            result = (result * number) % mod;
        }
        degree /= 2;
        number = (number * number) % mod;
    }
    return result;
}


void encrypt(
        void *original_raw_data,
        void *buffer,
        uint32_t number_of_bytes,
        key_pair *kp
        ) {
    __key_parent_t_ *origin = (__key_parent_t_*)original_raw_data;
    __key_t_ *buf = (__key_t_*)buffer;
    uint64_t public_key = kp->public_key;
    uint64_t base = kp->base;
    for(uint32_t i = 0; i < number_of_bytes; i++) {
        uint64_t data = origin[i];
        data = pow_(data, public_key, base);
        buf[i] = data;
    }
}


void decrypt(
        void *original_encrypted_data,
        void *buffer,
        uint32_t number_of_bytes,
        key_pair *kp
        ) {
    __key_t_ *origin = (__key_t_*)original_encrypted_data;
    __key_parent_t_ *buf = (__key_parent_t_*)buffer;
    number_of_bytes /= 2;
    uint64_t private_key = kp->private_key;
    uint64_t base = kp->base;
    for(uint32_t i = 0; i < number_of_bytes; i++) {
        uint64_t data = origin[i];
        data = pow_(data, private_key, base);
        buf[i] = data;
    }
}


int main() {
    key_pair *kp = (key_pair*)malloc(sizeof(key_pair));
    char *data = "Test";
    char *encrypted = (char*)malloc(LENGTH_MULTIPLIER*strlen(data));
    char *decrypted = (char*)malloc(strlen(data));

    generate_key_pair(kp);

    printf("Base: %u\n", kp->base);
    printf("Public key: %u\n", kp->public_key);
    printf("Private key: %u\n", kp->private_key);

    encrypt(
            (void*)data,
            (void*)encrypted,
            strlen(data),
            kp
            );
    decrypt(
            (void*)encrypted,
            (void*)decrypted,
            strlen(encrypted),
            kp
            );

    printf("Original: '%s'\n", data);
    printf("Encrypted: '%s'\n", encrypted);
    printf("Decrypted: '%s'\n", decrypted);


    free(kp);
    free(encrypted);
    free(decrypted);
    return 0;
}
