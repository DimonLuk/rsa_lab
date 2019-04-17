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
        if(kp->public_key >= euler_number || kp->public_key <= 3000 || safety_counter >= 1000 || kp->base < 1000000000L) {
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
    } while((kp->public_key * kp->private_key) % euler_number != 1 || kp->public_key <= kp->private_key);
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
        message *original_raw_data,
        message *buffer,
        key_pair *kp
        ) {
    __key_parent_t_ *origin = (__key_parent_t_*)(original_raw_data->message);
    __key_t_ *buf = (__key_t_*)malloc(2 * original_raw_data->size);
    buffer->message = (void*)buf;
    buffer->is_byte_added = original_raw_data->is_byte_added;
    buffer->size = 2 * original_raw_data->size;
    uint64_t public_key = kp->public_key;
    uint64_t base = kp->base;
    size_t amount_of_iterations = original_raw_data->size / sizeof(__key_parent_t_);
    for(uint32_t i = 0; i < amount_of_iterations; i++) {
        __key_t_ data = origin[i];
        data = pow_(data, public_key, base);
        buf[i] = data;
    }
}


void decrypt(
        message *original_encrypted_data,
        message *buffer,
        key_pair *kp
        ) {
    __key_t_ *origin = (__key_t_*)(original_encrypted_data->message);
    __key_parent_t_ *buf = (__key_parent_t_*)malloc(original_encrypted_data->size / 2);
    buffer->message = (void*)buf;
    buffer->is_byte_added = original_encrypted_data->is_byte_added;
    buffer->size = original_encrypted_data->size / 2;
    uint64_t private_key = kp->private_key;
    uint64_t base = kp->base;
    size_t amount_of_iterations = original_encrypted_data->size / sizeof(__key_t_);
    for(uint32_t i = 0; i < amount_of_iterations; i++) {
        uint64_t data = origin[i];
        data = pow_(data, private_key, base);
        buf[i] = data;
    }
    if(buffer->is_byte_added) {
        buffer->size--;
        buffer->message = (void*)realloc((void*)buf, buffer->size);
    }
}


message* create_message(void *msg, size_t msg_size) {
    message* result = (message*)malloc(sizeof(message));
    if(msg_size % 2 != 0) {
        result->is_byte_added = 1;
        result->message = (void*)realloc(msg, msg_size + 1);
        ((uint8_t*)(result->message))[msg_size] = 1;
        result->size = msg_size + 1;
    } else {
        result->message = msg;
        result->is_byte_added = 0;
        result->size = msg_size;
    }
    return result;
}


int main() {
    key_pair *kp = (key_pair*)malloc(sizeof(key_pair));
    char *msg = "Привет мир!abcccc";
    char *pmsg = (char*)malloc(strlen(msg));
    strcpy(pmsg, msg);
    message *data = create_message((void*)pmsg, strlen(msg));
    message *encrypted = (message*)malloc(sizeof(message));
    message *decrypted = (message*)malloc(sizeof(message));
    generate_key_pair(kp);

    printf("Base: %u\n", kp->base);
    printf("Public key: %u\n", kp->public_key);
    printf("Private key: %u\n", kp->private_key);

    encrypt(
            data,
            encrypted,
            kp
            );
    decrypt(
            encrypted,
            decrypted,
            kp
            );

    printf("Original: '%s'\n", (char*)data->message);
    printf("Encrypted: '%s'\n", (char*)encrypted->message);
    printf("Decrypted: '%s'\n", (char*)decrypted->message);


    free(kp);
    free(encrypted);
    free(decrypted);
    return 0;
}
