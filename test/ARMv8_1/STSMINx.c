#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define FIRST_VAL 42
#define SECOND_VAL 41

void test_standard() {
    uint64_t *val_64 = (uint64_t *)malloc(sizeof(uint64_t));
    *val_64 = FIRST_VAL;
    asm (
        "mov x3, %0\n\t"
        "mov x4, %1\n\t"
        "stsmin x3,[x4]\n\t"
        :: "I"(SECOND_VAL), "r"(val_64)
        );
    assert(*val_64 == SECOND_VAL);

    asm (
        "mov x3, %0\n\t"
        "mov x4, %1\n\t"
        "stsminl x3,[x4]\n\t"
        :: "I"(SECOND_VAL-1), "r"(val_64)
        );
    assert(*val_64 == SECOND_VAL-1);

    free(val_64);
}

void test_byte() {
    uint8_t *val_8 = (uint8_t *)malloc(sizeof(uint8_t));
    *val_8 = FIRST_VAL;
    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "stsminb w3,[x4]\n\t"
        :: "I"(SECOND_VAL), "r"(val_8)
        );
    assert(*val_8 == SECOND_VAL);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "stsminlb w3,[x4]\n\t"
        :: "I"(SECOND_VAL-1), "r"(val_8)
        );
    assert(*val_8 == SECOND_VAL-1);

    free(val_8);
}

void test_halfword() {
    uint32_t *val_32 = (uint32_t *)malloc(sizeof(uint32_t));
    *val_32 = FIRST_VAL;
    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "stsminh w3,[x4]\n\t"
        :: "I"(SECOND_VAL), "r"(val_32)
        );
    assert(*val_32 == SECOND_VAL);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "stsminlh w3,[x4]\n\t"
        :: "I"(SECOND_VAL-1), "r"(val_32)
        );
    assert(*val_32 == SECOND_VAL-1);

    free(val_32);
}

int main() {
    test_standard();
    test_byte();
    test_halfword();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}
