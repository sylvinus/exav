/* Bit tricks on 32-bit words. CC0-1.0, exav project. */
#include <stdint.h>
#include <stdio.h>

/* The number of set bits, by the parallel sum. */
static unsigned popcount32(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    x = (x + (x >> 4)) & 0x0f0f0f0fu;
    return (x * 0x01010101u) >> 24;
}

/* The index of the highest set bit, or -1 for zero. */
static int high_bit(uint32_t x) {
    int n = -1;
    while (x) {
        n++;
        x >>= 1;
    }
    return n;
}

/* The next power of two that is not below x. */
static uint32_t next_pow2(uint32_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

/* The bits of x in reverse order. */
static uint32_t reverse32(uint32_t x) {
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
    x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
    return (x >> 16) | (x << 16);
}

int main(void) {
    const uint32_t samples[] = {0u, 1u, 255u, 1000u, 0xdeadbeefu};
    for (size_t i = 0; i < sizeof samples / sizeof samples[0]; i++) {
        uint32_t v = samples[i];
        printf("%10u: bits %2u, high %2d, pow2 %10u, reversed %08x\n", v, popcount32(v), high_bit(v), next_pow2(v), reverse32(v));
    }
    return 0;
}
