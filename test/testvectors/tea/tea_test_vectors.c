#include <stdint.h>

// code taken from https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void main(int argc, char** argv) {
	uint32_t i;
	uint32_t s0, s1;
	uint32_t k[] = {0, 0, 0, 0};
	uint32_t v[] = {0, 0};
	printf("i #                k               #       pt       #        ct      \n");
	for(i = 0; i < 100; i++) {
		printf("%02X %08X%08X%08X%08X ", i, k[0], k[1], k[2], k[3]);
		printf("%08X%08X ", v[0], v[1]);
		encrypt(v, k);
		
		s0 = v[0];
		s1 = v[1];
		printf("%08X%08X\n", v[0], v[1]);
		decrypt(v, k);
		
		k[2 + (i%2)] ^= s0;
		k[1 - (i%2)] ^= s1;
		v[0] = s0;
		v[1] = s1;
	}
}