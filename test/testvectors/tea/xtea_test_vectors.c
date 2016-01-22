#include <stdint.h>

// code taken from https://en.wikipedia.org/wiki/XTEA

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void main(int argc, char** argv) {
	uint32_t i;
	uint32_t s0, s1;
	uint32_t k[] = {0, 0, 0, 0};
	uint32_t v[] = {0, 0};
	unsigned int rounds = 32;
	printf("i #                k               #       pt       #        ct      \n");
	for(i = 0; i < 100; i++) {
		printf("%02X %08X%08X%08X%08X ", i, k[0], k[1], k[2], k[3]);
		printf("%08X%08X ", v[0], v[1]);
		encipher(rounds, v, k);
		
		s0 = v[0];
		s1 = v[1];
		printf("%08X%08X\n", v[0], v[1]);
		decipher(rounds, v, k);
		
		k[2 + (i%2)] ^= s0;
		k[1 - (i%2)] ^= s1;
		v[0] = s0;
		v[1] = s1;
	}
}