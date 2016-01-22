#include <stdint.h>

// code taken from https://en.wikipedia.org/wiki/XXTEA

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
  
  void btea(uint32_t *v, int n, uint32_t const key[4]) {
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1) {          /* Coding Part */
      rounds = 6 + 52/n;
      sum = 0;
      z = v[n-1];
      do {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p=0; p<n-1; p++) {
          y = v[p+1]; 
          z = v[p] += MX;
        }
        y = v[0];
        z = v[n-1] += MX;
      } while (--rounds);
    } else if (n < -1) {  /* Decoding Part */
      n = -n;
      rounds = 6 + 52/n;
      sum = rounds*DELTA;
      y = v[0];
      do {
        e = (sum >> 2) & 3;
        for (p=n-1; p>0; p--) {
          z = v[p-1];
          y = v[p] -= MX;
        }
        z = v[n-1];
        y = v[0] -= MX;
        sum -= DELTA;
      } while (--rounds);
    }
  }

void main(int argc, char** argv) {
	uint32_t i;
	uint32_t s0, s1, s2, s3;
	uint32_t k[] = {0, 0, 0, 0};
	uint32_t v[] = {0, 0};
	uint32_t v3[] = {0, 0, 0};
	uint32_t v4[] = {0, 0, 0, 0};
	int n = 2;
	
	printf("i #n#                k               #       pt       #        ct      \n");
	for(i = 0; i < 100; i++) {
		printf("%02X %d %08X%08X%08X%08X ", i, n, k[0], k[1], k[2], k[3]);
		printf("%08X%08X ", v[0], v[1]);
		btea(v, n, k);
		
		s0 = v[0];
		s1 = v[1];
		printf("%08X%08X\n", v[0], v[1]);
		btea(v, -n, k);
		
		k[2 + (i%2)] ^= s0;
		k[1 - (i%2)] ^= s1;
		v[0] = s0;
		v[1] = s1;
	}
	
	k[0] = k[1] = k[2]= k[3] = 0;
	printf("i #n#                k               #           pt           #            ct          \n");
	n = 3;
	for(i = 0; i < 100; i++) {
		printf("%02X %d %08X%08X%08X%08X ", i, n, k[0], k[1], k[2], k[3]);
		printf("%08X%08X%08X ", v3[0], v3[1], v3[2]);
		btea(v3, n, k);
		
		s0 = v3[0];
		s1 = v3[1];
		s2 = v3[2];
		printf("%08X%08X%08X\n", v3[0], v3[1], v3[2]);
		btea(v3, -n, k);
		
		k[2 + (i%2)] ^= s0;
		k[1 - (i%2)] ^= s1;
		k[3] ^= s2;
		v3[0] = s0;
		v3[1] = s1;
		v3[2] = s2;
	}
	
	k[0] = k[1] = k[2]= k[3] = 0;
	printf("i #n#                k               #               pt               #                ct              \n");
	n = 4;
	for(i = 0; i < 100; i++) {
		printf("%02X %d %08X%08X%08X%08X ", i, n, k[0], k[1], k[2], k[3]);
		printf("%08X%08X%08X%08X ", v4[0], v4[1], v4[2], v4[3]);
		btea(v4, n, k);
		
		s0 = v4[0];
		s1 = v4[1];
		s2 = v4[2];
		s3 = v4[3];
		printf("%08X%08X%08X%08X\n", v4[0], v4[1], v4[2], v4[3]);
		btea(v4, -n, k);
		
		k[2 + (i%2)] ^= s0;
		k[1 - (i%2)] ^= s1;
		k[3] ^= s2;
		k[0] ^= s3;
		v4[0] = s0;
		v4[1] = s1;
		v4[2] = s2;
		v4[3] = s3;
	}
}