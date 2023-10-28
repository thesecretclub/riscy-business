#include <stdint.h>

char myData[] = "Hello, World!";

__attribute__((noinline)) void lfsr16_obfuscate(char* s, int length, unsigned short seed)
{
    int i, lsb;

    for (i = 0; i < length; i++)
    {
        s[i] ^= seed & 0x00ff;
        lsb = seed & 1;
        seed >>= 1;
        if (lsb)
            seed ^= 0xB400u;
    }
}

int bb();
int bb2();

uint64_t test_switch(uint64_t n)
{
    switch(n)
    {
    case 1:
        return 1234;
    case 2:
        return 4567;
    case 3:
        return 8901;
    case 4:
        return n + n;
    case 5:
        return n * 55;
    case 6:
        return n + 68;
    case 7:
        return 8473;
    case 8:
        return 8473 ^ n;
    case 9:
        return 6748 & n;
    case 10:
        return 948;
    case 11:
        return 4827;
    default:
        return n & 0x1337;
    }
}

__attribute((noinline)) int main()
{
    int x = bb() + bb2();
    lfsr16_obfuscate(myData, sizeof(myData) - 1, 1337 + x);
    return test_switch(x) + 42;
}

void* functions[] = {
    &lfsr16_obfuscate,
    &main,
};

/*void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}*/
