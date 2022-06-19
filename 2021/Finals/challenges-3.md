# HACK-A-SAT 2021: Challenge 3

## User Segment Client

We were given a client program (binary) along with an RSA key pair to communicate with the satellites' radio. The client communicates with a server and an RSA signature of the message is required. The usage is as follows:
```
Usage: User Segment Client [options]

Optional arguments:
-h --help               shows help message and exits [default: false]
-v --version            prints version information and exits [default: false]
-i --id                 Satellite ID [required]
-k --key                Attribution key [required]
-m --message            Hex message (to be converted to bytes) to send to user segment. Must be EVEN-length string. Ex: -m 414141 would be converted to AAA
-f --key-file           Path to private key file. [default: "id_rsa"]
-p --port               Port used to connect to the user segment server [default: 31337]
-a --address            Address used to connect to the user segment server [default: "127.0.0.1"]
-d --data-file          Path to data file. Contents will be used to send to user segment. [default: ""]
-s --danx-service       Send message to the DANX service instead of the Comm Payload Message Server [default: false]
```
With this client, it is possible to send messages to a team satellite provided we can sign messages as said team.

## Reverse engineering the client

### Public keys for all teams

It is possible to retrieve all RSA public keys from the server. The function \linebreak `UserSegmentPacket::askForPubKey` is present but never called. Reversing it shows that it sends a message with the satellite ID set to `0xDEB06FFFFFFFFFFF` (decimal: 16046448617623388159) and a content of length 1 which is likely the team number:

![Function to get the public keys for all teams](images/getpubkey.png)

The following command can be used to retrieve the public key for a given team:

```
./client -k 5647008472405673096 -f ../keys/team_7_rsa_priv.pem -m 01 -p 31337 -a 10.0.0.101 -i 16046448617623388159
```

Using `strace`, we obtain the following:
```
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x0a\x0b\x5d\x60\x8a\x07\xc7\x02\x69\x0f\x9e\xff\xcb\x34\xb1\xec\x12\x60\x6a\x61\x18\x4c\x94\x84\xc1\x67\xdf\x0b\x23\x45\x49\x49\x62\x3d\x0b\x1a\x50\xdf\x16\x19\x6a\x6d\x3d\xe1\xbb\xb9\x27\xf3\x22\x8a\x99\x8c\xec\x0b\xad\xcb\x5e\x3b\x20\xb6\x36\x28\xf3\x08\x7c\xcf\x5a\x6a\xc1\x11\x13\x7f\x95\x46\x7c\x0e\x0e\xf0\x9d\x68\xb0\xa8\x2c\xa2\x10\x4c\x95\xe1\x89\xa5\x27\x5f\x7d\x4a\x6c\x7b\x9a\x7d\xb4\x7d\xf8\x9c\x10\x89\x2b\x3b\x77\x98\xc7\x4c\x1f\x44\x40\xef\xa9\x4a\xb0\xd9\x09\x88\x9d\x4f\xf1\x7d\xd2\x89\xa2\x2a\x1e\x36\xc0\xd5\x2b\x06\xa3\x81\x6a\x47\xe8\x11\xb0\x29\xe8\xc9\xd1\x3d\x01\x97\x5c\xa7\xe3\xc5\x10\x4d\xab\x65\x4d\x32\x31\x52\x2f\xbb\x88\x71\xcf\x18\x3d\xea\x9c\xf0\x2f\xf3\x02\x03\x01\x00\x01", 512) = 205
```
```
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x0d\x79\x49\x9d\x6c\x57\xca\xe0\x27\x96\x5b\x5c\xc6\x61\xf2\x1b\x89\xb6\x07\x32\xf2\xc5\x21\x6e\x82\x08\xb4\x92\xa0\xa6\xa7\x06\x18\xff\x86\x65\x84\x97\x69\x56\x32\x7e\x16\x14\xfb\x55\x49\xc2\x1a\x20\x4f\x23\x41\xc5\x2f\x45\x8f\xd8\x1e\xd0\x13\xeb\x6e\xb1\x07\x91\x7b\xca\xb9\x1f\x6a\x66\x50\xc8\x80\xae\xa9\xcc\x3a\x31\x82\x2d\x04\x9f\xf8\x38\x10\xea\x95\x55\x49\x90\x58\xc6\xcf\x83\x3d\x93\x09\xbf\x2a\x20\xbf\x05\xa7\x7f\xf3\xab\xf8\xad\xfe\xb0\x27\x9e\x80\x03\x29\x7a\xfa\xe7\x44\xd6\xaa\x3d\xcf\xfb\x3b\xc8\xfd\xa3\xd9\xa4\xc6\xa0\x78\x64\x25\xb2\x96\x0f\xaf\xd8\x84\xab\x5a\x30\xa0\x54\x4c\x07\x71\x44\x3c\xda\xe1\xf8\x92\x75\x88\x93\xb5\x96\x1b\x9b\xb1\x98\xe8\x49\xcc\x38\xc2\xcb\x02\x03\x01\x00\x01", 512) = 205
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x0b\x62\xfb\xdc\x4c\x41\xd2\xe9\xeb\x69\x9c\xcb\x65\xce\xe1\x11\x1c\x68\xe7\xbd\x26\x72\x90\x44\xe5\x95\xc5\xc7\xcf\x2f\xe8\xd7\xc2\x79\xb8\x98\xa0\x13\x90\x1d\x50\x46\x7b\xef\xc5\x34\x13\x26\xf4\x2e\x70\xed\x4d\x4e\xa3\xe0\xd9\xc9\x45\x11\x52\x91\xd7\x99\x59\x9d\x57\x46\x4a\x7e\x09\x77\x2f\x96\x25\xa6\xf6\x17\x48\xa9\xe7\xa2\x0c\x22\xd9\x6b\x17\x2a\x2a\x2c\x26\x01\x21\xe2\xf0\xad\x96\x72\xe5\xb5\xd4\x74\x42\x45\x52\x26\x96\x12\x83\x72\xf7\xa9\x95\xc4\x46\xea\x03\xec\xe5\x92\xbc\x0e\x42\x0f\xb5\xcb\xe8\xe5\x4d\x4b\x21\x06\xac\x19\x0c\x35\x7c\xdf\xdf\x60\x43\x7a\xa3\x88\xe0\x25\x8d\x0a\xf6\x82\xc6\x2b\x59\xf4\x5c\x0c\xda\xf7\x5d\x76\xd8\x08\x6f\x4a\x36\xab\x38\x99\xdd\xf8\xb3\xc3\x02\x03\x01\x00\x01", 512) = 205
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x0b\x94\xc7\x83\x59\x28\xce\x25\x4f\x5c\xde\x35\x9f\x6e\x71\xda\xdd\x7f\xad\x8f\x42\x87\x17\xee\x42\xb0\x25\xd7\x63\x69\x32\x7f\x3e\x3f\xae\x37\x47\x82\x31\x30\x6c\x0e\x05\xfa\x63\x5a\xb7\x5a\xed\x85\x1e\xa5\xc0\xa2\x68\x8c\xad\x62\x4c\x63\x23\xf6\xe7\xf1\xa7\xba\x95\xc9\xb8\xc3\xc0\x63\x2c\xe7\xe9\x61\x08\x3a\x79\x95\x08\x9b\x15\x19\x5f\xff\xc4\xe6\x46\x40\xb9\x3a\x6f\x22\xee\x3b\x0c\xc5\x55\x63\x21\x46\xdb\x6e\xf8\xd4\xfe\x38\x0d\xe1\xb2\x9f\x85\x64\x05\xff\x5f\x43\x01\xa9\x13\x96\x02\x41\x36\x24\xf0\x56\xf6\x1c\xa5\xda\xdb\xc5\x0b\xad\x8f\x3a\xb0\x88\x67\x7e\xb8\x4d\x97\x27\xb1\xc4\xdc\xfa\xf9\x7c\xd5\x1a\x90\x4f\xdc\xd7\xbb\x6c\x1f\xe2\xaf\x6c\x36\x77\xc2\xf0\xbb\x6d\xb3\x19\x02\x03\x01\x00\x01", 512) = 205
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x08\xcd\x18\x86\x53\xd0\x57\x78\x49\x28\x8e\x41\xa7\x74\xa9\xdf\x36\x6f\x58\x52\x2e\xd0\xa7\xfd\xa9\xde\x90\xde\x6a\xa0\x31\x12\xe3\x32\xe6\x2b\x7a\x58\x54\x8c\xdb\xd0\x5c\xf7\xd3\x4b\xdf\xd1\x7b\x34\xcf\x9f\x3e\xa9\x63\xd9\x21\x11\x4c\x68\x04\x83\xcf\xa4\xb0\x5e\x8d\xe3\x2c\xcd\xd7\xdd\x64\xc1\x2f\xb6\xcc\xc5\x63\x4b\x7c\x91\x7e\xae\x5d\xd5\x2f\x10\xab\x84\x6a\xc6\x49\x7f\xad\x14\xd8\x37\x30\x91\x83\x2c\xc4\x87\x20\xc0\x3c\xc8\xd1\x70\xcf\xd3\xe0\x21\xe5\x85\xce\x46\x19\x7d\x80\x52\x51\x5c\xfd\xb5\x94\x3f\x7f\x61\x2e\x84\x8d\xe9\x73\x60\x71\xe2\x1a\xf1\xae\x0f\x74\xf8\x65\x37\x88\x13\x55\xe7\xe8\xba\xc2\x39\x12\x8d\x7e\xde\x3c\x9a\xb8\xa1\xab\x75\xda\x8c\x91\xd7\x30\x99\xce\x3d\x02\x03\x01\x00\x01", 512) = 205
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x0a\x1c\xaa\x01\xeb\xef\x91\x25\x7a\x98\xb0\x8c\x5d\x32\x44\x0d\x35\x50\xe7\x50\x11\x62\x43\x3a\x75\x86\x46\xfe\x95\xe3\x70\x04\x0c\x04\x70\x5e\x94\x9d\x9a\x65\xa2\x66\xc3\xc7\xe8\x8a\x4b\x5f\x32\xa8\x81\x5f\xa8\xfb\x92\x7c\x24\x5c\x1a\xd8\x72\x20\x47\x72\xee\xf8\x01\x8a\x1a\x30\x14\x24\xfb\xc8\x70\xc0\xc9\x43\xa3\x7d\xf7\x83\xed\x94\x11\x10\x27\x30\x1f\x80\xe6\x56\xf4\x06\x24\x9e\xe7\x53\x81\x6f\x5c\xcf\x30\xf3\xde\x1f\x81\xfa\x19\x03\x90\x39\xce\xdc\xa7\xf2\xe4\x1b\xe7\x3e\xf3\x24\xa2\x65\xca\xd2\xf8\x55\xbc\x20\x42\xf8\x1d\xef\xb8\x66\xeb\xd1\x79\x9d\xab\x26\x5a\x15\xd8\x1a\x5f\x7a\xf4\x96\x55\xfa\x74\x52\xd4\x0a\xa6\xa9\x0b\x74\x57\x12\x4f\xbf\x9d\x4c\x2a\xe5\xe1\xa7\x6d\x39\x02\x03\x01\x00\x01", 512) = 205
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x09\x3b\x84\x7f\x65\xa3\xa4\xb9\x83\xa9\xa1\xe4\xd3\x35\x38\x9d\x14\x61\x78\x64\xd9\xc1\xf1\x19\x3c\x67\x51\x60\x19\x4e\xdb\xc0\x4f\x99\xed\x45\xc3\x8d\x67\xaf\xbb\x65\xb1\x5e\xc9\x96\x42\xca\xd8\xc2\x34\xa5\xaa\x45\x87\x5b\xb1\xf6\x59\x11\x96\xe6\xf6\x1f\x27\xbf\xb8\x45\x57\x12\x6b\x8f\x70\x6f\xc0\xb9\xab\xd1\xf2\x36\x3b\xcd\x88\xb8\xd3\xb1\xcd\x3a\x06\x7c\x4f\x70\x1f\xf0\xbf\x3b\x9b\x1c\xb8\x8a\xcb\x16\x08\x1d\x5c\xaf\xea\x3c\xf1\x6d\xd0\xc8\x74\xc8\x8e\x23\x0d\x8e\x31\x6d\x7f\xe5\x3d\x8b\x93\xfb\xf2\x8f\x1c\x59\x22\x3f\x24\x8f\x3e\x9d\x14\x2f\x23\xde\xad\xec\x51\x12\xbe\xbf\x88\xfa\xef\x15\x51\x2e\xae\x45\x34\x0f\x55\x07\xf6\xa0\x91\xb0\x3b\xfa\xff\x6a\x76\xe3\x5c\x01\x5b\xb1\x02\x03\x01\x00\x01", 512) = 205
read(3, "\x30\x81\xca\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\xb8\x00\x30\x81\xb4\x02\x81\xac\x09\xe5\x99\xb0\x9b\x76\xa3\x61\xac\x6f\x21\xa3\xb6\x05\x19\x88\x4e\xd1\xef\xb1\xe5\xbc\x04\xb3\x27\xc7\x90\x80\x03\x3b\x61\x3d\x56\x00\x95\x9c\x0e\x3b\x4a\x91\xab\x1f\xd3\x03\x42\x88\xf3\xd4\x92\x93\x0f\xa9\x87\x60\x00\x95\x2f\xc8\xec\x09\x04\x05\x4f\x58\x5a\xc5\xe7\x00\xda\xc8\xea\x73\x3a\xa2\x24\x57\x93\xb5\xcc\xf8\x79\xd0\x53\x2b\x44\xa9\xc0\x4b\x33\x31\x11\xfa\xae\xf8\x88\x53\x13\x84\x67\x72\xe8\x1a\xa2\x38\x92\x2c\x78\x9c\x21\xd5\x75\x07\xc8\x98\x89\x69\x67\x52\xed\x39\x33\xbb\x47\x2c\x28\x31\xeb\x1c\x5e\x13\x8e\x08\x91\xc4\x75\x2e\x72\x86\x21\xc3\x6e\x17\xf5\x15\x07\xc5\x37\xae\xfc\x71\x0d\x13\xe0\x2d\x6b\xf4\x18\x71\xe5\xc9\xff\xf3\x84\x3c\x7e\xe9\xe9\x45\x45\xfc\x00\x95\x02\x03\x01\x00\x01", 512) = 205
```

### Prime numbers generation

The client is dynamically linked with OpenSSL. The signature uses SHA256 and a multiprime RSA key pair that can be generated by the client if the environment variable `TEAM_RANDOM_NUM` is set:

![RSA Key generation](images/generate_key.png)

The prime generation function used is `BN_generate_prime_ex2` with a custom `RAND` context so that the `rand` function from the `libc` is used rather than OpenSSL CSPRNG:

![RSA Key generation](images/rsa_ctx.png)

We quickly concluded that the use of `rand()` was merely to get a DRBG generator and not a real backdoor, since factoring attacks on composite numbers based on primes generated by the concatenation of an LCG are known to be currently prohibitive.

Moreover, the seeding is also based on the team number and a modular exponentiation of the team random number:

![Value for seed computing](images/seed_val.png)

As we can see, the seed value is based on `team_random_number^6 mod N` with N = 3930574699.

![Base value for the seed](images/seed_base.png)

Then, for each seeding, a modular exponentiation is computed with an exponent equal to `e[i+1] = 2 * e[i] + 1, e[0] = 65`. The team number is added before the call to `srand`.

We thus have for the seed values:
```
seed_base[0] = team_random_number^6 mod N
e[0] = 65
e[i+1] = 2 * e[i] + 1
seed_base[i] = seed_base[i-1]^e[i] mod N, i = 1..3

seed[i] = seed_base[i] + team_number
```

We put a breakpoint on `srand` to get some values so that we could have an idea of what was going on with this weird implementation. What we observed was that whatever `TEAM_RANDOM_NUM` we used, we always ended up with `TEAM_NUM + 1` for the third call:
```
Breakpoint 3, __srandom (x=8) at random.c:209
209     in random.c
(gdb)
```
After several tries, we were convinced this was not a coincidence and we should use it to get the third prime for all teams.

## Post mortem analysis and alternative solution

The reason this happens is that we can reduce the seed values equation by multiplying all the exponents used:
```
seed[1] = team_random_number^786 mod 3930574699 + team_number
seed[2] = team_random_number^206718 mod 3930574699 + team_number
seed[3] = team_random_number^108940386 mod 3930574699 + team_number
```

The thing to notice here, is that `108940386` is the value for the Carmichael function at N, `λ(3930574699)`:
```sage
sage: factor(3930574699)
787 * 1579 * 3163
sage: lcm([787 - 1, 1579 - 1, 3163 - 1])
108940386
```
It means that as long as `TEAM_RANDOM_NUM` is coprime with `N`, the result of the modular exponentiation will always be 1. Assuming that the team random number is not really random such that it is never a multiple of `787`, `1579` or `3163`, then the third seed value will always be `1 + team_number` for all teams. We can compute the third prime for the RSA modulus of all teams without knowing their random number.

But wait, there's more! For the second call to `srand` the exponent is `206718` which also happens to be a value for the Carmichael function `λ(787 * 1579)`. This means that the number of possible values before adding the team number will eventually be `2^2 * R_206718(3163)`, with `R_k(M)` being the order of the group defined by `a^k mod M`. This value is obviously bounded by `M = 3163`. Even better: `gcd(206718, 3163 - 1) = 6`, which means the number of elements in the group is likely around one-sixth of the modulus which makes it around `528`. Actually, if [Mathar's conjecture](https://www2.mpia-hd.mpg.de/~mathar/public/mathar20171110.pdf) for computing `R_k(M)` holds, it should be exactly `528`.

Using `sage` we can find all values in the group defined by `a^206718 mod 3163`. Then, using the Chinese Remainder Theorem, we can get all values for `a^206718 mod 3930574699` knowing that the only possible elements for `M = 1579` and `M = 787` are `0` and `1`:
```python
# Find elements for M = 3163
seed_bases=set()
for i in range(3163):
    seed_bases.add(pow(i, 206718, 3163))

# Find all elements for M = 3930574699
seed_base_all=set()
for k in seed_bases:
    for l in range(2):
        for m in range(2):
            c = CRT_list([Integer(k), Integer(l), Integer(m)], [3163, 787, 1579])
            seed_base_all.add(c)

# Add the team number to generate the full set of seeds
seed_base_tn=set()
for i in seed_base_all:
    for k in range(1, 9):
        seed_base_tn.add(i + k)

# Create a C header file
f = open("seeds.h", "wb+")
f.write(b"long seeds[] = ")
f.write(bytes(str(seed_base_tn), 'ascii'))
f.write(b";\n")
f.close()
```

This produces a set of 14279 elements if we remove our team number, or 16189 elements if we want to know the complete set of possible `q` for all teams including ours.

As we want to check for our own keys, we will test against all 16189 possible `q`. The following C implementation will generate prime numbers the same way the client binary does:
```C
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdio.h>
#include "seeds.h"

static int rnd_add(const void *a1, int a2, double a3) { return 0; }
static int rnd_status() { return 1; }
static int rnd_seed(const void *a1, int a2) { srand(seeds[*(int *)a1]);  return 0; }
static int rnd_bytes(unsigned char *a1, int a2) { for(int i=0;i<a2;++i) a1[i]=rand(); return 1; }

int main()
{
    BIGNUM *prime = BN_new();
    struct rand_meth_st meth = {
        .seed = rnd_seed,
        .bytes = rnd_bytes,
        .add = rnd_add,
        .pseudorand = rnd_bytes,
        .status = rnd_status
    };
    RAND_set_rand_method(&meth);
    for (long sidx = 0; sidx < sizeof(seeds)/sizeof(long); sidx++) {
        unsigned char buf[128];
        RAND_seed(&sidx, 8);
        BN_generate_prime_ex(prime, 172, 0LL, 0LL, 0LL, 0LL);
        BN_bn2bin(prime, buf);
        for (int i = 0; i < BN_num_bytes(prime); i++) printf("%02x", buf[i]);
        printf("\n");
    }
    return 0;
}
```

It needs to link against the provided `libcrypto.so` with the client since prime generation can change between versions of OpenSSL. So we simply compile and invoke as follows:
```sh
gcc -o gene_allq gene_allq.c -lcrypto -L/home/user/has2/finals/team_7/client/libs
LD_LIBRARY_PATH=/home/user/has2/finals/team_7/client/libs ./gene_allq >/tmp/allqs
```

This operation takes around 15s on an old laptop. This seems more than acceptable to solve this challenge!

Now, we have all moduli from the public keys, and we can compute all possible values for the second prime. To find which of these primes were used for the private keys, we simply need to check if `q` is a divisor of `n`:
```python
ns = {}
for i in keys.keys():
    k = load_der_public_key(keys[i])
    ns[i] = k.public_numbers().n

a = open("/tmp/allqs2", "rb")
for l in a.readlines():
    q = int(l, 16)
    for i in ns:
        if ns[i] % q == 0:
            print("found Q=%d for key_id=%d"%(q, i))
```

And it works, so we obtain one of the primes for all moduli in a total of just a few seconds:
```
found Q=4645117513501178961499067446656458881658861181774499 for key_id=1
found Q=5434384070623497911175138079325354353650695515424243 for key_id=5
found Q=4598203956375912136389367865517736286725503903811151 for key_id=7
found Q=5126382870572122392981665785314020995087596347758957 for key_id=2
found Q=5353747535350065882308650278879115514714177217964069 for key_id=4
found Q=5067657506070432955103555335846351858600345804911053 for key_id=3
found Q=4973437017047511659883180810111412955859155898990721 for key_id=8
found Q=4908891661270256934602919969470283478788007314693709 for key_id=6
```

We can also modify our C code to generate the `r` value for all teams:
```C
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdio.h>

static int rnd_add(const void *a1, int a2, double a3) { return 0; }
static int rnd_status() { return 1; }
static int rnd_seed(const void *a1, int a2) { srand(*(int *)a1);  return 0; }
static int rnd_bytes(unsigned char *a1, int a2) { for(int i=0;i<a2;++i) a1[i]=rand(); return 1; }

int main()
{
    BIGNUM *prime = BN_new();
    struct rand_meth_st meth = {
        .seed = rnd_seed,
        .bytes = rnd_bytes,
        .add = rnd_add,
        .pseudorand = rnd_bytes,
        .status = rnd_status
    };
    RAND_set_rand_method(&meth);
    for (long sidx = 2; sidx < 10; sidx++) {
        unsigned char buf[512];
        RAND_seed(&sidx, 8);
        BN_generate_prime_ex(prime, 1028, 0LL, 0LL, 0LL, 0LL);
        BN_bn2bin(prime, buf);
        printf("%ld: ", sidx-1);
        for (int i = 0; i < BN_num_bytes(prime); i++) printf("%02x", buf[i]);
        printf("\n");
    }
}
```

Which gives us divisors of their respective moduli:
```
1: 0d546fb87759f3703210335dbe700286212ecd5c9bc00b1120e387cf2fb5154c09840580ddf8f00f08236dc6946f4cb59d1a1138da1d4afb00d1ca3086e07c8f64810f4279ff518123be48b72d946ccaae7e03899b4d849b1e4ecba42e483393c942d5434126c464e50c1b12a188dd4f06e0d8a12d5c3c4bab08efd950226c197f
2: 0feee46caaafbcabe9eb5aa10c33cd72349710df1c23717d393b03bbdb3b2b762910e2d3bf9e7fa889d94a960c170840af1820cb3c914875cc4b30a7865b1db06b00832a9e02d328db1dbee734c628e3de48ae1ad9f68fa541bf4cc81b69788669fbb108fe8430d9a1eec1d5b4e9b9923167ad0a5e3caf9ffcfb671764df9dcf05
3: 0fdf64d331f7538791ba277df32515697bde56340bdf82795c4ac04aba4a232d2987005a7e53e10f0d098c002ea169a97fc0dd8b9f5f04fbaac445640e689137ef91916de5737df27c09f3aaab5c542a1c31b5bb91bab63b7efc9f8d6430c454c156c1a6c93e9945488ceff3e8431d0575d3c0068d77410b73e098d7105d2bd1b7
4: 0df2d6a4b89561f7179fcfbd8439e2d0023a6582e9f7fc82d960cdb4521456b3062d57bfc2b9b6d9588696dcbf78adc1b212439b093f1ee29feb97f1ffeda5051afcc4dcb57bb50d014ceac0c4978277a9c512b3053095a41b2c961a1a3b203437e411ed5fc6fa6012e421d77ba34e256860d86d916d12ac9aa8c7b4e3e7e81acf
5: 0ce18aa7fc5c5db67400433d883350ee8c2d12486d12308f86028e8a83f02a58d2b5ffce115c84855cc8c2e4fb12d2873fe4cfadf6ff3c7d02ca0785bb32dd8de7dc5bf838df7d94a73f78a2514a2a902ff93d25f979a2fb44aa80ffdc5e8cc33ae7bb73c638076e778010c8ca3a58f934961f2d0fc128536ba8524706de0a41cd
6: 0e8b798566b50e624e62a13f25bc2048f314371000c21d96a3017af5cf8050110cc997727fa5d4cd08750c2d322d762541ad35416f52d81253520723d35834df21cb51a071266e799b7aa6cda71cf2e9ca282a397a024cce5553f128ab2507cdf1586d627edbdb1a5681e7fd9edae6680211a17c13ed4a68413b90ec6197b95307
7: 0edf4d361ad6efc1ddf7fd2fd8d13d4abab24e07244f8f11e28370b5e29b2ad57a770b944dfa552af15259ca239614de4962e56db1747e93f7ee49da8973af04eaba9838b4ee62a540bc6f645283429be52709969b872a9276736cffe61b03d0d59c08898a6b2fca279e2e7922701507971e9e32a5c8c51b3b311b214d1ef122c5
8: 0fa9a64d7603e6ba848c3acb0a861e03f642896146664f7e285f3eae64fef5e3a79b301d9e16d723a311eead970db08e4f39ef95a03e13c89e527702506ce5f7081614a62cebc9cffcb87c94c52c22146611a9064fbcceed0e45ef5eb2d555baeb696017542ae751e263e5a79007bbf61864fc6720ca552f10448dc219e37c045d
```

Now that we have both `q` and `r`, generating the PEM files for the private keys is just a matter of a few lines of `python`.

## Solution used during the finals

### Getting the bigger prime

Since we observed that the third prime factor generated for the multiprime RSA key only used the team number for its seeding, we wanted to compute it for all teams. The primes do not have the same length. The function for generating the key is a modification of [OpenSSL's `rsa_multiprime_keygen` function](https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_gen.c#L75). Normally, the length of the modulus is distributed evenly among the primes, but there is this modification in the binary:

![Primes length assignation](images/prime_len.png)

Apparently, both `p` and `q` are relatively small (172 bits), and `r` is big (1028 bits). Since it is the bigger prime we can obtain for all teams, this is a huge deal!

Conveniently, the client will generate a key pair when the environment variable `TEAM_RANDOM_NUM` is set, we could trivially script it to get this prime for all teams.

A quick and dirty one-liner was used to generate the result into a python `dict`:
```sh
echo "r = {"; for ((i=1;i<9;i++)); do TEAM_NUM=$i TEAM_RANDOM_NUM=2 ./client -k 5647008472405673096 -m 0000 -p 31337 -a 10.0.0.101 -i 1 | grep -v id_rsa; openssl rsa -in private.pem -text | awk -v idx=$i 'BEGIN{parse=0}{ if ($0 ~ "prime3:") {parse = 1} else if($0 ~ "exponent3:") {parse=0} else if (parse == 1) { rr = rr$0}}END{print idx "-0x" rr ","; }' | sed 's/ //g;s/://g;s/-/: /'; done 2>/dev/null; echo "}"
```

Which gave us the following result:
```python
r = {
1: 0x0d546fb87759f3703210335dbe700286212ecd5c9bc00b1120e387cf2fb5154c09840580ddf8f00f08236dc6946f4cb59d1a1138da1d4afb00d1ca3086e07c8f64810f4279ff518123be48b72d946ccaae7e03899b4d849b1e4ecba42e483393c942d5434126c464e50c1b12a188dd4f06e0d8a12d5c3c4bab08efd950226c197f,
2: 0x0feee46caaafbcabe9eb5aa10c33cd72349710df1c23717d393b03bbdb3b2b762910e2d3bf9e7fa889d94a960c170840af1820cb3c914875cc4b30a7865b1db06b00832a9e02d328db1dbee734c628e3de48ae1ad9f68fa541bf4cc81b69788669fbb108fe8430d9a1eec1d5b4e9b9923167ad0a5e3caf9ffcfb671764df9dcf05,
3: 0x0fdf64d331f7538791ba277df32515697bde56340bdf82795c4ac04aba4a232d2987005a7e53e10f0d098c002ea169a97fc0dd8b9f5f04fbaac445640e689137ef91916de5737df27c09f3aaab5c542a1c31b5bb91bab63b7efc9f8d6430c454c156c1a6c93e9945488ceff3e8431d0575d3c0068d77410b73e098d7105d2bd1b7,
4: 0x0df2d6a4b89561f7179fcfbd8439e2d0023a6582e9f7fc82d960cdb4521456b3062d57bfc2b9b6d9588696dcbf78adc1b212439b093f1ee29feb97f1ffeda5051afcc4dcb57bb50d014ceac0c4978277a9c512b3053095a41b2c961a1a3b203437e411ed5fc6fa6012e421d77ba34e256860d86d916d12ac9aa8c7b4e3e7e81acf,
5: 0x0ce18aa7fc5c5db67400433d883350ee8c2d12486d12308f86028e8a83f02a58d2b5ffce115c84855cc8c2e4fb12d2873fe4cfadf6ff3c7d02ca0785bb32dd8de7dc5bf838df7d94a73f78a2514a2a902ff93d25f979a2fb44aa80ffdc5e8cc33ae7bb73c638076e778010c8ca3a58f934961f2d0fc128536ba8524706de0a41cd,
6: 0x0e8b798566b50e624e62a13f25bc2048f314371000c21d96a3017af5cf8050110cc997727fa5d4cd08750c2d322d762541ad35416f52d81253520723d35834df21cb51a071266e799b7aa6cda71cf2e9ca282a397a024cce5553f128ab2507cdf1586d627edbdb1a5681e7fd9edae6680211a17c13ed4a68413b90ec6197b95307,
7: 0x0edf4d361ad6efc1ddf7fd2fd8d13d4abab24e07244f8f11e28370b5e29b2ad57a770b944dfa552af15259ca239614de4962e56db1747e93f7ee49da8973af04eaba9838b4ee62a540bc6f645283429be52709969b872a9276736cffe61b03d0d59c08898a6b2fca279e2e7922701507971e9e32a5c8c51b3b311b214d1ef122c5,
8: 0x0fa9a64d7603e6ba848c3acb0a861e03f642896146664f7e285f3eae64fef5e3a79b301d9e16d723a311eead970db08e4f39ef95a03e13c89e527702506ce5f7081614a62cebc9cffcb87c94c52c22146611a9064fbcceed0e45ef5eb2d555baeb696017542ae751e263e5a79007bbf61864fc6720ca552f10448dc219e37c045d,
}
```

We now needed to divide the modulus from each team's public key to obtain a 344 bits number that can be factored into two 172 bits numbers. We used the following script to get the `p * q` product:

```python
import cryptography
from cryptography.hazmat.primitives.serialization import load_der_public_key
from data import keys, r

ns = {}
for i in keys.keys():
    k = load_der_public_key(keys[i])
    ns[i] = k.public_numbers().n
    pq = ns[i] // r[i]
    print(pq)
```

This gives the following result for the `p * q` product for all 8 keys:
```
27003348924062262876175862245390887892229191082497958302869624053290575750946215091468211135809959123853
30304398887949504977186476923894458595884706249755810043821660551905179587970664917176122317235243832207
25707848964421306860870690854799563384969578040628747145092120747173821981789770270957847033985943502421
29753679635970288510483446195084244244381400656822213101812299726134284990450478362408946427472775785879
24485438153176594044954257095588468186882366915285347162599396363402918000586275720487243090178853703217
24914134323855728627705398733245316777705865340438397543662262535821804207712692074402646833178539716031
22246416363987060635999737016863983275278241375084533371201059944467598268341432473477489793899637371901
22643846135708884611877534787292171711589740910338314701895968439229951738746811058059433130300837505433
```

### Factoring with cado-nfs

As a bit of trivia, in 1998 some French guy used an implementation of Multiple Polynomial Quadratic Sieve to factor a 384 bits RSA modulus used for all credit card payments in France. It allegedly took him around 3 months to factor the modulus. He then posted it on the Internet, wreaking havoc in the banking system for 4 years before a larger modulus was used. While not directly related to this challenge, it was a good argument in favor of factoring the obtained numbers and completely dismissing any bruteforce of the seed used to generate the prime for `p` and `q`. Considering the computing power of today's computer compared to those in 1998 with an additional decrease of 40 bits, it was a good bet to directly try to factor the `p * q` product.

We used [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs) to factor these 344 bits numbers, which can be achieved in 10 to 15 minutes on a 12 cores Ryzen 9 3900X, or about 8 minutes on a 32-cores `m6i.8xlarge` VM rented on EC2 during the finals (USD 1.53/hour).

The usage is quite simple and the output rather clear:
```
$ ./cado-nfs.py 27003348924062262876175862245390887892229191082497958302869624053290575750946215091468211135809959123853
[...]
4645117513501178961499067446656458881658861181774499 5813275734268549037839470061694776475762663585477647
```

We finally obtained the following results:
```
4645117513501178961499067446656458881658861181774499 * 5813275734268549037839470061694776475762663585477647 = 27003348924062262876175862245390887892229191082497958302869624053290575750946215091468211135809959123853
5126382870572122392981665785314020995087596347758957 * 5911458362174073680339051061564562568102834793062251 = 30304398887949504977186476923894458595884706249755810043821660551905179587970664917176122317235243832207
5067657506070432955103555335846351858600345804911053 * 5072925495384495253458550024101992155311846351410857 = 25707848964421306860870690854799563384969578040628747145092120747173821981789770270957847033985943502421
5353747535350065882308650278879115514714177217964069 * 5557542532499112788361301306687534885206931211412491 = 29753679635970288510483446195084244244381400656822213101812299726134284990450478362408946427472775785879
5434384070623497911175138079325354353650695515424243 * 4505651024103515385680422388399309428197988957958219 = 24485438153176594044954257095588468186882366915285347162599396363402918000586275720487243090178853703217
4908891661270256934602919969470283478788007314693709 * 5075307430477857433280402280078316236855670387980859 = 24914134323855728627705398733245316777705865340438397543662262535821804207712692074402646833178539716031
4838066465742558883325160026444100868903255429323251 * 4598203956375912136389367865517736286725503903811151 = 22246416363987060635999737016863983275278241375084533371201059944467598268341432473477489793899637371901
4973437017047511659883180810111412955859155898990721 * 4552957252317118476830362647347936169114770504686873 = 22643846135708884611877534787292171711589740910338314701895968439229951738746811058059433130300837505433
```

## Generating and using the private keys

We used [scapy](https://scapy.net/) to generate the PEM files for the private keys using the `RSAPrivateKey` class:

```python
from scapy.layers.x509 import RSAPrivateKey, RSAOtherPrimeInfo
from data import facts

ns = {}
for i in keys.keys():
    k = load_der_public_key(keys[i])
    ns[i] = k.public_numbers().n
    p, q = facts[i]
    d = pow(65537, -1, (r[i] - 1) * (p - 1) * (q - 1))
    rsa = RSAPrivateKey()
    rsa.modulus = ns[i]
    rsa.publicExponent = 65537
    rsa.privateExponent = d
    rsa.prime1 = p
    rsa.prime2 = q
    rsa.exponent1 = d % (p - 1)
    rsa.exponent2 = d % (q - 1)
    rsa.coefficient = pow(q, -1, p)
    op = RSAOtherPrimeInfo()
    op.prime = r[i]
    op.exponent = d % (r[i] - 1)
    op.coefficient = pow(p * q, -1, r[i])
    rsa.otherPrimeInfos = op
    with open("team_%d_rsa_priv.pem"%i, "wb+") as f:
        f.write(b"-----BEGIN RSA PRIVATE KEY-----\n")
        key = base64.b64encode(bytes(rsa))
        for offt in range(0, len(key), 64):
            f.write(key[offt:offt+64] + b'\n')
        f.write(b"-----END RSA PRIVATE KEY-----\n")
```
We could now sign messages ourselves as any other team using the command:

```
./client -k 5647008472405673096 -m 0000 -p 31337 -a 10.0.0.101 -i 8 -f team_8_rsa_priv.pem
```

Fortunately, the organizers announced a first blood on the challenge, as we had absolutely no idea what should be the next step. Apparently, it was sufficient to validate the challenge. We were looking for tokens since we were given a url to validate them. As we learned afterward, the tokens would have to be obtained in the next challenge eventually.

## Conclusion

We saw that there were two possible ways to solve this challenge, one requiring more background in mathematics than the other. During a CTF, where time is constrained, it is important to find a "quick win" rather than analyzing everything in detail. Taking traces with `gdb` to get an idea of what was going on quickly gave us the third prime. Since we knew based on successful factorings that the remaining composite number could be factored on our current hardware, we ended up with a relatively fast solution to this challenge.

As mentioned earlier, a third, purely theoretical approach existed. However, the state of the art considering attacks on moduli based on prime built using the output of an LCG is out-of-reach: [*the constructed matrix is of huge dimension (since the number of monomials is quite large) and the computation which is theoretically polynomial-time becomes in practice prohibitive*](https://www.iacr.org/archive/pkc2016/96140194/96140194.pdf).

Eventually, the solution based on Carmichael function properties and the order of finite groups generated by a fixed exponent made this challenge quite interesting!

