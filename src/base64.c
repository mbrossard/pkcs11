#include "base64.h"

#define BASE64_LINESIZE 72

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

static const unsigned char _b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                                      "ghijklmnopqrstuvwxyz0123456789+/";

unsigned int estimate_base64(unsigned int lin, int newline)
{
    int r = ((lin / 3) + 1) * 4;
    if(newline) {
        r += r / BASE64_LINESIZE + ((r % BASE64_LINESIZE) ? 1 : 0);
    }
    return r + 1;
}

unsigned int encode_base64(unsigned char *bin, unsigned int lin,
                           unsigned char *bout, int newline)
{
    unsigned int i, cur = 0, count = 0, col = 0, sum = 0;

    for(i = 0; i < lin; i++) {
        cur += *(bin++);
        count++;
        if(count == 3) {
            *(bout++) = _b64[(cur >> 18)];
            *(bout++) = _b64[(cur >> 12) & 0x3f];
            *(bout++) = _b64[(cur >> 6) & 0x3f];
            *(bout++) = _b64[(cur) & 0x3f];
            sum += 4;

            if(newline) {
                col += 4;
                if (col == BASE64_LINESIZE) {
                    *(bout++) = '\n';
                    col = 0;
                    sum++;
                }
            }
            cur = 0;
            count = 0;
        } else {
            cur <<= 8;
        }
    }

    if(count != 0) {
        cur <<= 16 - 8 * count;
        *(bout++) = _b64[(cur >> 18)];
        *(bout++) = _b64[(cur >> 12) & 0x3f];
        if(count == 1) {
            *(bout++) = '=';
        } else {
            *(bout++) = _b64[(cur >> 6) & 0x3f];
        }
        *(bout++) = '=';
        sum += 4;
    }
    if(newline && col) {
        *(bout++) = '\n';
        sum++;
    }

    *bout = '\0';
    return sum;
}

int decode_base64(unsigned char *bin, unsigned int lin,
				  unsigned char *bout, unsigned int *lout)
{
    static char valid[256], decoder[256], initialized = 0;
    unsigned int i, j, cur, c, count, err = 0;

    if(initialized == 0) {
        memset(valid, 0, sizeof(valid));
        memset(decoder, 0, sizeof(decoder));
        i = 64;
        while (i > 0) {
            i--;
            valid[_b64[i]] = 1;
            decoder[_b64[i]] = i;
        }
        initialized = 1;
    }

    count = 0;
    cur = 0;
    i = j = 0;
    while (i < lin) {
        c = *(bin++);

        if (c == '=') {
            break;
        }

        i++;
        if (! valid[c]) {
            continue;
        }

        cur += decoder[c];
        count++;
        if (count == 4) {
            *(bout++) = (cur >> 16);
            *(bout++) = (cur >> 8) & 0xff;
            *(bout++) = (cur) & 0xff;
            j += 3;
            cur = 0;
            count = 0;
        } else {
            cur <<= 6;
        }
    }
    if(i == lin) {
        if (count) {
            err ++;
#ifdef DEBUG
            fprintf(stderr, "base64 encoding incomplete: at least %d bits truncated\n",
                    ((4 - count) * 6));
#endif
        }
    } else { /* c == '=' */
        switch (count) {
            case 1:
#ifdef DEBUG
                fprintf(stderr, "base64 encoding incomplete: at least 2 bits missing\n");
#endif
                err++;
                break;
            case 2:
                *(bout++) = (cur >> 10);
                j++;
                break;
            case 3:
                *(bout++) = (cur >> 16);
                *(bout++) = (cur >> 8) & 0xff;
                j += 2;
                break;
        }
    }
    if(lout) {
        *lout = j;
    }
    return err ? -1 : 0;
}

#ifdef BASE64_TEST

void hexdump(unsigned char *buffer, int size) {
#ifdef DEBUG
    int i, j;
    printf("Size: %d (0x%x)\n", size, size);
    for(i = 0, j = 0; i < size; i++, j++) {
        printf("%02x", buffer[i]);
        if(((j+1) % 16) == 0) {
            printf("\n");
        } else if(((j+1) % 4) == 0) {
            printf(" ");
        }
    }
    printf("\n");

    for(i = 0, j = 0; i < size; i++, j++) {
        if(isgraph(buffer[i])) {
            printf("%c", buffer[i]);
        } else {
            printf(".");
        }
        if(((j+1) % 16) == 0) {
            printf("\n");
        } else if(((j+1) % 4) == 0) {
            printf(" ");
        }
    }
    printf("\n");
#endif
}

int main() {
    char *buf1, *buf2, *buf3;
    int i, j;
    long l;
    unsigned int msize = 4096, size;
    unsigned int s2, s3;

    buf1 = malloc(msize);
    buf2 = malloc(msize * 2);
    buf3 = malloc(msize);

    for(i = 0; i < 1024; i++) {
        size = (random() % msize);
        printf("Testing %d, (%d) newline %d\n", i, size, i % 2);

        for(j = 0 ; j < size; j++) {
            if((j & 3) == 0) {
                *((long *)&l) = random();
            }
            buf1[j] = l & 0xFF;
            l >>= 8;
        }

        hexdump((unsigned char *)buf1, size);
        s2 = encode_base64((unsigned char *)buf1, size,
                           (unsigned char *)buf2, i % 2);
        hexdump((unsigned char *)buf2, s2);

        if(decode_base64((unsigned char *)buf2, s2,
                         (unsigned char *)buf3, &s3)) {
            fprintf(stderr, "Error decoding\n");
            return -1;
        } else {
            if(s3 != size) {
                fprintf(stderr, "Invalid decoded size\n");
                return -1;
            } else {
                hexdump((unsigned char *)buf3, s3);
                if(bcmp(buf1, buf3, size)) {
                    fprintf(stderr, "Result differs from expected value\n");
                    return -1;
                }
            }
        }
        printf("Success %d, (%d)\n", i, size);
    }

    free(buf1);
    free(buf2);
    free(buf3);

    return 0;
}

#endif
