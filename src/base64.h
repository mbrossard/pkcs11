#ifndef BASE64__H
#define BASE64__H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

/** @file base64.h
 * Base64 encoding/decoding functions
 */

#ifdef __cplusplus
extern "C" {
#endif

unsigned int estimate_base64(unsigned int lin, int newline);

unsigned int encode_base64(unsigned char *bin, unsigned int lin,
                           unsigned char *bout, int newline);

int decode_base64(unsigned char *bin, unsigned int lin,
				  unsigned char *bout, unsigned int *lout);

#ifdef __cplusplus
}
#endif
#endif /* BASE64__H */
