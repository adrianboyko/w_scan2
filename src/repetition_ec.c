/*
 * A simple error correction method that infers correct data, given multiple copies of noisy data.
 *
 * Copyright (C) 2019 Adrian Boyko
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * Or, point your browser to http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "repetition_ec.h"
#include "tools.h"
#include "descriptors.h"

static pList all_fuzzy_bufs = NULL;

#define CRC_LENGTH 4
#define BITS_PER_BYTE 8

typedef struct {
    /*----------------------------*/
    void *prev;
    void *next;
    uint32_t index;
    /*----------------------------*/
    __u16 len;  // The length in bytes of the data that we're trying to correct.
    __s16 *counts;  // len*8 counts, one per bit. In a group of 8 counts, the most significant bit's is first.
} cFuzzyBuf, *pFuzzyBuf;

#ifdef DEBUG
/* A utility function that dumps bufs in a mixed hex/char format, so spotting some data is easier. */
static void dump_buffer(unsigned char *buf, __u16 len, char *title) {
    info("\n%s:\n", title);
    for (int i = 0; i < len; i++) {
        if (buf[i] > 32 && buf[i] < 127) { info("%2c ", buf[i]); }  // Printable ASCII values display as chars.
        else { info("%02x ", buf[i]); }  // Other values are displayed as hex.
        if (i % 40 == 39) { info("\n"); }  // 40 values per line
    }
    info("\n\n");
}
#endif


/* See header file for description */
void reset_repetition_ec(void) {
    if (!all_fuzzy_bufs) return;
    for (pFuzzyBuf pFB = all_fuzzy_bufs->first; pFB; pFB = pFB->next ) {
        free(pFB->counts);
    }
    ClearList(all_fuzzy_bufs);
}

/* This collects the required statistics.
 * Given a buf/len and a "reasonably similar" FuzzyBuf, this adjusts the bit balance counts.
 */
static void adjust_counts(pFuzzyBuf pFB, unsigned char *buf, __u16 len) {
    for (__u16 byte_pos = 0; byte_pos < len; byte_pos++) {
        for (__u8 bit_pos = 0; bit_pos < BITS_PER_BYTE; bit_pos++) {
            _Bool buf_bit_val = buf[byte_pos] & (128>>bit_pos);
            __s16 adjustment = buf_bit_val ? 1 : -1;
            pFB->counts[byte_pos * BITS_PER_BYTE + bit_pos] += adjustment;
        }
    }
}

/* repetition_ec's algorithm depends on the ability to determine which noisey bufs are like which others.
 * This is done by comparing a new buf to all the existing FuzzyBufs, to see if any is a reasonable match.
 */
static _Bool is_reasonable_match(pFuzzyBuf pFB, unsigned char *buf_in, __u16 len_in) {
    if (len_in != pFB->len) return 0;  // Not going to try to deal with inserted/deleted bits.

    // This algorithm will work for arbitrary buffers with or without CRCs.
    // However, the next three lines focus it on the CRC we know is present in this application.
    __u8 *buf = buf_in + len_in - CRC_LENGTH;
    __u16 len = CRC_LENGTH;
    __s16 *counts = pFB->counts + len_in * BITS_PER_BYTE - CRC_LENGTH * BITS_PER_BYTE;

    __u16 mismatch_count = 0;
    for (__u16 byte_pos = 0; byte_pos < len; byte_pos++) {
        for (__u8 bit_pos = 0; bit_pos < BITS_PER_BYTE; bit_pos++) {
            __s16 fuzzy_bit_val = counts[byte_pos * BITS_PER_BYTE + bit_pos];
            __s8 fuzzy_bit_sign = fuzzy_bit_val/abs(fuzzy_bit_val);
            _Bool buf_bit_val = buf[byte_pos] & (128>>bit_pos);
            switch (fuzzy_bit_sign) {
                case -1: // FuzzyBuf thinks this bit should be 0
                    mismatch_count += (buf_bit_val == 1);
                    continue;
                case +1: // FuzzyBuf thinks this bit should be 1
                    mismatch_count += (buf_bit_val == 0);
                    continue;
                default: // FuzzyBuf doesn't have an opinion re this bit
                    continue;
            }
        }
    }
    __u16 mismatch_pc = 100 * mismatch_count / (len * BITS_PER_BYTE);
    return mismatch_pc < 10;  // 10%, here, is an arbitrary choice for what's "reasonable"
}

/* A FuzzyBuf is *too* fuzzy if it doesn't have a statistical opinion as to whether some bit should be 0 or 1.
 * A bit balance count of "0" means that the FuzzyBuf has seen equal numbers of 0s and 1s in that position,
 * which leaves it without an opinion as to what that particular bit should be.
 */
static _Bool is_too_fuzzy(pFuzzyBuf pFB) {
    for (__u16 i = 0; i < pFB->len * BITS_PER_BYTE; i++) {
        if (pFB->counts[i] == 0) {
            return 1;
        }
    }
    return 0;
}

/* If a FuzzyBuf is not too fuzzy then it has a guess as to what the buf should actually be.
 * This function writes that guess into the given buf.
 * PRECONDITION: The FuzzyBuf must be known to be "not too fuzzy" (see is_too_fuzzy())
 * REQUIRED: The given buf must have the same byte length as the FuzzyBuf.
 */
static void make_guess(pFuzzyBuf pFB, unsigned char *buf, __u16 len) {
    assert(pFB->len == len);
    unsigned char constructed_byte = 0;
    for (__u16 i = 0; i < pFB->len * BITS_PER_BYTE; i++) {
        assert(pFB->counts[i] != 0);
        constructed_byte += (pFB->counts[i] < 0 ? 0 : 1);
        if (i % BITS_PER_BYTE == BITS_PER_BYTE-1) {
            buf[i/BITS_PER_BYTE] = constructed_byte;
            constructed_byte = 0;
        }
        else {
            constructed_byte = constructed_byte << 1;
        }
    }
#ifdef DEBUG
    dump_buffer(buf, len, "INFERRED");
#endif
}

/* See description in header file.
 */
_Bool attempt_correction(unsigned char *buf, __u16 len) {

    // Create and init an empty list of fuzzy buffs, if one hasn't already been created and init'ed
    if (!all_fuzzy_bufs) {
        all_fuzzy_bufs = malloc(sizeof(cFuzzyBuf));
        NewList(all_fuzzy_bufs, "Fuzzy Bufs");  // This inits the new list.
    }

    // Find a FuzzyBuf that matches the given buf, if one exists
    for (pFuzzyBuf pFB = all_fuzzy_bufs->first; pFB; pFB=pFB->next) {
        if (is_reasonable_match(pFB, buf, len)) {
            adjust_counts(pFB, buf, len);
            if (!is_too_fuzzy(pFB)) {
                make_guess(pFB, buf, len);  // Writes pFB's guess into buf.
                int passed = crc_check(buf, len);  // Is it a good guess?
                return passed;
            }
            else {
                return 0;
            }
        }
    }

    // No reasonable match was found, so create a new FuzzyBuf for given buf
    pFuzzyBuf newFB = malloc(sizeof(cFuzzyBuf));
    newFB->len = len;
    newFB->counts = calloc(len * BITS_PER_BYTE, sizeof(__s16)); // A count for each BIT (8*len)
    adjust_counts(newFB, buf, len);
    AddItem(all_fuzzy_bufs, newFB);

    return 0;
}

#ifdef DEBUG
/* Simulate random bit flips to support development of "repetition error correction"
 */
void simulate_noise(unsigned char *buf, __u16 len) {
    dump_buffer(buf, len, "RECEIVED");
    for (int i = 0; i < max(1, len/32); i++) {
        __u16 rand_byte_pos = rand() % len;
        __u8 rand_bit_pos = rand() % BITS_PER_BYTE;
        buf[rand_byte_pos] ^= (1 << rand_bit_pos);
    }
    dump_buffer(buf, len, "NOISED");
}
#endif
