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

#ifndef W_SCAN2_REPETION_EC_H
#define W_SCAN2_REPETION_EC_H

#include <linux/types.h>

/* Flushes out any accumulated error correction data.
 * Call this after tuning to a new channel since it will be sending unrelated data.
 */
void reset_repetition_ec(void);

/*
 * Give a buffer/length, this function tries to error correct the buffer on the basis of previous data collected.
 * Returns 0 if error correction was not possible.
 * Returns 1 if error correction was possible, with corrected data in buf.
 */
_Bool attempt_correction(unsigned char *buf, __u16 len);

#ifdef DEBUG
/* Use to simulate noise, in the form of random bit flips.
 * Is used during development/testing of repetition_ec.
 */
void simulate_noise(unsigned char *buf, __u16 len);
#endif

#endif //W_SCAN2_REPETION_EC_H
