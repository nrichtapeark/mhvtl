/*
 * SLDC (Streaming Lossless Data Compression)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _SLDC_H_
#define _SLDC_H_

#include "vtllib.h"

size_t sldc_decompress(uint8_t *compressed, size_t compressed_len, uint8_t *uncompressed, size_t uncompressed_len);

#endif /* _SLDC_H_ */
