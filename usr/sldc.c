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
 *
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <strings.h>
#include <syslog.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <ctype.h>
#include <stdbool.h>

#include "mhvtl_list.h"
#include "be_byteshift.h"
#include "vtl_common.h"
#include "mhvtl_scsi.h"
#include "q.h"
#include "logging.h"
#include "vtllib.h"
#include "vtltape.h"
#include "spc.h"
#include "ssc.h"
#include "mhvtl_log.h"
#include "mode.h"
#include "ccan/crc32c/crc32c.h"

#include "sldc.h"

struct history_buffer
{
        uint8_t *buffer;
        size_t pos;
        size_t len;
};

void history_buffer_init(struct history_buffer *history, size_t buffer_len)
{
        history->pos = 0;
        history->buffer = (uint8_t *)malloc(buffer_len);
        history->len = buffer_len;
}

void history_buffer_add(struct history_buffer *history, uint8_t byte)
{
        history->buffer[history->pos] = byte;
        history->pos++;
        history->pos %= history->len;
}

bool history_buffer_get(struct history_buffer *history, size_t offset, uint8_t *result)
{
        if (!result)
                return false;

        if (offset < 0 || offset >= history->len)
        {
                MHVTL_ERR("Bad offset in history_buffer_get: %zu", offset); 
                return false;
        }

        *result = history->buffer[offset % history->len];
        return true;
}

void history_buffer_reset(struct history_buffer *history)
{
        history->pos = 0;
}

void history_buffer_destroy(struct history_buffer *history)
{
    if (history->buffer)
        free(history->buffer);
}

struct bit_buffer
{
        uint8_t *buffer;
        size_t size;
};

void bit_buffer_init(struct bit_buffer *bb, uint8_t *buffer, size_t size)
{
        bb->buffer = buffer;
        bb->size = size * 8;
}

bool bit_buffer_test(struct bit_buffer *bb, size_t offset, uint8_t *result)
{
        if (!result)
                return false;

        if (offset > bb->size)
        {
                MHVTL_ERR("Bad offset in bit_buffer_test: %zu > size %zu", offset, bb->size);
                return false;
        }

        *result = bb->buffer[offset / 8] & (1 << (7 - (offset % 8)));
        return true;
}

bool bit_buffer_get_bits(struct bit_buffer *bb, size_t bit_count, size_t offset, uint8_t *result)
{
        size_t i;

        if (!result)
                return false;

        if (offset + bit_count > bb->size)
        {
                MHVTL_ERR("Bad offset in bit_buffer_get_bits: %zu > size %zu", offset + bit_count, bb->size);
                return false;
        }

        *result = 0;
        for (i = 0; i < bit_count; i++)
        {
                uint8_t test;
                if (!bit_buffer_test(bb, offset + i, &test))
                {
                        MHVTL_ERR("Test error in bit_buffer_get_bits at position %zu", i);
                        return false;
                }

                *result |= (test ? 1 : 0) << (bit_count - 1 - i);
        }

        return true;
}

bool bit_buffer_get_nibble(struct bit_buffer *bb, size_t offset, uint8_t *nibble)
{
        return bit_buffer_get_bits(bb, 4, offset, nibble);
}

bool bit_buffer_get_byte(struct bit_buffer *bb, size_t offset, uint8_t *byte)
{
        size_t byte_offset;
        int result;

        if (!byte)
                return false;

        if (offset + 8 >= bb->size)
        {
                MHVTL_ERR("Bad offset in bit_buffer_get_byte: %zu >= size %zu", offset + 8, bb->size);
                return false;
        }

        byte_offset = offset / 8;
        result = ((bb->buffer[byte_offset] << 8) | bb->buffer[byte_offset + 1]) & 0xFFFF;
        result >>= (8 - (offset % 8));

        *byte = (uint8_t)(result & 0xFF);
        return true;
}

struct byte_array
{
        uint8_t *array;
        size_t size;
        size_t pos;
};

bool byte_buffer_init(struct byte_array *ba, size_t initial_size)
{
        ba->array = (uint8_t *)malloc(initial_size);
        if (!ba->array)
        {
                MHVTL_ERR("Byte array malloc failed for size %zu", initial_size);
                return false;
        }
        ba->size = initial_size;
        ba->pos = 0;

        return true;
}

bool byte_buffer_append(struct byte_array *ba, uint8_t byte)
{
        if (ba->pos >= ba->size)
        {
                size_t new_size = ba->size * 2;

                ba->array = (uint8_t *)realloc(ba->array, new_size);
                if (!ba->array)
                {
                        MHVTL_ERR("Byte array realloc failed for size %zu", new_size);
                        return false;
                }
                ba->size = new_size;
        }

        ba->array[ba->pos] = byte;
        ba->pos++;
        return true;
}

void byte_buffer_destroy(struct byte_array *ba)
{
        if (ba->array)
            free(ba->array);
        
        ba->size = 0;
        ba->pos = 0;
}

struct sldc_buffer
{
        struct history_buffer history;
        struct bit_buffer bitset;
        int state;
        int last_valid_state;
        int displacement_size;
        size_t last_idx;
};

#define CONTROL_SYMBOL_FLUSH        0x00
#define CONTROL_SYMBOL_SCHEME1      0x01
#define CONTROL_SYMBOL_SCHEME2      0x02
#define CONTROL_SYMBOL_FILEMARK     0x03
#define CONTROL_SYMBOL_EOR          0x04
#define CONTROL_SYMBOL_RESET1       0x05
#define CONTROL_SYMBOL_RESET2       0x06
#define CONTROL_SYMBOL_END          0x0F

#define STATE_UNKNOWN   0
#define STATE_SKIP      1
#define STATE_SCHEME1   2
#define STATE_SCHEME2   3
#define STATE_END       4

bool sldc_buffer_init(struct sldc_buffer *sldc, size_t history_buffer_size)
{
        history_buffer_init(&sldc->history, history_buffer_size);
        sldc->state = STATE_UNKNOWN;
        sldc->last_valid_state = STATE_UNKNOWN;
        sldc->last_idx = 0;

        if (history_buffer_size == 1024)
                sldc->displacement_size = 10;
        else if (history_buffer_size == 16*1024)
                sldc->displacement_size = 14;
        else
        {
                MHVTL_ERR("History buffer size %zu not supported yet", history_buffer_size);
                return false;
        }

        return true;
}

bool sldc_buffer_add_byte(struct sldc_buffer *sldc, uint8_t byte, struct byte_array *result)
{
        history_buffer_add(&sldc->history, byte);
        return byte_buffer_append(result, byte);
}


bool sldc_buffer_set_control(struct sldc_buffer *sldc, size_t idx)
{
        uint8_t nibble;

        if (!bit_buffer_get_nibble(&sldc->bitset, idx + 9, &nibble))
                return false;

        switch (nibble)
        {
                case CONTROL_SYMBOL_SCHEME1:
                        sldc->last_valid_state = sldc->state;
                        sldc->state = STATE_SCHEME1;
                        break;
                case CONTROL_SYMBOL_SCHEME2:
                        sldc->last_valid_state = sldc->state;
                        sldc->state = STATE_SCHEME2;
                        break;
                case CONTROL_SYMBOL_RESET1:
                        history_buffer_reset(&sldc->history);
                        sldc->last_valid_state = sldc->state;
                        sldc->state = STATE_SCHEME1;
                        break;
                case CONTROL_SYMBOL_RESET2:
                        history_buffer_reset(&sldc->history);
                        sldc->last_valid_state = sldc->state;
                        sldc->state = STATE_SCHEME2;
                        break;
                case CONTROL_SYMBOL_FILEMARK:
                case CONTROL_SYMBOL_FLUSH:
                        sldc->state = STATE_SKIP;
                        break;
                case CONTROL_SYMBOL_EOR:
                case CONTROL_SYMBOL_END:
                        sldc->state = STATE_END;
                        break;
                default:
                        MHVTL_ERR("Unknown SLDC control symbol %01x at idx %zu (prev state %d, last valid state %d", nibble, idx, sldc->state, sldc->last_valid_state)
                        sldc->state = STATE_SKIP;
                        break;
        }

        return true;
}

bool sldc_buffer_extract(struct sldc_buffer *sldc, uint8_t *compressed, size_t compressed_len, uint8_t *uncompressed, size_t uncompressed_len)
{
        static int match_digits[] = {1, 2, 3, 4, 8};
        static int match_skip[] = {1, 1, 1, 1, 0};

        bool success = false;
        size_t idx;
        struct byte_array results;

        byte_buffer_init(&results, uncompressed_len);

        bit_buffer_init(&sldc->bitset, compressed, compressed_len);
        history_buffer_reset(&sldc->history);

        idx = sldc->last_idx;
        while (idx < sldc->bitset.size)
        {
                if (idx >= sldc->bitset.size - 8 || sldc->state == STATE_END)
                {
                        if (sldc->state != STATE_END && sldc->state != STATE_SKIP)
                        {
                                MHVTL_ERR("Went too far %zu, lim=%zu, state=%d", idx, sldc->bitset.size, sldc->state);
                                goto cleanup;
                        }

                        break;
                }

                uint8_t byte;
                if (!bit_buffer_get_byte(&sldc->bitset, idx, &byte))
                        goto cleanup;

                uint8_t test;
                if (!bit_buffer_test(&sldc->bitset, idx+8, &test))
                        goto cleanup;

                if (byte == 0xFF && test)
                {
                        if (!sldc_buffer_set_control(sldc, idx))
                                goto cleanup;
                        idx += 13;
                }
                else
                {
                        if (sldc->state == STATE_SCHEME1)
                        {
                                uint8_t bit;
                                if (!bit_buffer_test(&sldc->bitset, idx, &bit))
                                        goto cleanup;

                                if (bit == 0)
                                {
                                        /* raw byte */
                                        uint8_t raw_byte;
                                        if (!bit_buffer_get_byte(&sldc->bitset, idx + 1, &raw_byte))
                                                goto cleanup;
                                        if (!sldc_buffer_add_byte(sldc, raw_byte, &results))
                                                goto cleanup;
                                        idx += 9;
                                }
                                else
                                {

                                }
                        }
                }
        }

        success = true;
cleanup:
        byte_buffer_destroy(&results); 
        return success;
}

void sldc_destroy(struct sldc_buffer *sldc)
{
        history_buffer_destroy(&sldc->history);
}
