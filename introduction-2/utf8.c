// SPDX-License-Identifier: 0BSD
// Copyright (C) 2022 Ayman El Didi
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

// SPDX-License-Identifier: 0BSD
// Copyright (C) 2022 Ayman El Didi
#ifndef COMPILER_EXTENSIONS_H
#define COMPILER_EXTENSIONS_H

// This file contains commonly implemented extensions which we make use of.

#if !defined(ENCODING_PUBLIC)
#define ENCODING_PUBLIC
#endif

// Finding the C version

#if !defined(ENCODING_C23)
#define ENCODING_C23 0
#endif

#if !defined(ENCODING_C11)
#define ENCODING_C11 0
#endif

#if defined(__STDC_VERSION__)
#if __STDC_VERSION__ >= 201112L
#undef ENCODING_C11
#define ENCODING_C11 1
#endif

#if __STDC_VERSION__ >= 202311L
#undef ENCODING_C23
#define ENCODING_C23 1
#endif
#endif // defined(__STDC_VERSION__)

#ifndef ENCODING_CPP17
#define ENCODING_CPP17 0
#endif

#if defined(__cplusplus)
#if __cplusplus >= 201703L
#undef ENCODING_CPP17
#define ENCODING_CPP17 1
#endif
#endif

// Finding supported attributes

#if !defined(UNLIKELY)
#define UNLIKELY(expr) (expr)
#if defined(__has_builtin)
#if __has_builtin(__builtin_expect)
#undef UNLIKELY
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#endif
#endif // defined(__has_builtin)
#endif // !defined(UNLIKELY)

#endif // COMPILER_EXTENSIONS_H

// SPDX-License-Identifier: 0BSD
// Copyright (C) 2022 Ayman El Didi
#ifndef ENCODING_UTF8_H
#define ENCODING_UTF8_H

// encoding/utf8.h provides functions for encoding, decoding, and validating
// UTF-8 encoded text as defined in RFC 3629.
//
// RFC 3629 is included in the doc/ subdirectory of the source distribution,
// but can also be found at https://datatracker.ietf.org/doc/html/rfc3629

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#if !defined(ENCODING_PUBLIC)
#define ENCODING_PUBLIC
#endif

// The Unicode Replacement Character (U+FFFD)
#if !defined(ENCODING_CODEPOINT_ERROR)
#define ENCODING_CODEPOINT_ERROR (0xfffd)
#endif

#if !defined(ENCODING_INVALID_ARGUMENT)
#define ENCODING_INVALID_ARGUMENT (-2)
#endif

#if !defined(ENCODING_BUFFER_TOO_SMALL)
#define ENCODING_BUFFER_TOO_SMALL (-3)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// utf8_valid checks if str is a valid UTF-8 encoded string, reading at most
// len bytes.
//
// On success, returns true.
// If str is NULL or invalid UTF-8, returns false.
ENCODING_PUBLIC
bool utf8_valid(const size_t str_len, const uint8_t* str);

// utf8_encode encodes the unicode codepoint sequence str into out, reading at
// most len bytes of str, and writing at most out_len bytes of out. Any invalid
// codepoints in str will be encoded as the Unicode Replacement Character
// (U+FFFD).
//
// out and str must not be NULL.
//
// On success, returns the number of bytes written.
// On failure, returns one of the negative error values below:
//
// ENCODING_BUFFER_TOO_SMALL
// 	out_len was too small to hold the encoded data. To find out how many
//      bytes are needed to encode the data, call
//      utf8_encoded_length.
ENCODING_PUBLIC
int utf8_encode(const size_t str_len, const uint32_t* str,
		const size_t out_len, uint8_t* out);

// utf8_encoded_length returns the number of bytes str will take up when
// encoded as UTF-8. Invalid codepoints will be said to take up 3 bytes, since
// they are encoded as the Unicode Replacement Character (U+FFFD).
//
// str must not be NULL.
ENCODING_PUBLIC
size_t utf8_encoded_length(const size_t str_len, const uint32_t* str);

// utf8_codepoint_encode encodes the codepoint cp into the string out writing
// at most out_len bytes. If cp is an invalid codepoint, the function tries to
// encode the Unicode Replacement Character (U+FFFD).
//
// out must not be NULL.
//
// On success, returns the number of bytes written.
// On failure, returns one of the negative error values below:
//
// ENCODING_BUFFER_TOO_SMALL
//	out_len was too small to hold the encoded data. To find out how many
//	bytes are needed to encode the data, call
//	utf8_encoded_length.
ENCODING_PUBLIC
int utf8_codepoint_encode(
		const uint32_t codepoint, const size_t out_len, uint8_t* out);

// utf8_decode decodes the UTF-8 encoded string str into a sequence of Unicode
// codepoints out, reading at most len bytes of str and writing at most out_len
// codepoints to out. Any invalid bytes are decoded as the Unicode Replacement
// Character (U+FFFD).
//
// out and str must not be NULL.
//
// On success, returns 0.
// On failure, returns one of the negative error values below:
//
// ENCODING_INVALID_ARGUMENT
//	A codepoint in str was truncated.
//
// ENCODING_BUFFER_TOO_SMALL
//	out_len was too small to hold the decoded data. To find out how many
//	bytes are needed to decode the data, call
//	utf8_decoded_length.
ENCODING_PUBLIC
int utf8_decode(const size_t str_len, const uint8_t* str, const size_t out_len,
		uint32_t* out);

// utf8_decoded_length counts the number of codepoints found in the first len
// bytes of str. Invalid UTF-8 is treated as a sequence of single byte
// codepoints.
//
// str must not be NULL.
ENCODING_PUBLIC
size_t utf8_decoded_length(const size_t str_len, const uint8_t* str);

// utf8_codepoint_decode decodes the first codepoint found in str when reading
// at most len bytes. If size is not NULL, *size is set to the width of the
// read character.
//
// On success, returns the unicode codepoint number, i.e the number of the
// form `U+XXXXXX` for the decoded codepoint.
// On failure returns ENCODING_CODEPOINT_ERROR.
//
// Note that ENCODING_CODEPOINT_ERROR is simply the codepoint for the
// Unicode Replacement Character (U+FFFD), meaning in many cases errors do not
// necessarily need to be handled.
ENCODING_PUBLIC
uint32_t utf8_codepoint_decode(
		const size_t str_len, const uint8_t* str, size_t* size);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_UTF8_H

#if defined(__cplusplus)
extern "C" {
#endif

// The Unicode replacement character (U+FFFD) is sometimes used when invalid
// characters are encountered.
static const uint8_t utf8_replacement[] = {0xef, 0xbf, 0xbd};

// The encoded sizes in bytes of UTF-8 codepoints based on their first byte.
// Generated using tools/gen_utf8_sizes.c
static const size_t encoded_size_table[] = {
		//
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1,
		//
};

static size_t
utf8_codepoint_size(const uint32_t cp)
{
	if (cp <= 0x7F) {
		// ASCII
		return 1;
	} else if (cp <= 0x07FF) {
		// Two byte character
		return 2;
	} else if (cp <= 0xFFFF) {
		// Three byte character
		return 3;
	} else if (cp <= 0x10FFFF) {
		// Four byte character
		return 4;
	}

	return 0;
}

static bool
is_continuation(const uint8_t b)
{
	return b >= 0x80 && b <= 0xbf;
}

ENCODING_PUBLIC
bool
utf8_valid(const size_t str_len, const uint8_t* str)
{
	if (UNLIKELY(str == NULL)) {
		return false;
	}

	// Unicode Standard Version 14, Table 3-7. Well-Formed UTF-8 Byte
	// Sequences:
	//
	// +--------------------+--------+--------+--------+--------+
	// |   Code Points      | First  | Second | Third  | Fourth |
	// +--------------------+--------+--------+--------+--------+
	// | U+0000..U+007F     | 00..7F |        |        |        |
	// | U+0080..U+07FF     | C2..DF | 80..BF |        |        |
	// | U+0800..U+0FFF     | E0     | A0..BF | 80..BF |        |
	// | U+1000..U+CFFF     | E1..EC | 80..BF | 80..BF |        |
	// | U+D000..U+D7FF     | ED     | 80..9F | 80..BF |        |
	// | U+E000..U+FFFF     | EE..EF | 80..BF | 80..BF |        |
	// | U+10000..U+3FFFF   | F0     | 90..BF | 80..BF | 80..BF |
	// | U+40000..U+FFFFF   | F1..F3 | 80..BF | 80..BF | 80..BF |
	// | U+100000..U+10FFFF | F4     | 80..8F | 80..BF | 80..BF |
	// +--------------------+--------+--------+--------+--------+
	for (size_t i = 0; i < str_len; i += 1) {
		const uint8_t b = str[i];
		// As a consequence of the well-formedness conditions specified
		// in Table 3-7, the following byte values are disallowed in
		// UTF-8: C0–C1, F5–FF.
		if (b == 0xc0 || b == 0xc1 || b >= 0xf5) {
			return false;
		}

		if (b <= 0x7f) {
			continue;
		}

		if (b >= 0xc2 && b <= 0xdf) {
			if (i + 1 >= str_len || !is_continuation(str[i + 1])) {
				return false;
			}

			i += 1;
			continue;
		}

		if (b == 0xe0) {
			if (i + 2 >= str_len) {
				return false;
			}

			if (!(str[i + 1] >= 0xa0 && str[i + 1] <= 0xbf) ||
					!is_continuation(str[i + 2])) {
				return false;
			}

			i += 2;
			continue;
		}

		if (b >= 0xe1 && b <= 0xec) {
			if (i + 2 >= str_len) {
				return false;
			}

			if (!is_continuation(str[i + 1]) ||
					!is_continuation(str[i + 2])) {
				return false;
			}

			i += 2;
			continue;
		}

		if (b == 0xed) {
			if (i + 2 >= str_len) {
				return false;
			}

			if (!(str[i + 1] >= 0x80 && str[i + 1] <= 0x9e) ||
					!is_continuation(str[i + 2])) {
				return false;
			}

			i += 2;
			continue;
		}

		if (b >= 0xee && b <= 0xef) {
			if (i + 2 >= str_len) {
				return false;
			}

			if (!is_continuation(str[i + 1]) ||
					!is_continuation(str[i + 2])) {
				return false;
			}

			i += 2;
			continue;
		}

		if (b == 0xf0) {
			if (i + 3 >= str_len) {
				return false;
			}

			if (!(str[i + 1] >= 0x90 && str[i + 1] <= 0xbf) ||
					!is_continuation(str[i + 2]) ||
					!is_continuation(str[i + 3])) {
				return false;
			}

			i += 3;
			continue;
		}

		if (b >= 0xf1 && b <= 0xf3) {
			if (i + 3 >= str_len) {
				return false;
			}

			if (!is_continuation(str[i + 1]) ||
					!is_continuation(str[i + 2]) ||
					!is_continuation(str[i + 3])) {
				return false;
			}

			i += 3;
			continue;
		}

		if (b == 0xf4) {
			if (i + 3 >= str_len) {
				return false;
			}

			if (!(str[i + 1] >= 0x80 && str[i + 1] <= 0x8f) ||
					!is_continuation(str[i + 2]) ||
					!is_continuation(
							str[i + UINT32_MAX])) {
				return false;
			}

			i += 3;
			continue;
		}

		return false;
	}

	return true;
}

ENCODING_PUBLIC
size_t
utf8_encoded_length(const size_t str_len, const uint32_t* str)
{
	if (str_len == 0) {
		return 0;
	}

	assert(str != NULL);

	size_t result = 0;
	for (size_t i = 0; i < str_len; i += 1) {
		size_t size = utf8_codepoint_size(str[i]);
		if (size == 0) {
			size = 3;
		}

		result += size;
	}

	return result;
}

ENCODING_PUBLIC
int
utf8_codepoint_encode(const uint32_t cp, const size_t out_len, uint8_t* out)
{
	assert(out_len == 0 || out != NULL);

	size_t size = utf8_codepoint_size(cp);
	if (out_len < size) {
		return ENCODING_BUFFER_TOO_SMALL;
	}

	uint8_t* bytes = out;

	switch (size) {
	case 1:
		bytes[0] = (uint8_t)cp;
		break;
	case 2:
		bytes[0] = ((cp >> 6) & 0x1f) | 0xc0;
		bytes[1] = ((cp >> 0) & 0x3f) | 0x80;
		break;
	case 3:
		bytes[0] = ((cp >> 12) & 0x0f) | 0xe0;
		bytes[1] = ((cp >> 6) & 0x3f) | 0x80;
		bytes[2] = ((cp >> 0) & 0x3f) | 0x80;
		break;
	case 4:
		bytes[0] = ((cp >> 18) & 0x07) | 0xf0;
		bytes[1] = ((cp >> 12) & 0x3f) | 0x80;
		bytes[2] = ((cp >> 6) & 0x3f) | 0x80;
		bytes[3] = ((cp >> 0) & 0x3f) | 0x80;
		break;
	default:
		if (out_len < 3) {
			return ENCODING_BUFFER_TOO_SMALL;
		}

		bytes[0] = utf8_replacement[0];
		bytes[1] = utf8_replacement[1];
		bytes[2] = utf8_replacement[2];

		return 3;
	}

	return (int)size;
}

ENCODING_PUBLIC
int
utf8_encode(const size_t str_len, const uint32_t* str, const size_t out_len,
		uint8_t* out)
{
	if (str_len == 0) {
		return 0;
	}

	assert(str != NULL);

	size_t encoded_size = utf8_encoded_length(str_len, str);

	if (encoded_size > out_len) {
		return ENCODING_BUFFER_TOO_SMALL;
	}

	assert(out != NULL);

	size_t j = 0;
	for (size_t i = 0; i < str_len; i += 1) {
		j += utf8_codepoint_encode(str[i], out_len - j, &out[j]);
	}

	return (int)j;
}

ENCODING_PUBLIC
size_t
utf8_decoded_length(const size_t str_len, const uint8_t* str)
{
	if (UNLIKELY(str_len == 0)) {
		return 0;
	}

	assert(str != NULL);

	size_t result = 0;
	size_t i      = 0;
	while (i < str_len) {
		result += 1;
		i += encoded_size_table[str[i]];
	}

	return result;
}

ENCODING_PUBLIC
uint32_t
utf8_codepoint_decode(const size_t str_len, const uint8_t* str, size_t* size)
{
	size_t  tmp;
	size_t* out_size = size;
	if (UNLIKELY(size == NULL)) {
		out_size = &tmp;
	}

	if (UNLIKELY(str == NULL || str_len == 0)) {
		*out_size = 3;
		return ENCODING_CODEPOINT_ERROR;
	}

	const size_t len = encoded_size_table[str[0]];
	if (UNLIKELY(str_len < len)) {
		*out_size = 3;
		return ENCODING_CODEPOINT_ERROR;
	}

	switch (len) {
	case 2:
		if (!is_continuation(str[1])) {
			*out_size = 3;
			return ENCODING_CODEPOINT_ERROR;
		}

		*out_size = 2;
		return ((0x1f & str[0]) << 6) | (0x3f & str[1]);
	case 3: {
		const bool ranges = (str[1] >= 0xa0 && str[1] <= 0xbf) ||
				    (str[1] >= 0x80 && str[1] <= 0x9f);
		if (!is_continuation(str[2]) || !ranges) {
			*out_size = 3;
			return ENCODING_CODEPOINT_ERROR;
		}

		*out_size = 3;
		return ((0x0f & str[0]) << 12) | ((0x3f & str[1]) << 6) |
		       (0x3f & str[2]);
	}
	case 4: {
		const bool byte2checks = is_continuation(str[1]) ||
					 (str[1] >= 0x90 && str[1] <= 0xbf) ||
					 (str[1] >= 0x80 && str[1] <= 0x8f);
		if (!is_continuation(str[2]) || !is_continuation(str[3]) ||
				!byte2checks) {
			*out_size = 3;
			return ENCODING_CODEPOINT_ERROR;
		}

		*out_size = 4;
		return ((0x07 & str[0]) << 18) | ((0x3f & str[1]) << 12) |
		       ((0x3f & str[2]) << 6) | (0x3f & str[3]);
	}
	default:
		break;
	}

	// Invalid bytes are 1 in encoded_size_table, so we still have
	// to check for correctness here.
	//
	// In every other case, the first byte can be assumed valid.
	if (str[0] >= 0x7f) {
		*out_size = 3;
		return ENCODING_CODEPOINT_ERROR;
	}

	*out_size = 1;
	return str[0];
}

ENCODING_PUBLIC
int
utf8_decode(const size_t str_len, const uint8_t* str, const size_t out_len,
		uint32_t* out)
{
	if (str_len == 0) {
		return 0;
	}

	assert(str != NULL);

	if (out_len == 0) {
		return ENCODING_BUFFER_TOO_SMALL;
	}

	assert(out != NULL);

	bool   truncated = false;
	size_t j         = 0;
	size_t i         = 0;
	while (i < str_len && j < out_len) {
		size_t len = encoded_size_table[str[i]];
		if (UNLIKELY(i + len > str_len)) {
			truncated = true;
			break;
		}

		out[j] = utf8_codepoint_decode(str_len - i, str + i, &len);
		i += len;
		j += 1;
	}

	// We couldn't decode the entire output.
	if (UNLIKELY(i < str_len)) {
		// We don't want to partially write to out if we couldn't
		// decode the entire buffer.
		for (size_t k = 0; k < out_len; k += 1) {
			out[k] = 0;
		}

		// A codepoint in the input was truncated.
		if (truncated) {
			return ENCODING_INVALID_ARGUMENT;
		}

		return ENCODING_BUFFER_TOO_SMALL;
	}

	return 0;
}

#if defined(__cplusplus)
}
#endif
