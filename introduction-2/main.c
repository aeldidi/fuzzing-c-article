#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.c"
#include "utf8.c"

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
int
alloc_valid_utf8(struct fuzz* f, void* env, void** instance)
{
	size_t   len    = fuzz_random_range(f, 1, UINT16_MAX);
	uint8_t* result = calloc(len + 1, 1);
	if (result == NULL) {
		return FUZZ_RESULT_ERROR;
	}

	size_t i = 0;
	while (i < len) {
		size_t codepoint_size = fuzz_random_range(f, 1, 4);
		size_t remaining_size = len - i;
		if (codepoint_size > remaining_size) {
			codepoint_size = remaining_size;
		}

		switch (codepoint_size) {
		case 1:
			result[i] = fuzz_random_range(f, 0, 0x7f);
			break;
		case 2:
			result[i]     = fuzz_random_range(f, 0xc2, 0xdf);
			result[i + 1] = fuzz_random_range(f, 0x80, 0xbf);
			break;
		case 3:
			result[i]     = fuzz_random_range(f, 0xe0, 0xef);
			result[i + 1] = fuzz_random_range(f, 0x80, 0xbf);
			if (result[i] == 0xe0) {
				result[i + 1] = fuzz_random_range(
						f, 0xa0, 0xbf);
			} else if (result[i] == 0xed) {
				result[i + 1] = fuzz_random_range(
						f, 0x80, 0x9f);
			}

			result[i + 2] = fuzz_random_range(f, 0x80, 0xbf);
			break;
		case 4:
			result[i]     = fuzz_random_range(f, 0xf0, 0xf4);
			result[i + 1] = fuzz_random_range(f, 0x80, 0xbf);
			if (result[i] == 0xf0) {
				result[i + 1] = fuzz_random_range(
						f, 0x90, 0xbf);
			} else if (result[i] == 0xf4) {
				result[i + 1] = fuzz_random_range(
						f, 0x80, 0x8f);
			}

			result[i + 2] = fuzz_random_range(f, 0x80, 0xbf);
			result[i + 3] = fuzz_random_range(f, 0x80, 0xbf);
			break;
		default:
			return FUZZ_RESULT_ERROR;
		}

		i += codepoint_size;
	}

	*instance = (void*)result;
	return FUZZ_RESULT_OK;
}

// The property to be tested
int
valid_utf8_should_be_detected(struct fuzz* f, void* arg)
{
	uint8_t* buf     = arg;
	size_t   buf_len = strlen((char*)arg);

	if (utf8_valid(buf_len, buf)) {
		return FUZZ_RESULT_OK;
	}

	return FUZZ_RESULT_FAIL;
}

int
main()
{
	// Copy the builtin type info for uint8 arrays
	struct fuzz_type_info valid_utf8_type_info =
			*fuzz_get_builtin_type_info(
					FUZZ_BUILTIN_uint8_t_ARRAY);
	// But change the alloc callback.
	valid_utf8_type_info.alloc = alloc_valid_utf8;

	uint64_t corpus[] = {
			0x00a600d64b175eed,
	};

	struct fuzz_run_config config = {
			.name      = "valid UTF-8 is valid",
			.prop1     = valid_utf8_should_be_detected,
			.type_info = {&valid_utf8_type_info},

			.always_seeds      = corpus,
			.always_seed_count = sizeof(corpus) / sizeof(*corpus),

			// Stop after the first failure.
			.hooks.pre_trial = fuzz_hook_first_fail_halt,
	};

	return fuzz_run(&config);
}
