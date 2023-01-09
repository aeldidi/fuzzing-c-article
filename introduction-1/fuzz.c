// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_AUTOSHRINK_H
#define FUZZ_AUTOSHRINK_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct fuzz;
struct fuzz_type_info;

#define AUTOSHRINK_ENV_TAG      0xa5
#define AUTOSHRINK_BIT_POOL_TAG 'B'

struct autoshrink_bit_pool {
	// Bits will always be rounded up to a multiple of 64 bits,
	// and be aligned as a uint64_t.
	uint8_t* bits;
	bool     shrinking;   // is this pool shrinking?
	size_t   bits_filled; // how many bits are available
	size_t   bits_ceil;   // ceiling for bit buffer
	size_t   limit;       // after limit bytes, return 0

	size_t    consumed;
	size_t    request_count;
	size_t    request_ceil;
	uint32_t* requests;

	size_t  generation;
	size_t* index;
};

// How large should the default autoshrink bit pool be?
// The pool will be filled and grown on demand, but an
// excessively small initial pool will lead to several
// reallocs in quick succession.
#define DEF_POOL_SIZE (64 * 8 * sizeof(uint64_t))

// How large should the buffer for request sizes be by default?
#define DEF_REQUESTS_CEIL2 4 // constrain to a power of 2
#define DEF_REQUESTS_CEIL  (1 << DEF_REQUESTS_CEIL2)

// Default: Decide we've reached a local minimum after
// this many unsuccessful shrinks in a row.
#define DEF_MAX_FAILED_SHRINKS 100

// When attempting to drop records, default to odds of
// (1+DEF_DROP_THRESHOLD) in (1 << DEF_DROP_BITS).
#define DEF_DROP_THRESHOLD 0
#define DEF_DROP_BITS      5

// Max number of pooled random bits to give to alloc callback
// before returning 0 forever. Default: No limit.
#define DEF_POOL_LIMIT ULLONG_MAX

// Magic value to disable selecting a request to drop in
// drop_from_bit_pool, because it complicates tests.
#define DO_NOT_DROP (0xFFFFFFFFLU)

typedef uint64_t autoshrink_prng_fun(uint8_t bits, void* udata);

#define TWO_EVENLY  0x80
#define FOUR_EVENLY 0x40
#define MODEL_MIN   0x08
#define MODEL_MAX   0x80

#define DROPS_MIN 0x10
#define DROPS_MAX 0xA0

enum autoshrink_action {
	ASA_DROP  = 0x01,
	ASA_SHIFT = 0x02,
	ASA_MASK  = 0x04,
	ASA_SWAP  = 0x08,
	ASA_SUB   = 0x10,
};

enum autoshrink_weight {
	WEIGHT_DROP  = 0x00,
	WEIGHT_SHIFT = 0x01,
	WEIGHT_MASK  = 0x02,
	WEIGHT_SWAP  = 0x03,
	WEIGHT_SUB   = 0x04,
};

struct autoshrink_model {
	enum autoshrink_action cur_tried;
	enum autoshrink_action cur_set;
	enum autoshrink_action next_action;
	uint8_t                weights[5];
};

struct autoshrink_env {
	// config
	uint8_t  arg_i;
	size_t   pool_size;
	size_t   pool_limit;
	int      print_mode;
	size_t   max_failed_shrinks;
	uint64_t drop_threshold;
	uint8_t  drop_bits;

	struct autoshrink_model     model;
	struct autoshrink_bit_pool* bit_pool;

	// allow injecting a fake prng, for testing
	bool                 leave_trailing_zeroes;
	autoshrink_prng_fun* prng;
	void*                udata;
};

enum mutation {
	MUT_SHIFT,
	MUT_MASK,
	MUT_SWAP,
	MUT_SUB,
};
#define LAST_MUTATION      MUT_SUB
#define MUTATION_TYPE_BITS 2

struct change_info {
	enum mutation t;
	size_t        pos;
	uint32_t      size;
	union {
		uint8_t  shift;
		uint64_t mask;
		uint64_t and;
		uint64_t sub;
		uint8_t  swap_unused;
	} u;
};

struct autoshrink_env* fuzz_autoshrink_alloc_env(struct fuzz* t, uint8_t arg_i,
		const struct fuzz_type_info* type_info);

void fuzz_autoshrink_free_env(struct fuzz* t, struct autoshrink_env* env);

enum fuzz_autoshrink_wrap {
	FUZZ_AUTOSHRINK_WRAP_OK,
	FUZZ_AUTOSHRINK_WRAP_ERROR_MEMORY = -1,
	FUZZ_AUTOSHRINK_WRAP_ERROR_MISUSE = -2,
};
enum fuzz_autoshrink_wrap fuzz_autoshrink_wrap(struct fuzz* t,
		struct fuzz_type_info*                      type_info,
		struct fuzz_type_info*                      wrapper);

void fuzz_autoshrink_free_bit_pool(
		struct fuzz* t, struct autoshrink_bit_pool* pool);

void fuzz_autoshrink_bit_pool_random(struct fuzz* t,
		struct autoshrink_bit_pool* pool, uint32_t bit_count,
		bool save_request, uint64_t* buf);

void fuzz_autoshrink_get_real_args(struct fuzz* t, void** dst, void** src);

void fuzz_autoshrink_update_model(
		struct fuzz* t, uint8_t arg_id, int res, uint8_t adjustment);

// Alloc callback, with autoshrink_env passed along.
int fuzz_autoshrink_alloc(
		struct fuzz* t, struct autoshrink_env* env, void** instance);

uint64_t fuzz_autoshrink_hash(struct fuzz* t, const void* instance,
		struct autoshrink_env* env, void* type_env);

void fuzz_autoshrink_print(struct fuzz* t, FILE* f, struct autoshrink_env* env,
		const void* instance, void* type_env);

int fuzz_autoshrink_shrink(struct fuzz* t, struct autoshrink_env* env,
		uint32_t tactic, void** output,
		struct autoshrink_bit_pool** output_bit_pool);

// This is only exported for testing.
void fuzz_autoshrink_dump_bit_pool(FILE* f, size_t bit_count,
		const struct autoshrink_bit_pool* pool, int print_mode);

// Set the next action the model will deliver. (This is a hook for testing.)
void fuzz_autoshrink_model_set_next(
		struct autoshrink_env* env, enum autoshrink_action action);

#endif

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_H
#define FUZZ_H

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

#if !defined(FUZZ_PUBLIC)
#define FUZZ_PUBLIC
#endif

#if !defined(FUZZ_USE_FLOATING_POINT)
#define FUZZ_USE_FLOATING_POINT 1
#endif

// Version 1.0.0
#define FUZZ_VERSION_MAJOR 1
#define FUZZ_VERSION_MINOR 0
#define FUZZ_VERSION_PATCH 0

// Opaque handle struct for a fuzz property-test runner.
struct fuzz;

// Overall trial pass/fail/skip/duplicate counts after a run.
struct fuzz_run_report {
	size_t pass;
	size_t fail;
	size_t skip;
	size_t dup;
};

#define FUZZ_RESULT_OK        (0) // No failure
#define FUZZ_RESULT_FAIL      (1) // 1 or more failures
#define FUZZ_RESULT_SKIP      (2)
#define FUZZ_RESULT_DUPLICATE (3) // Skipped because this was already done

#define FUZZ_RESULT_ERROR_MEMORY (-1) // Memory allocation failure
#define FUZZ_RESULT_ERROR        (-2)

// Default number of trials to run.
#define FUZZ_DEF_TRIALS 100

// Default number of columns after which `fuzz_print_trial_result` should
// wrap.
#define FUZZ_DEF_MAX_COLUMNS 72

// A property can have at most this many arguments.
#define FUZZ_MAX_ARITY 7

// For worker processes that were sent a timeout signal, how long should they
// be given to terminate and exit before sending kill(pid, SIGKILL).
#define FUZZ_DEF_EXIT_TIMEOUT_MSEC 100

// This struct contains callbacks used to specify how to allocate, free, hash,
// print, and/or shrink the property test input.
//
// Only `alloc` is required, though `free` is strongly recommended.
struct fuzz_type_info; // (forward reference)

// Attempt to shrink an instance to a simpler instance.
//
// For a given INSTANCE, there are likely to be multiple ways in which it can
// be simplified. For example, a list of unsigned ints could have the first
// element decremented, divided by 2, or dropped. This callback should write a
// pointer to a freshly allocated, simplified instance in *output, or should
// return FUZZ_SHRINK_DEAD_END to indicate that the instance cannot be
// simplified further by this method.
//
// These tactics will be lazily explored breadth-first, to try to find simpler
// versions of arguments that cause the property to no longer hold.
//
// If there are no other tactics to try for this instance, then return
// FUZZ_SHRINK_NO_MORE_TACTICS. Otherwise, fuzz will keep calling the
// callback with successive tactics.
//
// If this callback is NULL, it is equivalent to always returning
// FUZZ_SHRINK_NO_MORE_TACTICS.
#define FUZZ_SHRINK_OK              (0)
#define FUZZ_SHRINK_DEAD_END        (1)
#define FUZZ_SHRINK_NO_MORE_TACTICS (2)
#define FUZZ_SHRINK_ERROR           (3)

#define FUZZ_HOOK_RUN_ERROR    (0)
#define FUZZ_HOOK_RUN_CONTINUE (1)
// Don't run any more trials (e.g. stop after N failures).
#define FUZZ_HOOK_RUN_HALT        (2)
#define FUZZ_HOOK_RUN_REPEAT      (2) // repeat with the same arguments
#define FUZZ_HOOK_RUN_REPEAT_ONCE (3) // Same as REPEAT, but only once

// When printing an autoshrink bit pool, should just the user's print callback
// be used (if available), or should it also print the raw bit pool and/or the
// request sizes and values?
enum fuzz_autoshrink_print_mode {
	FUZZ_AUTOSHRINK_PRINT_DEFAULT  = 0x00,
	FUZZ_AUTOSHRINK_PRINT_USER     = 0x01,
	FUZZ_AUTOSHRINK_PRINT_BIT_POOL = 0x02,
	FUZZ_AUTOSHRINK_PRINT_REQUESTS = 0x04,
	FUZZ_AUTOSHRINK_PRINT_ALL      = 0x07,
};

// Configuration for autoshrinking.
// For all of these fields, leaving them as 0 will use the default.
struct fuzz_autoshrink_config {
	bool enable; // true: Enable autoshrinking
	// Initial allocation size (default: DEF_POOL_SIZE).
	// When generating very complex instances, this may need to be
	// increased.
	size_t                          pool_size;
	enum fuzz_autoshrink_print_mode print_mode;

	// How many unsuccessful shrinking attempts to try in a row before
	// deciding a local minimum has been reached.
	// Default: DEF_MAX_FAILED_SHRINKS.
	size_t max_failed_shrinks;
};

// Callbacks used for testing with random instances of a type.
// For more information, see comments on their typedefs.
struct fuzz_type_info {
	// Allocate and return an instance of the type, based on a
	// pseudo-random number stream with a known seed. To get random
	// numbers, use `fuzz_random_bits(t, bit_count)` or
	// `fuzz_random_bits_bulk(t, bit_count, buffer)`. This stream of
	// numbers will be deterministic, so if the alloc callback is
	// constructed appropriately, an identical instance can be constructed
	// later from the same initial seed and environment.
	//
	// The allocated instance should be written into *output.
	//
	// If autoshrinking is used, then alloc has an additional requirement:
	// getting smaller values from `fuzz_random_bits` should correspond to
	// simpler instances. In particular, if `fuzz_random_bits` returns 0
	// forever, alloc must generate a minimal instance.
	int (*alloc)(struct fuzz* t, void* env, void** output);

	// Optional, but recommended:
	void (*free)(void* instance, void* env);           // free an instance
	uint64_t (*hash)(const void* instance, void* env); // instance -> hash
	void (*print)(FILE* f, const void* instance,
			void* env); // fprintf instance
	// shrink instance, if autoshrinking is not in use
	int (*shrink)(struct fuzz* t, const void* instance, uint32_t tactic,
			void* env, void** output);

	struct fuzz_autoshrink_config autoshrink_config;

	// Optional environment, passed to the callbacks above. This is
	// completely opaque to fuzz.
	void* env;
};

// Much of fuzz's runtime behavior can be customized using hooks. The
// hook functions all take a pointer to a fuzz_hook_*_info struct as the first
// parameter and a pointer to the env (as a `void*`) for the second parameter.
//
// For example, a pre-run hook function would have the following signature:
//
// ```
// int example(struct fuzz_pre_run_info* info, void* env);
// ```
//
// In all cases, returning `FUZZ_HOOK_RUN_ERROR` will cause fuzz to
// halt everything, clean up, and return `FUZZ_RESULT_ERROR`.

// Pre-run hook: called before the start of a run (group of trials).
// Returns FUZZ_HOOK_RUN_ERROR    if there was an error, or
//         FUZZ_HOOK_RUN_CONTINUE if the trial may continue.
struct fuzz_pre_run_info {
	const char* prop_name;
	size_t      total_trials; // total number of trials
	uint64_t    run_seed;
};

// The default pre-run hook. Calls `fuzz_print_pre_run_info` and returns
// FUZZ_HOOK_RUN_CONTINUE.
FUZZ_PUBLIC
int fuzz_pre_run_hook_print_info(
		const struct fuzz_pre_run_info* info, void* env);

// Post-run hook: called after the whole run has completed, with overall
// results.
// Returns FUZZ_HOOK_RUN_ERROR    if there was an error, or
//         FUZZ_HOOK_RUN_CONTINUE if there was no error.
struct fuzz_post_run_info {
	const char*            prop_name;
	size_t                 total_trials;
	uint64_t               run_seed;
	struct fuzz_run_report report;
};

// The default post-run hook. Calls `fuzz_print_post_run_info` and returns
// FUZZ_HOOK_RUN_CONTINUE.
FUZZ_PUBLIC
int fuzz_post_run_hook_print_info(
		const struct fuzz_post_run_info* info, void* env);

// Pre-argument generation hook: called before an individual trial's
// argument(s) are generated.
// Returns FUZZ_HOOK_RUN_ERROR    if there was an error, or
//         FUZZ_HOOK_RUN_CONTINUE if the trial may continue.
struct fuzz_pre_gen_args_info {
	const char* prop_name;
	size_t      total_trials;
	size_t      trial_id;
	size_t      failures; // failures so far
	uint64_t    run_seed;
	uint64_t    trial_seed;
	uint8_t     arity;
};

// Pre-trial hook: called before running the trial, with the initially
// generated argument(s).
// Returns FUZZ_HOOK_RUN_ERROR    if there was an error,
//         FUZZ_HOOK_RUN_CONTINUE if the trial may continue, or
//         FUZZ_HOOK_RUN_HALT     if no more trials must be ran.
struct fuzz_pre_trial_info {
	const char* prop_name;
	size_t      total_trials;
	size_t      trial_id;
	size_t      failures;
	uint64_t    run_seed;
	uint64_t    trial_seed;
	uint8_t     arity;
	void**      args;
};

// Post-fork hook: called on the child process after forking.
// Returns FUZZ_HOOK_RUN_ERROR    if there was an error, or
//         FUZZ_HOOK_RUN_CONTINUE if the trial may continue.
struct fuzz_post_fork_info {
	struct fuzz* t;
	const char*  prop_name;
	size_t       total_trials;
	size_t       failures;
	uint64_t     run_seed;
	uint8_t      arity;
	void**       args;
};

// Post-trial hook: called after the trial is run, with the arguments and
// result.
// Returns FUZZ_HOOK_RUN_ERROR       if there was an error,
//         FUZZ_HOOK_RUN_CONTINUE    if the trial may continue,
//         FUZZ_HOOK_RUN_REPEAT      if the trial should be repeated with the
//                                    same arguments, or
//         FUZZ_HOOK_RUN_REPEAT_ONCE if the trial should be repeated with the
//                                    same arguments only once.
struct fuzz_post_trial_info {
	struct fuzz* t;
	const char*  prop_name;
	size_t       total_trials;
	size_t       trial_id;
	size_t       failures;
	uint64_t     run_seed;
	uint64_t     trial_seed;
	uint8_t      arity;
	void**       args;
	int          result;
	bool         repeat;
};

// The default post-trial hook. Calls `fuzz_print_trial_result` with an
// internally allocated `struct fuzz_print_trial_result_env`.
FUZZ_PUBLIC
int fuzz_hook_trial_post_print_result(
		const struct fuzz_post_trial_info* info, void* env);

// Counter-example hook: called when fuzz finds a counter-example that causes
// a property test to fail.
// Returns FUZZ_HOOK_RUN_ERROR       if there was an error, or
//         FUZZ_HOOK_RUN_CONTINUE    if the trial may continue.
struct fuzz_counterexample_info {
	struct fuzz*            t;
	const char*             prop_name;
	size_t                  total_trials;
	size_t                  trial_id;
	uint64_t                trial_seed;
	uint8_t                 arity;
	struct fuzz_type_info** type_info;
	void**                  args;
};

// Print a property counter-example that caused a failing trial. This is the
// default counterexample hook.
FUZZ_PUBLIC
int fuzz_print_counterexample(
		const struct fuzz_counterexample_info* info, void* env);

// Pre-shrinking hook: called before each shrinking attempt.
// Returns FUZZ_HOOK_RUN_ERROR    if there was an error,
//         FUZZ_HOOK_RUN_CONTINUE if the trial may continue, or
//         FUZZ_HOOK_RUN_HALT     if no more trials must be ran.
struct fuzz_pre_shrink_info {
	const char* prop_name;
	size_t      total_trials;
	size_t      trial_id;
	size_t      failures;
	uint64_t    run_seed;
	uint64_t    trial_seed;
	uint8_t     arity;
	size_t      shrink_count;
	size_t      successful_shrinks;
	size_t      failed_shrinks;
	uint8_t     arg_index;
	void*       arg;
	uint32_t    tactic;
};

// Post-shrinking hook: called after attempting to shrink, with the new
// instance (if shrinking succeeded).
// Returns FUZZ_HOOK_RUN_ERROR       if there was an error, or
//         FUZZ_HOOK_RUN_CONTINUE    if the trial may continue.
enum fuzz_post_shrink_state {
	FUZZ_SHRINK_POST_SHRINK_FAILED,
	FUZZ_SHRINK_POST_SHRUNK,
	FUZZ_SHRINK_POST_DONE_SHRINKING,
};
struct fuzz_post_shrink_info {
	const char* prop_name;
	size_t      total_trials;
	size_t      trial_id;
	uint64_t    run_seed;
	uint64_t    trial_seed;
	uint8_t     arity;
	size_t      shrink_count;
	size_t      successful_shrinks;
	size_t      failed_shrinks;
	uint8_t     arg_index;
	void*       arg;
	uint32_t    tactic;
	// Did this shrinking attempt make any progress? If not, is shrinking
	// done overall?
	enum fuzz_post_shrink_state state;
};

// Post-trial-shrinking hook: called after running a trial with shrunken
// arguments.
// Returns FUZZ_HOOK_RUN_ERROR       if there was an error,
//         FUZZ_HOOK_RUN_CONTINUE    if the trial may continue,
//         FUZZ_HOOK_RUN_REPEAT      if the trial should be repeated with the
//                                    same arguments, or
//         FUZZ_HOOK_RUN_REPEAT_ONCE if the trial should be repeated with the
//                                    same arguments only once.
struct fuzz_post_shrink_trial_info {
	const char* prop_name;
	size_t      total_trials;
	size_t      trial_id;
	size_t      failures;
	uint64_t    run_seed;
	uint64_t    trial_seed;
	uint8_t     arity;
	size_t      shrink_count;
	size_t      successful_shrinks;
	size_t      failed_shrinks;
	uint8_t     arg_index;
	void**      args;
	uint32_t    tactic;
	int         result;
};

// Configuration struct for a fuzz run.
struct fuzz_run_config {
	// A test property function.
	// The argument count should match the number of callback structs
	// provided in `fuzz_config.type_info`. The fields which don't match
	// the `fuzz_config.type_info` will be ignored.
	//
	// Should return:
	//     FUZZ_RESULT_OK if the property holds,
	//     FUZZ_RESULT_FAIL if a counter-example is found,
	//     FUZZ_RESULT_SKIP if the combination of args isn't applicable,
	//  or FUZZ_RESULT_ERROR if the whole run should be halted.
	int (*prop1)(struct fuzz* t, void* arg1);
	int (*prop2)(struct fuzz* t, void* arg1, void* arg2);
	int (*prop3)(struct fuzz* t, void* arg1, void* arg2, void* arg3);
	int (*prop4)(struct fuzz* t, void* arg1, void* arg2, void* arg3,
			void* arg4);
	int (*prop5)(struct fuzz* t, void* arg1, void* arg2, void* arg3,
			void* arg4, void* arg5);
	int (*prop6)(struct fuzz* t, void* arg1, void* arg2, void* arg3,
			void* arg4, void* arg5, void* arg6);
	int (*prop7)(struct fuzz* t, void* arg1, void* arg2, void* arg3,
			void* arg4, void* arg5, void* arg6, void* arg7);

	// Callbacks for allocating, freeing, printing, hashing, and shrinking
	// each property function argument.
	const struct fuzz_type_info* type_info[FUZZ_MAX_ARITY];

	// -- All fields after this point are optional. --

	// Property name, displayed in test runner output if non-NULL.
	const char* name;

	// Array of seeds to always run, and its length. Can be used for
	// regression tests.
	size_t    always_seed_count; // number of seeds
	uint64_t* always_seeds;      // seeds to always run

	// Number of trials to run. Defaults to FUZZ_DEF_TRIALS.
	size_t trials;

	// Seed for the random number generator.
	uint64_t seed;

	// Bits to use for the bloom filter -- this field is no longer used,
	// and will be removed in a future release.
	uint8_t bloom_bits;

	// Fork before running the property test, in case generated arguments
	// can cause the code under test to crash.
	struct {
		bool   enable;
		size_t timeout; // in milliseconds (or 0, for none)
		// signal to send after timeout, defaults to SIGTERM
		int signal;
		// For workers sent a timeout signal, how long should fuzz
		// wait for them to actually exit (in msec). Defaults to
		// FUZZ_DEF_EXIT_TIMEOUT_MSEC.
		size_t exit_timeout;
	} fork;

	// These functions are called in several contexts to report on
	// progress, halt shrinking early, repeat trials with different
	// logging, etc.
	struct {
		int (*pre_run)(const struct fuzz_pre_run_info* info,
				void*                          env);
		int (*post_run)(const struct fuzz_post_run_info* info,
				void*                            env);
		int (*pre_gen_args)(const struct fuzz_pre_gen_args_info* info,
				void*                                    env);
		int (*pre_trial)(const struct fuzz_pre_trial_info* info,
				void*                              env);
		int (*post_fork)(const struct fuzz_post_fork_info* info,
				void*                              env);
		int (*post_trial)(const struct fuzz_post_trial_info* info,
				void*                                env);
		int (*counterexample)(
				const struct fuzz_counterexample_info* info,
				void*                                  env);
		int (*pre_shrink)(const struct fuzz_pre_shrink_info* info,
				void*                                env);
		int (*post_shrink)(const struct fuzz_post_shrink_info* info,
				void*                                  env);
		int (*post_shrink_trial)(
				const struct fuzz_post_shrink_trial_info* info,
				void*                                     env);
		// Environment pointer. This is completely opaque to fuzz
		// itself, but will be passed to all callbacks.
		void* env;
	} hooks;
};

// Run a series of randomized trials of a property function.
//
// Configuration is specified in CFG; many fields are optional.
FUZZ_PUBLIC
int fuzz_run(const struct fuzz_run_config* cfg);

// Generate the instance based on a given seed, print it to F, and then free
// it. If print or free callbacks are NULL, they will be skipped.
FUZZ_PUBLIC
int fuzz_generate(FILE* f, uint64_t seed, const struct fuzz_type_info* info,
		void* hook_env);

// Get BITS random bits from the test runner's PRNG, which will be returned as
// a little-endian uint64_t. At most 64 bits can be retrieved at once --
// requesting more is a checked error.
//
// For more than 64 bits, use fuzz_random_bits_bulk.
FUZZ_PUBLIC
uint64_t fuzz_random_bits(struct fuzz* t, uint8_t bits);

// Get BITS random bits, in bulk, and put them in BUF. BUF is assumed to be
// large enough, and will be zeroed before any bits are copied to it. Bits will
// be copied little-endian.
FUZZ_PUBLIC
void fuzz_random_bits_bulk(struct fuzz* t, uint32_t bits, uint64_t* buf);

#if FUZZ_USE_FLOATING_POINT
// Get a random double from the test runner's PRNG.
FUZZ_PUBLIC
double fuzz_random_double(struct fuzz* t);

// Get a random uint64_t less than CEIL.
// For example, `fuzz_random_choice(t, 5)` will return
// approximately evenly distributed values from [0, 1, 2, 3, 4].
FUZZ_PUBLIC
uint64_t fuzz_random_choice(struct fuzz* t, uint64_t ceil);

// Get a random uint64_t in the range [min, max].
// For example, `fuzz_random_range(f, 7, 18)` will return approximately evenly
// distributed values from [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18].
FUZZ_PUBLIC
uint64_t fuzz_random_range(
		struct fuzz* f, const uint64_t min, const uint64_t max);
#endif

// Hash a buffer in one pass. (Wraps the below functions.)
FUZZ_PUBLIC uint64_t fuzz_hash_onepass(const uint8_t* data, size_t bytes);

// Initialize/reset a hasher h for incremental hashing.
FUZZ_PUBLIC
void fuzz_hash_init(uint64_t* h);

// Sink more data into an incremental hash h.
FUZZ_PUBLIC
void fuzz_hash_sink(uint64_t* h, const uint8_t* data, size_t bytes);

// Finish hashing and get the result. (This also resets the internal hasher h's
// state.)
FUZZ_PUBLIC
uint64_t fuzz_hash_finish(uint64_t* h);

// Print a trial result in the default format.
//
// To use this, add a `struct fuzz_print_trial_result_env` to the env in the
// `struct fuzz_run_config`, and call `fuzz_print_trial_result` with it from
// inside the `trial_post` hook.
//
// When the default `fuzz_hook_trial_post_print_result` hook is used, the env
// is allocated and freed internally.
//
// Unless a custom output max_column width is wanted, all of these fields can
// just be initialized to 0.
#define FUZZ_PRINT_TRIAL_RESULT_ENV_TAG 0xe7a6
struct fuzz_print_trial_result_env {
	uint16_t      tag;        // used for internal validation
	const uint8_t max_column; // 0 -> default of 72
	uint8_t       column;
	size_t        scale_pass;
	size_t        scale_skip;
	size_t        scale_dup;
	size_t        consec_pass;
	size_t        consec_skip;
	size_t        consec_dup;
};
FUZZ_PUBLIC
void fuzz_print_trial_result(struct fuzz_print_trial_result_env* print_env,
		const struct fuzz_post_trial_info*               info);

// Print a standard pre-run report.
FUZZ_PUBLIC
void fuzz_print_pre_run_info(FILE* f, const struct fuzz_pre_run_info* info);

// Print a standard post-run report.
FUZZ_PUBLIC
void fuzz_print_post_run_info(FILE* f, const struct fuzz_post_run_info* info);

// Halt trials after the first failure.
FUZZ_PUBLIC
int fuzz_hook_first_fail_halt(
		const struct fuzz_pre_trial_info* info, void* env);

// Get the hook environment pointer. This is the contents of
// fuzz_run_config.hooks.env.
FUZZ_PUBLIC
void* fuzz_hook_get_env(struct fuzz* t);

// Change T's output stream handle to OUT. (Default: stdout.)
FUZZ_PUBLIC
void fuzz_set_output_stream(struct fuzz* t, FILE* out);

// Get a seed based on the hash of the current timestamp.
FUZZ_PUBLIC
uint64_t fuzz_seed_of_time(void);

// Generic free callback: just call free(instance).
FUZZ_PUBLIC
void fuzz_generic_free_cb(void* instance, void* env);

// Return a string name of a FUZZ_RESULT_* value.
FUZZ_PUBLIC
const char* fuzz_result_str(int res);

enum fuzz_builtin_type_info {
	FUZZ_BUILTIN_bool,

	// Built-in unsigned types.
	//
	// If env is non-NULL, it will be cast to a pointer to this type and
	// dereferenced for a limit.
	//
	// For example, if the fuzz_type_info struct's env field is set like
	// this:
	//
	//     uint8_t limit = 64;
	//     struct fuzz_type_info info = *fuzz_get_builtin_type_info(
	//			FUZZ_BUILTIN_uint8_t);
	//     info.env = &limit;
	//
	// then the generator will produce uint8_t values 0 <= x < 64.
	FUZZ_BUILTIN_uint, // platform-specific
	FUZZ_BUILTIN_uint8_t,
	FUZZ_BUILTIN_uint16_t,
	FUZZ_BUILTIN_uint32_t,
	FUZZ_BUILTIN_uint64_t,
	FUZZ_BUILTIN_size_t,

	// Built-in signed types.
	//
	// If env is non-NULL, it will be cast to a pointer to this type and
	// dereferenced for a +/- limit.
	//
	// For example, if if the fuzz_type_info struct's env field is set
	// like this:
	//
	//     int16_t limit = 1000;  // limit must be positive
	//     struct fuzz_type_info info = *fuzz_get_builtin_type_info(
	//			FUZZ_BUILTIN_int16_t);
	//     info.env = &limit;
	//
	// then the generator will produce uint8_t values -1000 <= x < 1000.
	FUZZ_BUILTIN_int,
	FUZZ_BUILTIN_int8_t,
	FUZZ_BUILTIN_int16_t,
	FUZZ_BUILTIN_int32_t,
	FUZZ_BUILTIN_int64_t,

#if FUZZ_USE_FLOATING_POINT
	// Built-in floating point types.
	// If env is non-NULL, it will be cast to a pointer of this type and
	// dereferenced for a +/- limit.
	FUZZ_BUILTIN_float,
	FUZZ_BUILTIN_double,
#endif

	// Built-in array types.
	// If env is non-NULL, it will be cast to a `size_t *` and deferenced
	// for a max length.
	// These are always terminated by a 0 byte, and do not generate 0 bytes
	// as part of the array.
	FUZZ_BUILTIN_char_ARRAY,
	FUZZ_BUILTIN_uint8_t_ARRAY,
};

// Get a const pointer to built-in type_info callbacks for TYPE. See the
// comments for each type above for details.
//
// NOTE: All built-ins have autoshrink enabled.
FUZZ_PUBLIC
const struct fuzz_type_info* fuzz_get_builtin_type_info(
		enum fuzz_builtin_type_info type);

#endif

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_RANDOM_H
#define FUZZ_RANDOM_H

#include <inttypes.h>

struct fuzz;
struct autoshrink_bit_pool;

// Inject a bit pool for autoshrinking -- Get the random bit stream from
// it, rather than the PRNG, because we'll shrink by shrinking the bit
// pool itself.
void fuzz_random_inject_autoshrink_bit_pool(
		struct fuzz* t, struct autoshrink_bit_pool* bitpool);

// Stop using an autoshrink bit pool.
// (Re-seeding the PRNG will also do this.)
void fuzz_random_stop_using_bit_pool(struct fuzz* t);

// (Re-)initialize the random number generator with a specific seed.
// This stops using the current bit pool.
void fuzz_random_set_seed(struct fuzz* t, uint64_t seed);

#endif

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_RNG_H
#define FUZZ_RNG_H

#include <inttypes.h>

// Wrapper for Mersenne Twister.
// See copyright and license in fuzz_rng.c, more details at:
//     http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
//
// Local modifications are described in fuzz_mt.c.

// Opaque type for a Mersenne Twister PRNG.
struct fuzz_rng;

// Heap-allocate a mersenne twister struct.
struct fuzz_rng* fuzz_rng_init(uint64_t seed);

// Free a heap-allocated mersenne twister struct.
void fuzz_rng_free(struct fuzz_rng* mt);

// Reset a mersenne twister struct, possibly stack-allocated.
void fuzz_rng_reset(struct fuzz_rng* mt, uint64_t seed);

// Get a 64-bit random number.
uint64_t fuzz_rng_random(struct fuzz_rng* mt);

// Convert a uint64_t to a number on the [0,1]-real-interval.
double fuzz_rng_uint64_to_double(uint64_t x);

#endif

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_TYPES_INTERNAL_H
#define FUZZ_TYPES_INTERNAL_H

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#if !defined(_WIN32)
#include <sys/types.h>
#endif

#if !defined(FUZZ_PUBLIC)
#define FUZZ_PUBLIC
#endif

#if defined(_WIN32)
// The LOG macro makes use of a compile-time known conditional, so we disable
// the MSVC warning "conditional expression is constant" (4127)
//
// Error 4996 is the "this function is deprecated" warning for standard C
// stuff.
#pragma warning(disable : 4127 4996)
#endif

#define FUZZ_MAX_TACTICS ((uint32_t)-1)
#define DEFAULT_uint64_t 0xa600d64b175eedLLU

#define FUZZ_LOG_LEVEL 0
#define LOG(LEVEL, ...)                                                       \
	do {                                                                  \
		if (LEVEL <= FUZZ_LOG_LEVEL) {                                \
			printf(__VA_ARGS__);                                  \
		}                                                             \
	} while (0)

#if !defined(FUZZ_MAX_ARITY)
#define FUZZ_MAX_ARITY 7
#endif

struct fuzz;
struct fuzz_pre_run_info;
struct fuzz_post_run_info;
struct fuzz_pre_gen_args_info;
struct fuzz_pre_trial_info;
struct fuzz_post_fork_info;
struct fuzz_post_trial_info;
struct fuzz_counterexample_info;
struct fuzz_pre_shrink_info;
struct fuzz_post_shrink_info;
struct fuzz_post_shrink_trial_info;

struct fuzz_bloom; // bloom filter
struct fuzz_rng;   // pseudorandom number generator

struct seed_info {
	const uint64_t run_seed;

	// Optional array of seeds to always run.
	// Can be used for regression tests.
	const size_t    always_seed_count; // number of seeds
	const uint64_t* always_seeds;      // seeds to always run
};

struct fork_info {
	const bool   enable;
	const size_t timeout;
	const int    signal;
	const size_t exit_timeout;
};

struct prop_info {
	const char* name; // property name, can be NULL
	// property function under test. Each funX represents a property
	// function which takes X arguments.
	union {
		int (*fun1)(struct fuzz*, void* arg1);
		int (*fun2)(struct fuzz*, void* arg1, void* arg2);
		int (*fun3)(struct fuzz*, void* arg1, void* arg2, void* arg3);
		int (*fun4)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4);
		int (*fun5)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4, void* arg5);
		int (*fun6)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4, void* arg5, void* arg6);
		int (*fun7)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4, void* arg5, void* arg6,
				void* arg7);
	} u;
	const size_t trial_count;

	// Type info for ARITY arguments.
	const uint8_t          arity; // number of arguments
	struct fuzz_type_info* type_info[FUZZ_MAX_ARITY];
};

// Hook function types
typedef int fuzz_pre_run_hook_cb(
		const struct fuzz_pre_run_info* info, void* env);
typedef int fuzz_post_run_hook_cb(
		const struct fuzz_post_run_info* info, void* env);
typedef int fuzz_hook_gen_args_pre_cb(
		const struct fuzz_pre_gen_args_info* info, void* env);
typedef int fuzz_hook_trial_pre_cb(
		const struct fuzz_pre_trial_info* info, void* env);
typedef int fuzz_hook_fork_post_cb(
		const struct fuzz_post_fork_info* info, void* env);
typedef int fuzz_hook_trial_post_cb(
		const struct fuzz_post_trial_info* info, void* env);
typedef int fuzz_hook_counterexample_cb(
		const struct fuzz_counterexample_info* info, void* env);
typedef int fuzz_hook_shrink_pre_cb(
		const struct fuzz_pre_shrink_info* info, void* env);
typedef int fuzz_hook_shrink_post_cb(
		const struct fuzz_post_shrink_info* info, void* env);
typedef int fuzz_hook_shrink_trial_post_cb(
		const struct fuzz_post_shrink_trial_info* info, void* env);

struct hook_info {
	fuzz_pre_run_hook_cb*           pre_run;
	fuzz_post_run_hook_cb*          post_run;
	fuzz_hook_gen_args_pre_cb*      pre_gen_args;
	fuzz_hook_trial_pre_cb*         trial_pre;
	fuzz_hook_fork_post_cb*         fork_post;
	fuzz_hook_trial_post_cb*        trial_post;
	fuzz_hook_counterexample_cb*    counterexample;
	fuzz_hook_shrink_pre_cb*        shrink_pre;
	fuzz_hook_shrink_post_cb*       shrink_post;
	fuzz_hook_shrink_trial_post_cb* shrink_trial_post;
	void*                           env;
};

struct counter_info {
	size_t pass;
	size_t fail;
	size_t skip;
	size_t dup;
};

struct prng_info {
	struct fuzz_rng* rng; // random number generator
	uint64_t         buf; // buffer for PRNG bits
	uint8_t          bits_available;
	// Bit pool, only used during autoshrinking.
	struct autoshrink_bit_pool* bit_pool;
};

enum arg_type {
	ARG_BASIC,
	ARG_AUTOSHRINK,
};

struct arg_info {
	void* instance;

	enum arg_type type;
	union {
		struct {
			struct autoshrink_env* env;
		} as;
	} u;
};

// Result from an individual trial.
struct trial_info {
	const int       trial; // N'th trial
	uint64_t        seed;  // Seed used
	size_t          shrink_count;
	size_t          successful_shrinks;
	size_t          failed_shrinks;
	struct arg_info args[FUZZ_MAX_ARITY];
};

enum worker_state {
	WS_INACTIVE,
	WS_ACTIVE,
	WS_STOPPED,
};

struct worker_info {
	enum worker_state state;
	int               fds[2];
	pid_t             pid;
	int               wstatus;
};

// Handle to state for the entire run.
struct fuzz {
	FILE*                               out;
	struct fuzz_bloom*                  bloom; // bloom filter
	struct fuzz_print_trial_result_env* print_trial_result_env;

	struct prng_info    prng;
	struct prop_info    prop;
	struct seed_info    seeds;
	struct fork_info    fork;
	struct hook_info    hooks;
	struct counter_info counters;
	struct trial_info   trial;
	struct worker_info  workers[1];
};

#endif

#define GET_DEF(X, DEF) (X ? X : DEF)
#define LOG_AUTOSHRINK  0

static struct autoshrink_bit_pool* alloc_bit_pool(
		size_t size, size_t limit, size_t request_ceil);

static int alloc_from_bit_pool(struct fuzz* t, struct autoshrink_env* env,
		struct autoshrink_bit_pool* bit_pool, void** output,
		bool shrinking);

static bool append_request(
		struct autoshrink_bit_pool* pool, uint32_t bit_count);

static void drop_from_bit_pool(struct fuzz* t, struct autoshrink_env* env,
		const struct autoshrink_bit_pool* orig,
		struct autoshrink_bit_pool*       pool);

static void mutate_bit_pool(struct fuzz* t, struct autoshrink_env* env,
		const struct autoshrink_bit_pool* orig,
		struct autoshrink_bit_pool*       pool);

static bool choose_and_mutate_request(struct fuzz* t,
		struct autoshrink_env*             env,
		const struct autoshrink_bit_pool*  orig,
		struct autoshrink_bit_pool*        pool);

static bool build_index(struct autoshrink_bit_pool* pool);

static size_t offset_of_pos(
		const struct autoshrink_bit_pool* orig, size_t pos);

static void convert_bit_offset(
		size_t bit_offset, size_t* byte_offset, uint8_t* bit);

static uint64_t read_bits_at_offset(const struct autoshrink_bit_pool* pool,
		size_t bit_offset, uint8_t size);

static void write_bits_at_offset(struct autoshrink_bit_pool* pool,
		size_t bit_offset, uint8_t size, uint64_t bits);

static void truncate_trailing_zero_bytes(struct autoshrink_bit_pool* pool);

static void init_model(struct autoshrink_env* env);

static enum mutation get_weighted_mutation(
		struct fuzz* t, struct autoshrink_env* env);

static bool should_drop(struct fuzz* t, struct autoshrink_env* env,
		size_t request_count);

static void lazily_fill_bit_pool(struct fuzz* t,
		struct autoshrink_bit_pool* pool, const uint32_t bit_count);

static void fill_buf(struct autoshrink_bit_pool* pool,
		const uint32_t bit_count, uint64_t* buf);

static autoshrink_prng_fun* get_prng(
		struct fuzz* t, struct autoshrink_env* env);
static uint64_t get_autoshrink_mask(uint8_t bits);

struct autoshrink_env*
fuzz_autoshrink_alloc_env(struct fuzz* t, uint8_t arg_i,
		const struct fuzz_type_info* type_info)
{
	(void)t;
	struct autoshrink_env* env = malloc(sizeof(*env));
	if (env == NULL) {
		return NULL;
	}

	*env = (struct autoshrink_env){
			.arg_i      = arg_i,
			.pool_size  = type_info->autoshrink_config.pool_size,
			.print_mode = type_info->autoshrink_config.print_mode,
			.max_failed_shrinks =
					type_info->autoshrink_config
							.max_failed_shrinks,
	};
	return env;
}

void
fuzz_autoshrink_free_env(struct fuzz* t, struct autoshrink_env* env)
{
	(void)t;
	if (env->bit_pool != NULL) {
		fuzz_autoshrink_free_bit_pool(t, env->bit_pool);
	}
	free(env);
}

void
fuzz_autoshrink_bit_pool_random(struct fuzz* t,
		struct autoshrink_bit_pool* pool, uint32_t bit_count,
		bool save_request, uint64_t* buf)
{
	assert(pool);
	if (bit_count == 0) {
		return;
	}

	// If not shrinking, lazily fill the bit pool.
	if (!pool->shrinking) {
		lazily_fill_bit_pool(t, pool, bit_count);
	}

	// Only return as many bits as the pool contains. After reaching the
	// end of the pool, just return 0 bits forever and stop tracking
	// requests.
	if (pool->consumed == pool->limit) {
		LOG(3 - LOG_AUTOSHRINK,
				"%s: end of bit pool, yielding zeroes\n",
				__func__);
		memset(buf, 0x00,
				(bit_count / 64) +
						((bit_count % 64) == 0 ? 0
								       : 1));
		return;
	}

	if (pool->consumed + bit_count >= pool->limit) {
		assert(pool->limit - pool->consumed <= UINT32_MAX);
		bit_count = (uint32_t)(pool->limit - pool->consumed);
	}

	if (save_request && !append_request(pool, bit_count)) {
		assert(false); // memory fail
	}

	fill_buf(pool, bit_count, buf);
}

static void
lazily_fill_bit_pool(struct fuzz* t, struct autoshrink_bit_pool* pool,
		const uint32_t bit_count)
{
	// Grow pool->bits as necessary
	LOG(3, "consumed %zd, bit_count %u, ceil %zd\n", pool->consumed,
			bit_count, pool->bits_ceil);
	while (pool->consumed + bit_count > pool->bits_ceil) {
		size_t nceil = 2 * pool->bits_ceil;
		LOG(1, "growing pool: from bits %p, ceil %zd, ",
				(void*)pool->bits, pool->bits_ceil);
		uint64_t* nbits = realloc(
				pool->bits, nceil / (64 / sizeof(uint64_t)));
		LOG(1, "nbits %p, nceil %zd\n", (void*)nbits, nceil);
		if (nbits == NULL) {
			assert(false); // alloc fail
			return;
		}
		pool->bits      = (uint8_t*)nbits;
		pool->bits_ceil = nceil;
	}

	while (pool->consumed + bit_count > pool->bits_filled) {
		uint64_t* bits64 = (uint64_t*)pool->bits;
		size_t    offset = pool->bits_filled / 64;
		assert(offset * 64 < pool->bits_ceil);
		bits64[offset] = fuzz_rng_random(t->prng.rng);
		LOG(3, "filling bit64[%zd]: 0x%016" PRIx64 "\n", offset,
				bits64[offset]);
		pool->bits_filled += 64;
	}
}

static void
fill_buf(struct autoshrink_bit_pool* pool, const uint32_t bit_count,
		uint64_t* dst)
{
	const uint64_t* src        = (const uint64_t*)pool->bits;
	size_t          src_offset = pool->consumed / 64;
	uint8_t         src_bit    = (pool->consumed & 0x3f);

	size_t dst_offset = 0;
	dst[0]            = 0; // clobber the destination buffer

	uint32_t i = 0;
	while (i < bit_count) {
		const uint8_t dst_bit = i & 0x3f;

		const uint8_t src_rem = 64 - src_bit;
		uint8_t       dst_req = (uint8_t)(64U - dst_bit);

		if (bit_count - i < 64U - dst_bit) {
			dst_req = (uint8_t)(bit_count - i);
		}

		// Figure out how many bits can be copied at once, based on the
		// current bit offsets into the src and dst buffers.
		const uint8_t to_copy =
				(dst_req < src_rem ? dst_req : src_rem);
		const uint64_t mask = get_autoshrink_mask(to_copy);
		const uint64_t bits = (src[src_offset] >> src_bit) & mask;

		LOG(5,
				"src_bit %u, dst_bit %u, src_rem %u, dst_req "
				"%u, to_copy %u, mask 0x%" PRIx64
				", bits 0x%" PRIx64 "\n",
				src_bit, dst_bit, src_rem, dst_req, to_copy,
				mask, bits);
		LOG(5,
				"    src[%zd] 0x%016" PRIx64
				", dst[%zd] 0x%016" PRIx64 " => %016" PRIx64
				"\n",
				src_offset, src[src_offset], dst_offset,
				dst[dst_offset],
				dst[dst_offset] | (bits << dst_bit));

		dst[dst_offset] |= (bits << dst_bit);

		src_bit += to_copy;
		if (src_bit == 64) {
			src_bit = 0;
			src_offset++;
		}

		i += to_copy;
		if (dst_bit + to_copy == 64) {
			dst_offset++;
			if (i < bit_count) {
				dst[dst_offset] = 0;
			}
		}
	}

	pool->consumed += bit_count;
}

static uint64_t
get_autoshrink_mask(uint8_t bits)
{
	return (bits == 64U ? (uint64_t)-1 : ((1LLU << bits) - 1));
}

static size_t
get_aligned_size(size_t size, uint8_t alignment)
{
	if ((size % alignment) != 0) {
		size += alignment - (size % alignment);
	}
	return size;
}

static struct autoshrink_bit_pool*
alloc_bit_pool(size_t size, size_t limit, size_t request_ceil)
{
	uint8_t*                    bits     = NULL;
	uint32_t*                   requests = NULL;
	struct autoshrink_bit_pool* res      = NULL;

	size_t alloc_size = get_aligned_size(size, 64);
	assert((alloc_size % 64) == 0);

	// Ensure that the allocation size is aligned to 64 bits, so we can
	// work in 64-bit steps later on.
	LOG(3, "Allocating alloc_size %zd => %zd bytes\n", alloc_size,
			(alloc_size / 64) * sizeof(uint64_t));
	uint64_t* aligned_bits = calloc(alloc_size / 64, sizeof(uint64_t));
	bits                   = (uint8_t*)aligned_bits;
	if (bits == NULL) {
		goto fail;
	}

	res = calloc(1, sizeof(*res));
	if (res == NULL) {
		goto fail;
	}

	requests = calloc(request_ceil, sizeof(*requests));
	if (requests == NULL) {
		goto fail;
	}

	*res = (struct autoshrink_bit_pool){
			.bits          = bits,
			.bits_ceil     = alloc_size,
			.limit         = limit,
			.request_count = 0,
			.request_ceil  = request_ceil,
			.requests      = requests,
	};
	return res;

fail:
	if (bits) {
		free(bits);
	}
	if (res) {
		free(res);
	}
	if (requests) {
		free(requests);
	}
	return NULL;
}

void
fuzz_autoshrink_free_bit_pool(struct fuzz* t, struct autoshrink_bit_pool* pool)
{
	if (t) {
		// don't free while still in use
		assert(t->prng.bit_pool == NULL);
	}
	assert(pool);
	assert(pool->bits);
	if (pool->index) {
		free(pool->index);
	}
	free(pool->bits);
	free(pool->requests);
	free(pool);
}

static int
alloc_from_bit_pool(struct fuzz* t, struct autoshrink_env* env,
		struct autoshrink_bit_pool* bit_pool, void** output,
		bool shrinking)
{
	assert(env);
	int ares;
	bit_pool->shrinking = shrinking;
	fuzz_random_inject_autoshrink_bit_pool(t, bit_pool);
	struct fuzz_type_info* ti = t->prop.type_info[env->arg_i];
	ares                      = ti->alloc(t, ti->env, output);
	fuzz_random_stop_using_bit_pool(t);
	return ares;
}

int
fuzz_autoshrink_alloc(
		struct fuzz* t, struct autoshrink_env* env, void** instance)
{
	assert(env);
	const size_t pool_size  = GET_DEF(env->pool_size, DEF_POOL_SIZE);
	const size_t pool_limit = GET_DEF(env->pool_limit, DEF_POOL_LIMIT);

	struct autoshrink_bit_pool* pool = alloc_bit_pool(
			pool_size, pool_limit, DEF_REQUESTS_CEIL);
	if (pool == NULL) {
		return FUZZ_RESULT_ERROR;
	}
	env->bit_pool = pool;

	void* res  = NULL;
	int   ares = alloc_from_bit_pool(t, env, pool, &res, false);
	if (ares != FUZZ_RESULT_OK) {
		return ares;
	}

	*instance = res;
	return FUZZ_RESULT_OK;
}

uint64_t
fuzz_autoshrink_hash(struct fuzz* t, const void* instance,
		struct autoshrink_env* env, void* type_env)
{

	// If the user has a hash callback defined, use it on
	// the instance, otherwise hash the bit pool.
	const struct fuzz_type_info* ti = t->prop.type_info[env->arg_i];
	if (ti->hash != NULL) {
		return ti->hash(instance, type_env);
	} else {
		struct autoshrink_bit_pool* pool = env->bit_pool;
		assert(pool);
		// Hash the consumed bits from the bit pool
		uint64_t h = 0;
		fuzz_hash_init(&h);
		LOG(5 - LOG_AUTOSHRINK, "@@@ SINKING: [ ");
		for (size_t i = 0; i < pool->consumed / 8; i++) {
			LOG(5 - LOG_AUTOSHRINK, "%02x ", pool->bits[i]);
		}
		fuzz_hash_sink(&h, pool->bits, pool->consumed / 8);
		const uint8_t rem_bits = pool->consumed % 8;
		if (rem_bits > 0) {
			const uint8_t last_byte =
					pool->bits[pool->consumed / 8];
			const uint8_t mask = ((1U << rem_bits) - 1);
			uint8_t       rem  = last_byte & mask;
			LOG(5 - LOG_AUTOSHRINK, "%02x/%d", rem, rem_bits);
			fuzz_hash_sink(&h, &rem, 1);
		}
		LOG(5 - LOG_AUTOSHRINK, " ]\n");
		uint64_t res = fuzz_hash_finish(&h);
		LOG(2 - LOG_AUTOSHRINK, "%s: 0x%016" PRIx64 "\n", __func__,
				res);
		return res;
	}
}

int
fuzz_autoshrink_shrink(struct fuzz* t, struct autoshrink_env* env,
		uint32_t tactic, void** output,
		struct autoshrink_bit_pool** output_bit_pool)
{
	struct autoshrink_bit_pool* orig = env->bit_pool;
	assert(orig);

	if (tactic >= GET_DEF(env->max_failed_shrinks,
				      DEF_MAX_FAILED_SHRINKS)) {
		return FUZZ_SHRINK_NO_MORE_TACTICS;
	}

	if (!build_index(orig)) {
		return FUZZ_SHRINK_ERROR;
	}

	// Make a copy of the bit pool to shrink
	struct autoshrink_bit_pool* copy = alloc_bit_pool(
			orig->bits_filled, orig->limit, orig->request_ceil);
	if (copy == NULL) {
		return FUZZ_SHRINK_ERROR;
	}
	copy->generation      = orig->generation + 1;
	size_t total_consumed = 0;
	for (size_t i = 0; i < orig->request_count; i++) {
		total_consumed += orig->requests[i];
	}
	assert(total_consumed == orig->consumed);
	copy->limit = orig->limit;

	env->model.cur_tried = 0x00;
	env->model.cur_set   = 0x00;

	LOG(3 - LOG_AUTOSHRINK, "========== BEFORE (tactic %u)\n", tactic);
	if (3 - LOG_AUTOSHRINK <= FUZZ_LOG_LEVEL) {
		fuzz_autoshrink_dump_bit_pool(stdout, orig->bits_filled, orig,
				FUZZ_AUTOSHRINK_PRINT_ALL);
	}

	if (env->model.weights[WEIGHT_DROP] == 0) {
		init_model(env);
	}

	if (should_drop(t, env, orig->request_count)) {
		env->model.cur_set |= ASA_DROP;
		drop_from_bit_pool(t, env, orig, copy);
	} else {
		mutate_bit_pool(t, env, orig, copy);
	}
	LOG(3 - LOG_AUTOSHRINK, "========== AFTER\n");
	if (3 - LOG_AUTOSHRINK <= FUZZ_LOG_LEVEL) {
		fuzz_autoshrink_dump_bit_pool(stdout, copy->bits_filled, copy,
				FUZZ_AUTOSHRINK_PRINT_ALL);
	}

	if (!env->leave_trailing_zeroes) {
		truncate_trailing_zero_bytes(copy);
	}

	void* res  = NULL;
	int   ares = alloc_from_bit_pool(t, env, copy, &res, true);
	if (ares == FUZZ_RESULT_SKIP) {
		fuzz_autoshrink_free_bit_pool(t, copy);
		return FUZZ_SHRINK_DEAD_END;
	} else if (ares == FUZZ_RESULT_ERROR) {
		fuzz_autoshrink_free_bit_pool(t, copy);
		return FUZZ_SHRINK_ERROR;
	}

	assert(ares == FUZZ_RESULT_OK);
	*output          = res;
	*output_bit_pool = copy;
	return FUZZ_SHRINK_OK;
}

static void
truncate_trailing_zero_bytes(struct autoshrink_bit_pool* pool)
{
	size_t       nsize     = 0;
	const size_t byte_size = (pool->bits_filled / 8) +
				 ((pool->bits_filled % 8) == 0 ? 0 : 1);
	if (byte_size > 0) {
		size_t i = byte_size;
		do {
			i--;
			if (pool->bits[i] != 0x00) {
				nsize = i + 1;
				break;
			}
		} while (i > 0);
	}
	nsize *= 8;
	LOG(2, "Truncating to nsize: %zd\n", nsize);
	pool->bits_filled = nsize;
	if (pool->limit > pool->bits_filled) {
		pool->limit = pool->bits_filled;
	}
}

static uint8_t
popcount(uint64_t value)
{
	uint8_t pop = 0;
	for (uint8_t i = 0; i < 64; i++) {
		if (value & (1LLU << i)) {
			pop++;
		}
	}
	return pop;
}

static uint8_t
log2ceil(size_t value)
{
	uint8_t res = 0;
	while ((1LLU << res) < value) {
		res++;
	}
	return res;
}

// Copy the contents of the orig pool into the new pool, but with a
// small probability of dropping individual requests.
static void
drop_from_bit_pool(struct fuzz* t, struct autoshrink_env* env,
		const struct autoshrink_bit_pool* orig,
		struct autoshrink_bit_pool*       copy)
{
	size_t src_offset = 0;
	size_t dst_offset = 0;

	size_t  src_byte = 0;
	size_t  dst_byte = 0;
	uint8_t src_bit  = 0x01;
	uint8_t dst_bit  = 0x01;

	// If N random bits are <= DROP_THRESHOLD, then drop the
	// current request, otherwise copy it.
	//
	// TODO: should this dynamically adjust based on orig->request_count?
	const uint64_t drop_threshold =
			GET_DEF(env->drop_threshold, DEF_DROP_THRESHOLD);
	const uint8_t drop_bits = GET_DEF(env->drop_bits, DEF_DROP_BITS);

	autoshrink_prng_fun* prng = get_prng(t, env);

	// Always drop at least one, unless to_drop is DO_NOT_DROP (which is
	// only for testing).
	size_t to_drop = prng(32, env->udata);
	if (to_drop != DO_NOT_DROP && orig->request_count > 0) {
		to_drop %= orig->request_count;
	}

	size_t drop_count = 0;

	for (size_t ri = 0; ri < orig->request_count; ri++) {
		const uint32_t req_size = orig->requests[ri];
		if (ri == to_drop || prng(drop_bits, env->udata) <=
						     drop_threshold) {
			LOG(2 - LOG_AUTOSHRINK, "DROPPING: %zd - %zd\n",
					src_offset, src_offset + req_size);
			drop_count++;

			if (req_size > 64) { // drop subset
				uint32_t drop_offset = prng(32, env->udata) %
						       req_size;
				uint32_t drop_size = prng(32, env->udata) %
						     req_size;
				LOG(2 - LOG_AUTOSHRINK,
						"DROPPING offset %u, size %u "
						"of %u\n",
						drop_offset, drop_size,
						req_size);
				for (size_t bi = 0; bi < req_size; bi++) {
					if (bi < drop_offset ||
							bi > drop_offset + drop_size) {
						if (orig->bits[src_byte] &
								src_bit) {
							copy->bits[dst_byte] |=
									dst_bit;
						}

						dst_bit <<= 1;
						if (dst_bit == 0x00) {
							dst_bit = 0x01;
							dst_byte++;
						}
						dst_offset++;
					}

					src_bit <<= 1;
					if (src_bit == 0x00) {
						src_bit = 0x01;
						src_byte++;
					}
					src_offset++;
				}
			} else { // drop all
				for (size_t bi = 0; bi < req_size; bi++) {
					src_bit <<= 1;
					if (src_bit == 0x00) {
						src_bit = 0x01;
						src_byte++;
					}
					src_offset++;
				}
			}
		} else { // copy
			for (size_t bi = 0; bi < req_size; bi++) {
				if (orig->bits[src_byte] & src_bit) {
					copy->bits[dst_byte] |= dst_bit;
				}

				src_bit <<= 1;
				if (src_bit == 0x00) {
					src_bit = 0x01;
					src_byte++;
				}
				src_offset++;

				dst_bit <<= 1;
				if (dst_bit == 0x00) {
					dst_bit = 0x01;
					dst_byte++;
				}
				dst_offset++;
			}
		}
	}

	LOG(2 - LOG_AUTOSHRINK, "DROP: %zd -> %zd (%zd requests)\n",
			orig->bits_filled, dst_offset, drop_count);
	(void)drop_count;
	copy->bits_filled = dst_offset;
}

static void
mutate_bit_pool(struct fuzz* t, struct autoshrink_env* env,
		const struct autoshrink_bit_pool* orig,
		struct autoshrink_bit_pool*       pool)
{
	const size_t orig_bytes = (orig->bits_filled / 8) +
				  ((orig->bits_filled % 8) == 0 ? 0 : 1);
	memcpy(pool->bits, orig->bits, orig_bytes);
	pool->bits_filled = orig->bits_filled;

	autoshrink_prng_fun* prng = get_prng(t, env);

	// Ensure that we aren't getting random bits from a pool while trying
	// to shrink the pool.
	assert(t->prng.bit_pool == NULL);

	uint8_t max_changes = 5;
	while ((1LLU << max_changes) < orig->request_count) {
		max_changes++;
	}

	// Get some random bits, and for each 1 bit, we will make one change in
	// the pool copy.
	uint8_t change_count = popcount(prng(max_changes, env->udata)) + 1;

	// If there are only a few requests, and none of them are large,
	// then limit the change count to the request count. This helps
	// prevent making several changes to a small surface area, which
	// tends to make shrinking overshoot when it's close to a local
	// minimum.
	if (change_count > orig->request_count) {
		bool all_small = true;
		for (size_t i = 0; i < orig->request_count; i++) {
			if (orig->requests[i] > 64) {
				all_small = false;
				break;
			}
		}

		if (all_small) {
			LOG(4 - LOG_AUTOSHRINK, "%s: clamping %u to %zd\n",
					__func__, change_count,
					orig->request_count);
			assert(orig->request_count <= UINT8_MAX);
			change_count = (uint8_t)orig->request_count;
		}
	}

	uint8_t changed = 0;

	// Attempt to make up to CHANGE_COUNT changes, with limited retries
	// for when the random modifications have no effect.
	for (size_t i = 0; i < 10U * change_count; i++) {
		if (choose_and_mutate_request(t, env, orig, pool)) {
			changed++;

			LOG(3 - LOG_AUTOSHRINK,
					"-- step changed (try %zd, changed "
					"%u, change_count %u)\n",
					i, changed, change_count);

			if (LOG_AUTOSHRINK >= 3) {
				fuzz_autoshrink_dump_bit_pool(stdout,
						pool->bits_filled, pool,
						FUZZ_AUTOSHRINK_PRINT_ALL);
			}

			if (changed == change_count) {
				break;
			}
		} else {
			LOG(3 - LOG_AUTOSHRINK,
					"-- step failed (try %zd, changed %u, "
					"change_count %u)\n",
					i, changed, change_count);
		}
	}

	// Truncate half of the unconsumed bits
	size_t nsize = orig->consumed +
		       (orig->bits_filled - orig->consumed) / 2;
	pool->limit = nsize < pool->limit ? nsize : pool->limit;
}

static bool
choose_and_mutate_request(struct fuzz* t, struct autoshrink_env* env,
		const struct autoshrink_bit_pool* orig,
		struct autoshrink_bit_pool*       pool)
{
	autoshrink_prng_fun* prng  = get_prng(t, env);
	enum mutation        mtype = get_weighted_mutation(t, env);

	const uint8_t request_bits = log2ceil(orig->request_count);

	if (orig->request_count == 0) {
		return false; // dead end, no more requests to mutate
	}

	// Align a change in the bit pool with a random request. The
	// mod here biases it towards earlier requests.
	const size_t pos =
			prng(request_bits, env->udata) % orig->request_count;
	const size_t   bit_offset = offset_of_pos(orig, pos);
	const uint32_t size       = orig->requests[pos];

	switch (mtype) {
	default:
		assert(false);
	case MUT_SHIFT: {
		env->model.cur_tried |= ASA_SHIFT;
		const uint8_t shift     = prng(2, env->udata) + 1;
		uint64_t      new_pos   = 0;
		uint32_t      to_change = 0;

		if (size > 64) { // Pick an offset and region to shift
			new_pos   = prng(32, env->udata) % size;
			to_change = (uint32_t)prng(6, env->udata);
			if (to_change > size - new_pos) {
				to_change = (uint32_t)(size - new_pos);
			}
		} else {
			to_change = size; // just change the whole thing
		}

		assert(to_change <= UINT8_MAX);
		const uint64_t bits  = read_bits_at_offset(pool,
				 bit_offset + new_pos, (uint8_t)to_change);
		const uint64_t nbits = bits >> shift;
		LOG(2 - LOG_AUTOSHRINK,
				"SHIFT[%u, %u @ %" PRIx64
				" (0x%08zx)]: 0x%016" PRIx64
				" -> 0x%016" PRIx64 "\n",
				shift, size, new_pos, bit_offset, bits, nbits);
		write_bits_at_offset(pool, bit_offset + new_pos,
				(uint8_t)to_change, nbits);
		if (bits != nbits) {
			env->model.cur_set |= ASA_SHIFT;
			return true;
		}

		return false;
	}
	case MUT_MASK: {
		env->model.cur_tried |= ASA_MASK;
		// Clear each bit with 1/4 probability
		uint8_t  mask_size = (size <= 64 ? size : 64);
		uint64_t mask      = prng(mask_size, env->udata) |
				prng(mask_size, env->udata);
		if (mask == (uint64_t)(-1)) {
			// always clear at least 1 bit
			const uint8_t one_bit =
					prng(8, env->udata) % mask_size;
			mask &= ~(1LU << one_bit) + 1;
		}

		uint64_t new_pos   = 0;
		uint32_t to_change = 0;

		if (size > 64) { // Pick an offset and region to shift
			new_pos   = prng(32, env->udata) % size;
			to_change = (uint32_t)prng(6, env->udata);
			if (to_change > size - new_pos) {
				to_change = (uint32_t)(size - new_pos);
			}
		} else {
			to_change = (uint32_t)size;
		}
		const uint64_t bits  = read_bits_at_offset(pool,
				 bit_offset + new_pos, (uint8_t)to_change);
		const uint64_t nbits = bits & mask;
		LOG(2 - LOG_AUTOSHRINK,
				"MASK[0x%016" PRIx64 ", %u @ %" PRId64
				" (0x%08zx)]: 0x%016" PRIx64
				" -> 0x%016" PRIx64 "\n",
				mask, size, new_pos, bit_offset, bits, nbits);
		write_bits_at_offset(pool, bit_offset + new_pos,
				(uint8_t)to_change, nbits);
		if (bits != nbits) {
			env->model.cur_set |= ASA_MASK;
			return true;
		}

		return false;
	}
	case MUT_SWAP: {
		env->model.cur_tried |= ASA_SWAP;
		assert(size > 0);
		if (size > 64) {
			// maybe swap two blocks non-overlapping within the
			// request
			uint8_t to_swap = prng(6, env->udata);
			while (2U * to_swap >= size) {
				to_swap /= 2;
			}
			if (to_swap == 0) {
				return false;
			}
			assert(size - 2 * to_swap > 0);
			size_t pos_a = prng(32, env->udata) % (size - to_swap);
			size_t pos_b = prng(32, env->udata) %
				       (size - 2 * to_swap);
			if ((pos_a < pos_b && pos_a + to_swap > pos_b) ||
					(pos_b < pos_a &&
							pos_b + to_swap >
									pos_a)) {
				return false; // overlapping
			}

			const uint64_t a = read_bits_at_offset(
					pool, bit_offset + pos_a, to_swap);
			const uint64_t b = read_bits_at_offset(
					pool, bit_offset + pos_b, to_swap);
			if (b < a) {
				LOG(2 - LOG_AUTOSHRINK,
						"SWAPPING %zd <-> %zd "
						"(bulk)\n",
						bit_offset + pos_a,
						bit_offset + pos_b);
				write_bits_at_offset(pool, bit_offset + pos_a,
						to_swap, b);
				write_bits_at_offset(pool, bit_offset + pos_b,
						to_swap, a);
				env->model.cur_set |= ASA_SWAP;
				return true;
			}
			return false;
		} else { // maybe swap two requests with the same size
			LOG(4 - LOG_AUTOSHRINK, "SWAP at %zd...\n", pos);
			const uint64_t bits = read_bits_at_offset(
					pool, bit_offset, (uint8_t)size);

			// Find the next pos of the same size, if any.
			// Read both, and if the latter is lexicographically
			// smaller, swap.
			for (size_t i = pos + 1; i < orig->request_count;
					i++) {
				if (orig->requests[i] == size) {
					const size_t other_offset =
							offset_of_pos(orig, i);
					const uint64_t other = read_bits_at_offset(
							pool, other_offset,
							(uint8_t)size);
					if (other < bits) {
						LOG(2 - LOG_AUTOSHRINK,
								"SWAPPING %zd "
								"<-> %zd\n",
								pos, i);
						write_bits_at_offset(pool,
								bit_offset,
								(uint8_t)size,
								other);
						write_bits_at_offset(pool,
								other_offset,
								(uint8_t)size,
								bits);
						env->model.cur_set |= ASA_SWAP;
						return true;
					}
				}
			}
			LOG(2 - LOG_AUTOSHRINK,
					"NO SWAP (would not shrink)\n");
		}
		return false;
	}
	case MUT_SUB: {
		env->model.cur_tried |= ASA_SUB;
		uint8_t        sub_size  = (size <= 64 ? size : 64);
		const uint64_t sub       = prng(sub_size, env->udata);
		uint64_t       new_pos   = 0;
		uint32_t       to_change = 0;
		if (size > 64) { // Pick an offset and region to shift
			new_pos   = prng(32, env->udata) % size;
			to_change = prng(6, env->udata);
			if (to_change > size - new_pos) {
				to_change = size - new_pos;
			}
		} else { // just change the whole thing
			to_change = size;
		}
		uint64_t bits = read_bits_at_offset(
				pool, bit_offset + new_pos, to_change);
		if (bits > 0) {
			uint64_t nbits = bits - (sub % bits);
			if (nbits == bits) {
				nbits--;
			}
			LOG(2 - LOG_AUTOSHRINK,
					"SUB[%" PRIu64 ", %u @ %" PRId64
					" (0x%08zx)]: 0x%016" PRIx64
					" -> 0x%016" PRIx64 "\n",
					sub, size, new_pos, bit_offset, bits,
					nbits);
			env->model.cur_set |= ASA_SUB;
			write_bits_at_offset(pool, bit_offset + new_pos,
					to_change, nbits);
			return true;
		}
		return false;
	}
	}
}

static bool
build_index(struct autoshrink_bit_pool* pool)
{
	if (pool->index == NULL) {
		size_t* index = malloc(pool->request_count * sizeof(size_t));
		if (index == NULL) {
			return false;
		}

		size_t total = 0;
		for (size_t i = 0; i < pool->request_count; i++) {
			index[i] = total;
			total += pool->requests[i];
		}
		pool->index = index;
	}
	return true;
}

static size_t
offset_of_pos(const struct autoshrink_bit_pool* orig, size_t pos)
{
	assert(orig->index);
	return orig->index[pos];
}

static void
convert_bit_offset(size_t bit_offset, size_t* byte_offset, uint8_t* bit)
{
	*byte_offset = bit_offset / 8;
	*bit         = bit_offset % 8;
}

static uint64_t
read_bits_at_offset(const struct autoshrink_bit_pool* pool, size_t bit_offset,
		uint8_t size)
{
	size_t  byte = 0;
	uint8_t bit  = 0;
	convert_bit_offset(bit_offset, &byte, &bit);
	uint64_t acc   = 0;
	uint8_t  bit_i = 0x01 << bit;

	for (uint8_t i = 0; i < size; i++) {
		LOG(5, "byte %zd, size %zd\n", byte, pool->bits_filled);
		if (pool->bits[byte] & bit_i) {
			acc |= (1LLU << i);
		}
		bit_i <<= 1;
		if (bit_i == 0) {
			byte++;
			bit_i = 0x01;
		}
	}

	return acc;
}

static void
write_bits_at_offset(struct autoshrink_bit_pool* pool, size_t bit_offset,
		uint8_t size, uint64_t bits)
{
	size_t  byte = 0;
	uint8_t bit  = 0;
	convert_bit_offset(bit_offset, &byte, &bit);
	uint8_t bit_i = 0x01 << bit;

	for (uint8_t i = 0; i < size; i++) {
		if (bits & (1LLU << i)) {
			pool->bits[byte] |= bit_i;
		} else {
			pool->bits[byte] &= ~bit_i;
		}
		bit_i <<= 1;
		if (bit_i == 0) {
			byte++;
			bit_i = 0x01;
		}
	}
}

void
fuzz_autoshrink_dump_bit_pool(FILE* f, size_t bit_count,
		const struct autoshrink_bit_pool* pool, int print_mode)
{
	fprintf(f,
			"\n-- autoshrink [generation: %zd, requests: %zd -- "
			"%zd/%zd bits consumed]\n",
			pool->generation, pool->request_count, pool->consumed,
			pool->limit == (size_t)-1 ? pool->bits_filled
						  : pool->limit);
	bool prev = false;

	// Print the raw buffer.
	if (print_mode & FUZZ_AUTOSHRINK_PRINT_BIT_POOL) {
		prev                      = true;
		const uint8_t* bits       = pool->bits;
		const size_t   byte_count = bit_count / 8;
		const char     prefix[]   = "raw:  ";
		const char     left_pad[] = "      ";
		assert(strlen(prefix) == strlen(left_pad));

		fprintf(f, "%s", prefix);
		for (size_t i = 0; i < byte_count; i++) {
			const uint8_t byte =
					read_bits_at_offset(pool, 8 * i, 8);
			const uint8_t byte2 = bits[i];
			assert(byte == byte2);
			fprintf(f, "%02x ", byte);
			if ((i & 0x0f) == 0x0f) {
				fprintf(f, "\n%s", left_pad);
			} else if ((i & 0x03) == 0x03) {
				fprintf(f, " ");
			}
		}
		const uint8_t rem = bit_count % 8;
		if (rem != 0) {
			const uint8_t byte =
					bits[byte_count] & ((1U << rem) - 1);
			fprintf(f, "%02x/%d", byte, rem);
			if ((byte_count & 0x0f) == 0x0e) {
				fprintf(f, "\n");
				prev = false;
			}
		}
	}

	// Print the bit pool, grouped into requests -- this corresponds to
	// the actual values the caller gets from `fuzz_random_bits`.
	if (print_mode & FUZZ_AUTOSHRINK_PRINT_REQUESTS) {
		if (prev) {
			fprintf(f, "\n\n");
		}
		size_t offset = 0;
		if (pool->request_count > 0) {
			fprintf(f, "requests: (%zd)\n", pool->request_count);
		}
		for (size_t i = 0; i < pool->request_count; i++) {
			uint32_t req_size = pool->requests[i];
			if (offset + req_size > pool->bits_filled) {
				req_size = pool->bits_filled - offset;
			}
			if (req_size <= 64) { // fits in a uint64_t
				uint64_t bits = read_bits_at_offset(
						pool, offset, req_size);
				// Print as e.g. "3 -- 20 bits: 72 (0x48), "
				fprintf(f,
						"%zd -- %u bits: %" PRIu64
						" (0x%" PRIx64 ")\n",
						i, req_size, bits, bits);
			} else { // bulk request
				// Print as e.g. "4 -- 72 bits:
				// [ a5 52 29 14 0a 05 82 c1 60 ]"
				char   header[64];
				size_t header_used = snprintf(header,
						sizeof(header),
						"%zd -- %u bits: [ ", i,
						req_size);
				assert(header_used < sizeof(header));
				char* left_pad = calloc(header_used + 1, 1);
				// TODO: don't assert here
				assert(left_pad != NULL);
				for (size_t pad_i = 0; pad_i < header_used;
						pad_i++) {
					left_pad[pad_i] = ' ';
				}
				left_pad[header_used] = '\0';

				fprintf(f, "%s", header);
				const uint32_t byte_count = req_size / 8;
				const uint32_t rem        = req_size % 8;

				for (size_t bi = 0; bi < byte_count; bi++) {
					uint8_t bits = read_bits_at_offset(
							pool, offset + 8 * bi,
							8);
					fprintf(f, "%02x ", bits);
					if ((bi & 15) == 15) {
						// Add enough spaces to align
						// with the previous line
						fprintf(f, "\n%s", left_pad);
					} else if ((bi & 3) == 3) {
						fprintf(f, " ");
					}
				}
				if (rem > 0) {
					uint8_t bits = read_bits_at_offset(
							pool,
							offset + byte_count,
							rem);
					fprintf(f, "%02x/%u ", bits, rem);
				}
				fprintf(f, "]\n");
				free(left_pad);
			}
			offset += req_size;
		}
	}
}

void
fuzz_autoshrink_print(struct fuzz* t, FILE* f, struct autoshrink_env* env,
		const void* instance, void* type_env)
{
	// If the user has a print callback defined, use it on
	// the instance, otherwise print the bit pool.
	const struct fuzz_type_info*    ti = t->prop.type_info[env->arg_i];
	enum fuzz_autoshrink_print_mode print_mode = env->print_mode;

	// Default the print mode to either requests or (when provided)
	// just calling the user print callback.
	if (print_mode == FUZZ_AUTOSHRINK_PRINT_DEFAULT) {
		print_mode = (ti->print == NULL ? FUZZ_AUTOSHRINK_PRINT_REQUESTS
						: FUZZ_AUTOSHRINK_PRINT_USER);
	}

	if (ti->print) {
		ti->print(f, instance, type_env);
	}

	struct autoshrink_bit_pool* pool = env->bit_pool;
	assert(pool->bits_ceil >= pool->consumed);
	fuzz_autoshrink_dump_bit_pool(f, pool->consumed, pool, print_mode);
}

static bool
append_request(struct autoshrink_bit_pool* pool, uint32_t bit_count)
{
	assert(pool);
	if (pool->request_count == pool->request_ceil) { // grow
		size_t    nceil     = pool->request_ceil * 2;
		uint32_t* nrequests = realloc(
				pool->requests, nceil * sizeof(*nrequests));
		if (nrequests == NULL) {
			return false;
		}
		pool->requests     = nrequests;
		pool->request_ceil = nceil;
	}

	LOG(4, "appending request %zd for %u bits\n", pool->request_count,
			bit_count);
	pool->requests[pool->request_count] = bit_count;
	pool->request_count++;
	return true;
}

static uint64_t
def_autoshrink_prng(uint8_t bits, void* udata)
{
	struct fuzz* t = (struct fuzz*)udata;
	return fuzz_random_bits(t, bits);
}

static autoshrink_prng_fun*
get_prng(struct fuzz* t, struct autoshrink_env* env)
{
	if (env->prng) {
		return env->prng;
	} else {
		env->udata = t;
		return def_autoshrink_prng;
	}
}

static void
init_model(struct autoshrink_env* env)
{
	if (env->model.next_action != 0x00) {
		return; // a test has an action scheduled
	}
	env->model = (struct autoshrink_model){
			.weights =
					{
							[WEIGHT_DROP] = TWO_EVENLY,
							[WEIGHT_SHIFT] =
									FOUR_EVENLY,
							[WEIGHT_MASK] = FOUR_EVENLY,
							[WEIGHT_SWAP] = FOUR_EVENLY -
									0x10,
							[WEIGHT_SUB] = FOUR_EVENLY,
					},
	};
}

static bool
should_drop(struct fuzz* t, struct autoshrink_env* env, size_t request_count)
{
	autoshrink_prng_fun* prng = get_prng(t, env);
	// Limit the odds of dropping when there are only a few requests
	const int rc_mul = 8;
	uint8_t   weight = env->model.weights[WEIGHT_DROP];
	if (weight > rc_mul * request_count) {
		weight = rc_mul * request_count;
	}
	if (env->model.next_action == 0x00) {
		return prng(8, env->udata) < weight;
	} else {
		return env->model.next_action == ASA_DROP;
	}
}

static enum mutation
get_weighted_mutation(struct fuzz* t, struct autoshrink_env* env)
{
	if (env->model.next_action != 0x00) {
		switch (env->model.next_action) {
		default:
			assert(false);
		case ASA_SHIFT:
			return MUT_SHIFT;
		case ASA_MASK:
			return MUT_MASK;
		case ASA_SWAP:
			return MUT_SWAP;
		case ASA_SUB:
			return MUT_SUB;
		}
	}

	const uint16_t shift = env->model.weights[WEIGHT_SHIFT];
	const uint16_t mask  = shift + env->model.weights[WEIGHT_MASK];
	const uint16_t swap  = mask + env->model.weights[WEIGHT_SWAP];
	const uint16_t sub   = swap + env->model.weights[WEIGHT_SUB];

	LOG(4 - LOG_AUTOSHRINK,
			"%s: shift %04x, mask %04x, swap %04x, sub %04x => "
			"LIMIT %04x\n",
			__func__, env->model.weights[WEIGHT_SHIFT],
			env->model.weights[WEIGHT_MASK],
			env->model.weights[WEIGHT_SWAP],
			env->model.weights[WEIGHT_SUB], sub);
	uint8_t bit_count = 7;
	while ((1LU << bit_count) < sub) {
		bit_count++;
	}
	assert(bit_count <= 16);

	for (;;) {
		const uint16_t bits = fuzz_random_bits(t, bit_count);
		LOG(4 - LOG_AUTOSHRINK, "%s: 0x%04x -- ", __func__, bits);
		if (bits < shift) {
			LOG(4 - LOG_AUTOSHRINK, "SHIFT\n");
			return MUT_SHIFT;
		} else if (bits < mask) {
			LOG(4 - LOG_AUTOSHRINK, "MASK\n");
			return MUT_MASK;
		} else if (bits < swap) {
			LOG(4 - LOG_AUTOSHRINK, "SWAP\n");
			return MUT_SWAP;
		} else if (bits < sub) {
			LOG(4 - LOG_AUTOSHRINK, "SUB\n");
			return MUT_SUB;
		} else {
			LOG(4 - LOG_AUTOSHRINK, "continue\n");
			continue; // draw again
		}
	}
}

static void
adjust(struct autoshrink_model* model, enum autoshrink_weight w, uint8_t min,
		uint8_t max, int8_t adjustment)
{
	enum autoshrink_action flag = (enum autoshrink_action)(1U << w);
	uint8_t                nv   = 0;
	if (model->cur_set & flag) {
		nv = model->weights[w] + adjustment;
	} else if ((model->cur_tried & flag) && adjustment > 0) {
		// De-emphasize actions that produced no changes, but don't add
		// emphasis to them if they caused the property to pass
		// (leading to a negative adjustment)
		LOG(3 - LOG_AUTOSHRINK, "DE-EMPHASIZING flag 0x%02x by %u\n",
				flag, adjustment);
		nv = model->weights[w] - adjustment;
		LOG(3 - LOG_AUTOSHRINK, "  -- was %u, now %u\n",
				model->weights[w], nv);
	}

	if (nv != 0) {
		if (nv > max) {
			nv = max;
		} else if (nv < min) {
			nv = min;
		}
		model->weights[w] = nv;
	}
}

void
fuzz_autoshrink_update_model(
		struct fuzz* t, uint8_t arg_id, int res, uint8_t adjustment)
{
	// If this type isn't using autoshrink, there's nothing to do.
	if (t->prop.type_info[arg_id]->autoshrink_config.enable == false) {
		return;
	}

	struct autoshrink_env* env = t->trial.args[arg_id].u.as.env;

	const uint8_t cur_set = env->model.cur_set;
	if (cur_set == 0x00) {
		return;
	}

	uint8_t adj = (res == FUZZ_RESULT_FAIL ? adjustment : -adjustment);

	LOG(3 - LOG_AUTOSHRINK,
			"%s: res %d, arg_id %u, adj %u, cur_set 0x%02x\n",
			__func__, res, arg_id, adjustment, cur_set);

	adjust(&env->model, WEIGHT_DROP, DROPS_MIN, DROPS_MAX, adj);
	adjust(&env->model, WEIGHT_SHIFT, MODEL_MIN, MODEL_MAX, adj);
	adjust(&env->model, WEIGHT_MASK, MODEL_MIN, MODEL_MAX, adj);
	adjust(&env->model, WEIGHT_SWAP, MODEL_MIN, MODEL_MAX, adj);
	adjust(&env->model, WEIGHT_SUB, MODEL_MIN, MODEL_MAX, adj);

	LOG(3 - LOG_AUTOSHRINK,
			"cur_set: %02" PRIx8 " -- new weights DROP %u SHIFT "
			"%u MASK %u SWAP %u SUB %u\n",
			(uint8_t)env->model.cur_set,
			env->model.weights[WEIGHT_DROP],
			env->model.weights[WEIGHT_SHIFT],
			env->model.weights[WEIGHT_MASK],
			env->model.weights[WEIGHT_SWAP],
			env->model.weights[WEIGHT_SUB]);
}

void
fuzz_autoshrink_model_set_next(
		struct autoshrink_env* env, enum autoshrink_action action)
{
	env->model.next_action = action;
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

struct type_info_row {
	enum fuzz_builtin_type_info key;
	struct fuzz_type_info       value;
};

static int
bool_alloc(struct fuzz* t, void* env, void** instance)
{
	(void)env;
	bool* res = malloc(sizeof(*res));
	if (res == NULL) {
		return FUZZ_RESULT_ERROR;
	}
	*res      = (bool)fuzz_random_bits(t, 1);
	*instance = res;
	return FUZZ_RESULT_OK;
}

#define BITS_USE_SPECIAL (3)

#define ALLOC_USCALAR(NAME, TYPE, BITS, ...)                                  \
	static int NAME##_alloc(struct fuzz* t, void* env, void** instance)   \
	{                                                                     \
		TYPE* res = malloc(sizeof(*res));                             \
		if (res == NULL) {                                            \
			return FUZZ_RESULT_ERROR;                             \
		}                                                             \
		if (((1LU << BITS_USE_SPECIAL) - 1) ==                        \
				fuzz_random_bits(t, BITS_USE_SPECIAL)) {      \
			const TYPE special[] = {__VA_ARGS__};                 \
			size_t     idx       = fuzz_random_bits(t, 8) %       \
				     (sizeof(special) / sizeof(special[0]));  \
			*res = special[idx];                                  \
		} else {                                                      \
			*res = (TYPE)fuzz_random_bits(t, BITS);               \
		}                                                             \
		if (env != NULL) {                                            \
			TYPE limit = *(TYPE*)env;                             \
			assert(limit != 0);                                   \
			(*res) %= limit;                                      \
		}                                                             \
		*instance = res;                                              \
		return FUZZ_RESULT_OK;                                        \
	}

#define ALLOC_SSCALAR(NAME, TYPE, BITS, ...)                                  \
	static int NAME##_alloc(struct fuzz* t, void* env, void** instance)   \
	{                                                                     \
		TYPE* res = malloc(sizeof(*res));                             \
		if (res == NULL) {                                            \
			return FUZZ_RESULT_ERROR;                             \
		}                                                             \
		if (((1LU << BITS_USE_SPECIAL) - 1) ==                        \
				fuzz_random_bits(t, BITS_USE_SPECIAL)) {      \
			const TYPE special[] = {__VA_ARGS__};                 \
			size_t     idx       = fuzz_random_bits(t, 8) %       \
				     (sizeof(special) / sizeof(special[0]));  \
			*res = special[idx];                                  \
		} else {                                                      \
			*res = (TYPE)fuzz_random_bits(t, BITS);               \
		}                                                             \
		if (env != NULL) {                                            \
			TYPE limit = *(TYPE*)env;                             \
			assert(limit > 0); /* -limit <= res < limit */        \
			if (*res < (-limit)) {                                \
				*res %= (-limit);                             \
			} else if (*res >= limit) {                           \
				(*res) %= limit;                              \
			}                                                     \
		}                                                             \
		*instance = res;                                              \
		return FUZZ_RESULT_OK;                                        \
	}

#define ALLOC_FSCALAR(NAME, TYPE, MOD, BITS, ...)                             \
	static int NAME##_alloc(struct fuzz* t, void* env, void** instance)   \
	{                                                                     \
		TYPE* res = malloc(sizeof(*res));                             \
		if (res == NULL) {                                            \
			return FUZZ_RESULT_ERROR;                             \
		}                                                             \
		if (((1LU << BITS_USE_SPECIAL) - 1) ==                        \
				fuzz_random_bits(t, BITS_USE_SPECIAL)) {      \
			const TYPE special[] = {__VA_ARGS__};                 \
			size_t     idx       = fuzz_random_bits(t, 8) %       \
				     (sizeof(special) / sizeof(special[0]));  \
			*res = special[idx];                                  \
		} else {                                                      \
			*res = (TYPE)fuzz_random_bits(t, BITS);               \
		}                                                             \
		if (env != NULL) {                                            \
			TYPE limit = *(TYPE*)env;                             \
			assert(limit > 0); /* -limit <= res < limit */        \
			if (*res < (-limit)) {                                \
				*res = MOD(*res, -limit);                     \
			} else {                                              \
				*res = MOD(*res, limit);                      \
			}                                                     \
		}                                                             \
		*instance = res;                                              \
		return FUZZ_RESULT_OK;                                        \
	}

#define PRINT_SCALAR(NAME, TYPE, FORMAT)                                      \
	static void NAME##_print(FILE* f, const void* instance, void* env)    \
	{                                                                     \
		(void)env;                                                    \
		fprintf(f, FORMAT, *(TYPE*)instance);                         \
	}

ALLOC_USCALAR(uint, unsigned int, 8 * sizeof(unsigned int), 0, 1, 2, 3, 4, 5,
		6, 7, 63, 64, 127, 128, 129, 255, UINT_MAX - 1, UINT_MAX)

ALLOC_USCALAR(uint8_t, uint8_t, 8 * sizeof(uint8_t), 0, 1, 2, 3, 4, 5, 6, 7,
		63, 64, 65, 127, 128, 129, 254, 255)

ALLOC_USCALAR(uint16_t, uint16_t, 8 * sizeof(uint16_t), 0, 1, 2, 3, 4, 5, 6,
		255, 256, 1024, 4096, 16384, 32768, 32769, 65534, 65535)

ALLOC_USCALAR(uint32_t, uint32_t, 8 * sizeof(uint32_t), 0, 1, 2, 3, 4, 5, 6,
		255, (1LU << 8), (1LU << 8) + 1, (1LU << 16) - 1, (1LU << 16),
		(1LU << 16) + 1, (1LU << 19), (1LU << 22), (1LLU << 32) - 1)

ALLOC_USCALAR(uint64_t, uint64_t, 8 * sizeof(uint64_t), 0, 1, 2, 3, 4, 5, 6,
		255, (1LLU << 8), (1LLU << 16), (1LLU << 32), (1LLU << 32) + 1,
		(1LLU << 53), (1LLU << 53) + 1, (uint64_t)-2, (uint64_t)-1)

ALLOC_USCALAR(size_t, size_t, 8 * sizeof(size_t), 0, 1, 2, 3, 4, 5, 6, 255,
		256, (size_t)-2, (size_t)-1)

ALLOC_SSCALAR(int, int, 8 * sizeof(int), 0, 1, 2, 3, -1, -2, -3, -4,
		INT_MIN + 1, INT_MIN, INT_MAX - 1, INT_MAX)

ALLOC_SSCALAR(int8_t, int8_t, 8 * sizeof(int8_t), 0, 1, 2, 3, -1, -2, -3, -4,
		63, 64, 65, 127, -128, -127, -2, -1)

ALLOC_SSCALAR(int16_t, int16_t, 8 * sizeof(int16_t), 0, 1, 2, 3, 4, 5, 6, 255,
		256, 1024, 4096, 16384, (int16_t)32768, (int16_t)32769,
		(int16_t)65534, (int16_t)65535)

ALLOC_SSCALAR(int32_t, int32_t, 8 * sizeof(int32_t), 0, 1, 2, 3, 4, 5, 6, 255,
		(1LU << 8), (1LU << 8) + 1, (1LU << 16) - 1, (1LU << 16),
		(int32_t)(1LU << 16) + 1, (int32_t)(1LU << 19),
		(int32_t)(1LU << 22), (int32_t)(1LLU << 32) - 1)

ALLOC_SSCALAR(int64_t, int64_t, 8 * sizeof(int64_t), 0, 1, 2, 3, 4, 5, 6, 255,
		(1LLU << 8), (1LLU << 16), (1LLU << 32), (1LLU << 32) + 1,
		(1LLU << 53), (1LLU << 53) + 1, (int64_t)-2, (int64_t)-1)

PRINT_SCALAR(bool, bool, "%d")
PRINT_SCALAR(uint, unsigned int, "%u")
PRINT_SCALAR(uint8_t, uint8_t, "%" PRIu8)
PRINT_SCALAR(uint16_t, uint16_t, "%" PRIu16)
PRINT_SCALAR(uint32_t, uint32_t, "%" PRIu32)
PRINT_SCALAR(uint64_t, uint64_t, "%" PRIu64)
PRINT_SCALAR(size_t, size_t, "%zu")

PRINT_SCALAR(int, int, "%d")
PRINT_SCALAR(int8_t, int8_t, "%" PRId8)
PRINT_SCALAR(int16_t, int16_t, "%" PRId16)
PRINT_SCALAR(int32_t, int32_t, "%" PRId32)
PRINT_SCALAR(int64_t, int64_t, "%" PRId64)

#if FUZZ_USE_FLOATING_POINT
#include <float.h>
#include <math.h>
ALLOC_FSCALAR(float, float, fmodf, 8 * sizeof(float), 0, 1, -1, NAN, INFINITY,
		-INFINITY, FLT_MIN, FLT_MAX)
ALLOC_FSCALAR(double, double, fmod, 8 * sizeof(double), 0, 1, -1, NAN, NAN,
		INFINITY, -INFINITY, DBL_MIN, DBL_MAX)

static void
float_print(FILE* f, const void* instance, void* env)
{
	(void)env;
	float    fl  = *(float*)instance;
	uint32_t u32 = (uint32_t)fl;
	fprintf(f, "%g (0x%08" PRIx32 ")", fl, u32);
}

static void
double_print(FILE* f, const void* instance, void* env)
{
	(void)env;
	double   d   = *(double*)instance;
	uint64_t u64 = (uint64_t)d;
	fprintf(f, "%g (0x%016" PRIx64 ")", d, u64);
}

#endif

#define SCALAR_ROW(NAME)                                                        \
	{                                                                       \
		.key   = FUZZ_BUILTIN_##NAME,                                   \
		.value = {                                                      \
				.alloc = NAME##_alloc,                          \
				.free  = fuzz_generic_free_cb,                  \
				.print = NAME##_print,                          \
				.autoshrink_config =                            \
						{                               \
								.enable = true, \
						},                              \
		},                                                              \
	}

#define DEF_BYTE_ARRAY_CEIL 8
static int
char_ARRAY_alloc(struct fuzz* t, void* env, void** instance)
{
	(void)env;
	size_t  ceil       = DEF_BYTE_ARRAY_CEIL;
	size_t  size       = 0;
	size_t* max_length = NULL;
	if (env != NULL) {
		max_length = (size_t*)env;
		assert(*max_length > 0);
	}

	char* res = malloc(ceil * sizeof(char));
	if (res == NULL) {
		return FUZZ_RESULT_ERROR;
	}
	while (true) {
		if (max_length != NULL && size + 1 == *max_length) {
			res[size] = 0;
			break;
		} else if (size == ceil) {
			const size_t nceil = 2 * ceil;
			char*        nres = realloc(res, nceil * sizeof(char));
			if (nres == NULL) {
				free(res);
				return FUZZ_RESULT_ERROR;
			}
			res  = nres;
			ceil = nceil;
		}
		char byte = fuzz_random_bits(t, 8);
		res[size] = byte;
		if (byte == 0x00) {
			break;
		}
		size++;
	}

	*instance = res;
	return FUZZ_RESULT_OK;
}

static void
hexdump(FILE* f, const uint8_t* raw, size_t size)
{
	for (size_t row_i = 0; row_i < size; row_i += 16) {
		size_t rem = (size - row_i > 16 ? 16 : size - row_i);
		fprintf(f, "%04zx: ", row_i);
		for (size_t i = 0; i < rem; i++) {
			fprintf(f, "%02x ", raw[row_i + i]);
		}

		for (size_t ii = rem; ii < 16; ++ii)
			fprintf(f, "   "); /* add padding */

		for (size_t i = 0; i < rem; i++) {
			char c = ((const char*)raw)[i];
			fprintf(f, "%c", (isprint(c) ? c : '.'));
		}
		fprintf(f, "\n");
	}
}

static void
char_ARRAY_print(FILE* f, const void* instance, void* env)
{
	(void)env;
	const char* s   = (const char*)instance;
	size_t      len = strlen(s);
	hexdump(f, (const uint8_t*)s, len);
}

static struct type_info_row rows[] = {
		{
				.key = FUZZ_BUILTIN_bool,
				.value =
						{
								.alloc = bool_alloc,
								.free = fuzz_generic_free_cb,
								.print = bool_print,
								.autoshrink_config =
										{
												.enable = true,
										},
						},
		},
		SCALAR_ROW(uint),
		SCALAR_ROW(uint8_t),
		SCALAR_ROW(uint16_t),
		SCALAR_ROW(uint32_t),
		SCALAR_ROW(uint64_t),
		SCALAR_ROW(size_t),

		SCALAR_ROW(int),
		SCALAR_ROW(int8_t),
		SCALAR_ROW(int16_t),
		SCALAR_ROW(int32_t),
		SCALAR_ROW(int64_t),

#if FUZZ_USE_FLOATING_POINT
		SCALAR_ROW(float),
		SCALAR_ROW(double),
#endif

		{
				.key = FUZZ_BUILTIN_char_ARRAY,
				.value =
						{
								.alloc = char_ARRAY_alloc,
								.free = fuzz_generic_free_cb,
								.print = char_ARRAY_print,
								.autoshrink_config =
										{
												.enable = true,
										},
						},
		},
		// This is actually the same implementation, but
		// the user should cast it differently.
		{
				.key = FUZZ_BUILTIN_uint8_t_ARRAY,
				.value =
						{
								.alloc = char_ARRAY_alloc,
								.free = fuzz_generic_free_cb,
								.print = char_ARRAY_print,
								.autoshrink_config =
										{
												.enable = true,
										},
						},
		},
};

const struct fuzz_type_info*
fuzz_get_builtin_type_info(enum fuzz_builtin_type_info type)
{
	for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		const struct type_info_row* row = &rows[i];
		if (row->key == type) {
			return &row->value;
		}
	}
	assert(false);
	return NULL;
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <stdlib.h>

#if !defined(_WIN32)
#include <sys/time.h>
#endif

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2022 Ayman El Didi
#ifndef FUZZ_POLYFILL_H
#define FUZZ_POLYFILL_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#define FUZZ_POLYFILL_HAVE_FORK true
#if defined(_WIN32)
#undef FUZZ_POLYFILL_HAVE_FORK
#define FUZZ_POLYFILL_HAVE_FORK false
#include "poll_windows.h"

// Windows's read() function returns int.
typedef int ssize_t;

struct timespec;

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

typedef int pid_t;

// Not actually used. Here to silence "incomplete type" warnings.
struct sigaction {
	void (*sa_handler)(int);
	void (*sa_sigaction)(int, void*, void*);
	int sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};

// Not actually used. Here to silence "incomplete type" warnings.
struct rlimit {
	int rlim_cur;
	int rlim_max;
};

#define RLIMIT_CPU     0
#define SIGKILL        0
#define SIGUSR1        0
#define WIFEXITED(x)   ((void)(x), 0)
#define WEXITSTATUS(x) ((void)(x), 0)
#define WNOHANG        0

// POSIX pipe(2)
int pipe(int pipefd[2]);

// POSIX nanosleep(2)
int nanosleep(const struct timespec* req, struct timespec* rem);

// Not actually implemented. Disabled on Windows.
int fork();

int gettimeofday(struct timeval* tp, struct timezone* tzp);

// When POLYFILL_HAVE_FORK is false, these do nothing and are never called.
// They only exist to prevent linker errors.
int wait(int* status);
int waitpid(int pid, int* status, int options);
int kill(int pid, int sig);

int sigaction(int signum, const struct sigaction* act,
		struct sigaction* oldact);

int setrlimit(int resource, const struct rlimit* rlim);
int getrlimit(int resource, struct rlimit* rlim);
#endif

#endif // FUZZ_POLYFILL_H

// Name used when no property name is set.
static const char def_prop_name[] = "(anonymous)";

uint64_t
fuzz_seed_of_time(void)
{
	struct timeval tv = {0, 0};
	if (-1 == gettimeofday(&tv, NULL)) {
		return 0;
	}

	return (uint64_t)fuzz_hash_onepass((const uint8_t*)&tv, sizeof(tv));
}

void
fuzz_generic_free_cb(void* instance, void* env)
{
	(void)env;
	free(instance);
}

// Print a tally marker for a trial result, but if there have been
// SCALE_FACTOR consecutive ones, increase the scale by an
// order of magnitude.
static size_t
autoscale_tally(char* buf, size_t buf_size, size_t scale_factor, char* name,
		size_t* cur_scale, char tally, size_t* count)
{
	const size_t scale  = *cur_scale == 0 ? 1 : *cur_scale;
	const size_t nscale = scale_factor * scale;
	size_t       used   = 0;
	if (scale > 1 || *count >= nscale) {
		if (*count == nscale) {
			used = snprintf(buf, buf_size, "(%s x %zd)%c", name,
					nscale, tally);
			*cur_scale = nscale;
		} else if ((*count % scale) == 0) {
			used = snprintf(buf, buf_size, "%c", tally);
		} else {
			buf[0] = '\0'; // truncate -- print nothing
		}
	} else {
		used = snprintf(buf, buf_size, "%c", tally);
	}
	(*count)++;
	return used;
}

void
fuzz_print_trial_result(struct fuzz_print_trial_result_env* env,
		const struct fuzz_post_trial_info*          info)
{
	assert(env);
	assert(info);

	struct fuzz* t = info->t;
	if (t->print_trial_result_env == env) {
		assert(t->print_trial_result_env->tag ==
				FUZZ_PRINT_TRIAL_RESULT_ENV_TAG);
	} else if ((t->hooks.trial_post !=
				   fuzz_hook_trial_post_print_result) &&
			env == t->hooks.env) {
		if (env != NULL &&
				env->tag != FUZZ_PRINT_TRIAL_RESULT_ENV_TAG) {
			fprintf(stderr, "\n"
					"WARNING: The *env passed to "
					"trial_print_trial_result is probably "
					"not\n"
					"a `fuzz_print_trial_result_env` "
					"struct -- to suppress this warning,\n"
					"set env->tag to "
					"FUZZ_PRINT_TRIAL_RESULT_ENV_TAG.\n");
		}
	}

	const uint8_t maxcol = (env->max_column == 0 ? FUZZ_DEF_MAX_COLUMNS
						     : env->max_column);

	size_t used = 0;
	char   buf[64];

	switch (info->result) {
	case FUZZ_RESULT_OK:
		used = autoscale_tally(buf, sizeof(buf), 100, "PASS",
				&env->scale_pass, '.', &env->consec_pass);
		break;
	case FUZZ_RESULT_FAIL:
		used             = snprintf(buf, sizeof(buf), "F");
		env->scale_pass  = 1;
		env->consec_pass = 0;
		env->column      = 0;
		break;
	case FUZZ_RESULT_SKIP:
		used = autoscale_tally(buf, sizeof(buf), 10, "SKIP",
				&env->scale_skip, 's', &env->consec_skip);
		break;
	case FUZZ_RESULT_DUPLICATE:
		used = autoscale_tally(buf, sizeof(buf), 10, "DUP",
				&env->scale_dup, 'd', &env->consec_dup);
		break;
	case FUZZ_RESULT_ERROR:
		used = snprintf(buf, sizeof(buf), "E");
		break;
	default:
		assert(false);
		return;
	}

	assert(info->t);
	FILE* f = (info->t->out == NULL ? stdout : info->t->out);

	if (env->column + used >= maxcol) {
		fprintf(f, "\n");
		env->column = 0;
	}

	fprintf(f, "%s", buf);
	fflush(f);
	assert(used <= UINT8_MAX);
	env->column += (uint8_t)used;
}

int
fuzz_hook_first_fail_halt(const struct fuzz_pre_trial_info* info, void* env)
{
	(void)env;
	return info->failures > 0 ? FUZZ_HOOK_RUN_HALT
				  : FUZZ_HOOK_RUN_CONTINUE;
}

int
fuzz_hook_trial_post_print_result(
		const struct fuzz_post_trial_info* info, void* env)
{
	fuzz_print_trial_result(
			(struct fuzz_print_trial_result_env*)env, info);
	return FUZZ_HOOK_RUN_CONTINUE;
}

int
fuzz_print_counterexample(
		const struct fuzz_counterexample_info* info, void* env)
{
	(void)env;
	struct fuzz* t     = info->t;
	int          arity = info->arity;
	fprintf(t->out, "\n\n -- Counter-Example: %s\n",
			info->prop_name ? info->prop_name : "");
	fprintf(t->out, "    Trial %zd, Seed 0x%016" PRIx64 "\n",
			info->trial_id, (uint64_t)info->trial_seed);
	for (int i = 0; i < arity; i++) {
		struct fuzz_type_info* ti = info->type_info[i];
		if (ti->print) {
			fprintf(t->out, "    Argument %d:\n", i);
			ti->print(t->out, info->args[i], ti->env);
			fprintf(t->out, "\n");
		}
	}
	return FUZZ_HOOK_RUN_CONTINUE;
}

void
fuzz_print_pre_run_info(FILE* f, const struct fuzz_pre_run_info* info)
{
	const char* prop_name =
			info->prop_name ? info->prop_name : def_prop_name;
	fprintf(f, "\n== PROP '%s': %zd trials, seed 0x%016" PRIx64 "\n",
			prop_name, info->total_trials, info->run_seed);
}

int
fuzz_pre_run_hook_print_info(const struct fuzz_pre_run_info* info, void* env)
{
	(void)env;
	fuzz_print_pre_run_info(stdout, info);
	return FUZZ_HOOK_RUN_CONTINUE;
}

void
fuzz_print_post_run_info(FILE* f, const struct fuzz_post_run_info* info)
{
	const struct fuzz_run_report* r = &info->report;
	const char*                   prop_name =
                        info->prop_name ? info->prop_name : def_prop_name;
	fprintf(f, "\n== %s '%s': pass %zd, fail %zd, skip %zd, dup %zd\n",
			r->fail > 0 ? "FAIL" : "PASS", prop_name, r->pass,
			r->fail, r->skip, r->dup);
}

int
fuzz_post_run_hook_print_info(const struct fuzz_post_run_info* info, void* env)
{
	(void)env;
	fuzz_print_post_run_info(stdout, info);
	return FUZZ_HOOK_RUN_CONTINUE;
}

void*
fuzz_hook_get_env(struct fuzz* t)
{
	return t->hooks.env;
}

struct fuzz_aux_print_trial_result_env {
	FILE*         f;          // 0 -> default of stdout
	const uint8_t max_column; // 0 -> default of DEF_MAX_COLUMNS

	uint8_t column;
	size_t  consec_pass;
	size_t  consec_fail;
};

const char*
fuzz_result_str(int res)
{
	switch (res) {
	case FUZZ_RESULT_OK:
		return "PASS";
	case FUZZ_RESULT_FAIL:
		return "FAIL";
	case FUZZ_RESULT_SKIP:
		return "SKIP";
	case FUZZ_RESULT_DUPLICATE:
		return "DUP";
	case FUZZ_RESULT_ERROR:
		return "ERROR";
	case FUZZ_RESULT_ERROR_MEMORY:
		return "ALLOCATION ERROR";
	default:
		return "(matchfail)";
	}
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_BLOOM_H
#define FUZZ_BLOOM_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

// Opaque type for bloom filter.
struct fuzz_bloom;

struct fuzz_bloom_config {
	uint8_t top_block_bits;
	uint8_t min_filter_bits;
};

// Initialize a bloom filter.
struct fuzz_bloom* fuzz_bloom_init(const struct fuzz_bloom_config* config);

// Hash data and mark it in the bloom filter.
bool fuzz_bloom_mark(struct fuzz_bloom* b, uint8_t* data, size_t data_size);

// Check whether the data's hash is in the bloom filter.
bool fuzz_bloom_check(struct fuzz_bloom* b, uint8_t* data, size_t data_size);

// Free the bloom filter.
void fuzz_bloom_free(struct fuzz_bloom* b);

#endif

// This is a dynamic blocked bloom filter, loosely based on
// _Cache Efficient Bloom Filters for Shared Memory Machines_
// by Tim Kaler.
//
// The top level of the bloom filter uses the first N bits of the hash
// (top_block2) to choose between (1 << N) distinct bloom filter blocks.
// These blocks are created as necessary, i.e., a NULL block means no
// bits in that block would have been set.
//
// When checking for matches, HASH_COUNT different chunks of M bits from
// the hash are used to check each block's bloom filter. (M is
// block->size2, and the bloom filter has (1 << M) bits.) If any of
// the selected bits are false, there was no match. Every bloom filter
// in the block's linked list is checked, so all must match for
// `fuzz_bloom_check` to return true.
//
// When marking, only the front (largest) bloom filter in the
// appropriate block is updated. If marking did not change any
// bits (all bits chosen by the hash were already set), then
// the bloom filter is considered too full, and a new one is
// inserted before it, as the new head of the block. The new
// bloom filter's size2 is one larger, so more bits of the hash
// are used, and the bloom filter doubles in size.

// Default number of bits to use for choosing a specific
// block (linked list of bloom filters)
#define DEF_TOP_BLOCK_BITS 9

// Default number of bits in each first-layer bloom filter
#define DEF_MIN_FILTER_BITS 9

// How many hashes to check for each block
#define HASH_COUNT 4

#define LOG_BLOOM 0

struct bloom_filter {
	struct bloom_filter* next;
	uint8_t              size2; // log2 of bit count
	uint8_t              bits[];
};

struct fuzz_bloom {
	const uint8_t top_block2;
	const uint8_t min_filter2;
	// These start as NULL and are lazily allocated.
	// Each block is a linked list of bloom filters, with successively
	// larger filters appended at the front as the filters fill up.
	struct bloom_filter* blocks[];
};

static struct fuzz_bloom_config def_config = {.top_block_bits = 0};

// Initialize a dynamic blocked bloom filter.
struct fuzz_bloom*
fuzz_bloom_init(const struct fuzz_bloom_config* config)
{
#define DEF(X, DEFAULT) (X ? X : DEFAULT)
	config = DEF(config, &def_config);
	const uint8_t top_block2 =
			DEF(config->top_block_bits, DEF_TOP_BLOCK_BITS);
	const uint8_t min_filter2 =
			DEF(config->min_filter_bits, DEF_MIN_FILTER_BITS);
#undef DEF

	const size_t top_block_count = (1LLU << top_block2);
	const size_t alloc_size =
			sizeof(struct fuzz_bloom) +
			top_block_count * sizeof(struct bloom_filter*);

	struct fuzz_bloom* res = malloc(alloc_size);
	if (res == NULL) {
		return NULL;
	}
	memset(&res->blocks, 0x00,
			top_block_count * sizeof(struct bloom_filter*));

	struct fuzz_bloom b = {
			.top_block2  = top_block2,
			.min_filter2 = min_filter2,
	};
	memcpy(res, &b, sizeof(b));
	return res;
}

static struct bloom_filter*
alloc_filter(uint8_t bits)
{
	const size_t alloc_size =
			sizeof(struct bloom_filter) + ((1LLU << bits) / 8);
	struct bloom_filter* bf = malloc(alloc_size);
	if (bf != NULL) {
		memset(bf, 0x00, alloc_size);
		bf->size2 = bits;
		LOG(4 - LOG_BLOOM, "%s: %p [size2 %u (%zd bytes)]\n", __func__,
				(void*)bf, bf->size2,
				(size_t)((1LLU << bf->size2) / 8));
	}
	return bf;
}

// Hash data and mark it in the bloom filter.
bool
fuzz_bloom_mark(struct fuzz_bloom* b, uint8_t* data, size_t data_size)
{
	uint64_t     hash            = fuzz_hash_onepass(data, data_size);
	const size_t top_block_count = (1LLU << b->top_block2);
	LOG(3 - LOG_BLOOM, "%s: overall hash: 0x%016" PRIx64 "\n", __func__,
			hash);

	const uint64_t top_block_mask = top_block_count - 1;
	const size_t   block_id       = hash & top_block_mask;
	LOG(3 - LOG_BLOOM, "%s: block_id %zd\n", __func__, block_id);

	struct bloom_filter* bf = b->blocks[block_id];
	if (bf == NULL) { // lazily allocate
		bf = alloc_filter(b->min_filter2);
		if (bf == NULL) {
			return false; // alloc fail
		}
		b->blocks[block_id] = bf;
	}

	// Must be able to do all checks with one 64 bit hash.
	// In order to relax this restriction, fuzz's hashing
	// code will need to be restructured to give the bloom
	// filter code two independent hashes.
	assert(64 - b->top_block2 - (HASH_COUNT * bf->size2) > 0);
	hash >>= b->top_block2;

	const uint8_t  block_size2 = bf->size2;
	const uint64_t block_mask  = (1LLU << block_size2) - 1;
	bool           any_set     = false;

	// Only mark in the front filter.
	for (size_t i = 0; i < HASH_COUNT; i++) {
		const uint64_t v = (hash >> (i * block_size2)) & block_mask;
		const uint64_t offset = v / 8;
		const uint8_t  bit    = 1 << (v & 0x07);
		LOG(4 - LOG_BLOOM,
				"%s: marking %p @ %" PRIu64
				" =>  offset %" PRIu64 ", bit 0x%02x\n",
				__func__, (void*)bf, v, offset, bit);
		if (0 == (bf->bits[offset] & bit)) {
			any_set = true;
		}
		bf->bits[offset] |= bit;
	}

	// If all bits were already set, prepend a new, empty filter -- the
	// previous filter will still match when checking, but there will be
	// a reduced chance of false positives for new entries.
	if (!any_set) {
		if (b->top_block2 + HASH_COUNT * (bf->size2 + 1) > 64) {
			// We can't grow this hash chain any further with the
			// hash bits available.
			LOG(0,
					"%s: Warning: bloom filter block %zd "
					"cannot grow further!\n",
					__func__, block_id);
		} else {
			struct bloom_filter* nbf = alloc_filter(bf->size2 + 1);
			LOG(3 - LOG_BLOOM,
					"%s: growing bloom filter -- bits %u, "
					"nbf %p\n",
					__func__, bf->size2 + 1, (void*)nbf);
			if (nbf == NULL) {
				return false; // alloc fail
			}
			nbf->next           = bf;
			b->blocks[block_id] = nbf; // append to front
		}
	}

	return true;
}

// Check whether the data's hash is in the bloom filter.
bool
fuzz_bloom_check(struct fuzz_bloom* b, uint8_t* data, size_t data_size)
{
	uint64_t hash = fuzz_hash_onepass(data, data_size);
	LOG(3 - LOG_BLOOM, "%s: overall hash: 0x%016" PRIx64 "\n", __func__,
			hash);
	const size_t   top_block_count = (1LLU << b->top_block2);
	const uint64_t top_block_mask  = top_block_count - 1;
	const size_t   block_id        = hash & top_block_mask;
	LOG(3 - LOG_BLOOM, "%s: block_id %zd\n", __func__, block_id);

	struct bloom_filter* bf = b->blocks[block_id];
	if (bf == NULL) {
		return false; // block not allocated: no bits set
	}

	hash >>= b->top_block2;

	// Check every block
	while (bf != NULL) {
		const uint8_t  block_size2 = bf->size2;
		const uint64_t block_mask  = (1LLU << block_size2) - 1;

		bool hit_all_in_block = true;
		for (size_t i = 0; i < HASH_COUNT; i++) {
			const uint64_t v = (hash >> (i * block_size2)) &
					   block_mask;
			const uint64_t offset = v / 8;
			const uint8_t  bit    = 1 << (v & 0x07);
			LOG(4 - LOG_BLOOM,
					"%s: checking %p (bits %u) @ %" PRIu64
					" => offset %" PRIu64
					", bit 0x%02x: 0x%02x\n",
					__func__, (void*)bf, block_size2, v,
					offset, bit, (bf->bits[offset] & bit));
			if (0 == (bf->bits[offset] & bit)) {
				hit_all_in_block = false;
				break;
			}
		}
		if (hit_all_in_block) {
			return true;
		}
		bf = bf->next;
	}

	return false; // there wasn't any block with all checked bits set
}

// Free the bloom filter.
void
fuzz_bloom_free(struct fuzz_bloom* b)
{
	const size_t top_block_count = (1LLU << b->top_block2);
	uint8_t      max_length      = 0;
	for (size_t i = 0; i < top_block_count; i++) {
		uint8_t              length = 0;
		struct bloom_filter* bf     = b->blocks[i];
		while (bf != NULL) {
			struct bloom_filter* next = bf->next;
			free(bf);
			bf = next;
			length++;
		}
		LOG(3 - LOG_BLOOM, "%s: block %zd, length %u\n", __func__, i,
				length);
		max_length = (length > max_length ? length : max_length);
	}
	LOG(3 - LOG_BLOOM, "%s: %zd blocks, max length %u\n", __func__,
			top_block_count, max_length);
	free(b);
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
#include <io.h>
#endif

#if !defined(_WIN32)
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_CALL_H
#define FUZZ_CALL_H

#include <stdbool.h>

struct fuzz;

// Actually call the property function referenced in INFO, with the arguments
// in ARGS.
int fuzz_call(struct fuzz* t, void** args);

// Check if this combination of argument instances has been called.
bool fuzz_call_check_called(struct fuzz* t);

// Mark the tuple of argument instances as called in the bloom filter.
void fuzz_call_mark_called(struct fuzz* t);

#endif

static int fuzz_call_inner(struct fuzz* t, void** args);

static int parent_handle_child_call(
		struct fuzz* t, pid_t pid, struct worker_info* worker);

// Returns one of:
// FUZZ_HOOK_RUN_ERROR
// FUZZ_HOOK_RUN_CONTINUE
static int run_fork_post_hook(struct fuzz* t, void** args);

static bool step_waitpid(struct fuzz* t);

static bool wait_for_exit(struct fuzz* t, struct worker_info* worker,
		size_t timeout, size_t kill_timeout);

#define LOG_CALL 0

#define MAX_FORK_RETRIES 10
#define DEF_KILL_SIGNAL  SIGTERM

// Actually call the property function. Its number of arguments is not
// constrained by the typedef, but will be defined at the call site
// here. (If info->arity is wrong, it will probably crash.)
int
fuzz_call(struct fuzz* t, void** args)
{
	if (!t->fork.enable) {
		return fuzz_call_inner(t, args);
	}

	// We should've bailed if we don't have fork a long time ago.
	assert(FUZZ_POLYFILL_HAVE_FORK);

	struct timespec tv = {.tv_nsec = 1};
	if (-1 == pipe(t->workers[0].fds)) {
		return FUZZ_RESULT_ERROR;
	}

	int   res = FUZZ_RESULT_ERROR;
	pid_t pid = -1;
	for (;;) {
		pid = fork();
		if (pid != -1) {
			break;
		}

		if (errno != EAGAIN) {
			perror("fork");
			return FUZZ_RESULT_ERROR;
		}

		// If we get EAGAIN, then wait for terminated child processes a
		// chance to clean up -- forking is probably failing due to
		// RLIMIT_NPROC.
		const int fork_errno = errno;
		if (!step_waitpid(t)) {
			return FUZZ_RESULT_ERROR;
		}

		if (-1 == nanosleep(&tv, NULL)) {
			perror("nanosleep");
			return FUZZ_RESULT_ERROR;
		}

		if (tv.tv_nsec >= (1L << MAX_FORK_RETRIES)) {
			errno = fork_errno;
			perror("fork");
			return FUZZ_RESULT_ERROR;
		}

		errno = 0;
		tv.tv_nsec <<= 1;
		continue;
	}

	if (pid == -1) {
		close(t->workers[0].fds[0]);
		close(t->workers[0].fds[1]);
		return FUZZ_RESULT_ERROR;
	}

	if (pid == 0) { // child
		close(t->workers[0].fds[0]);
		int out_fd = t->workers[0].fds[1];
		if (run_fork_post_hook(t, args) == FUZZ_HOOK_RUN_ERROR) {
			uint8_t byte = (uint8_t)FUZZ_RESULT_ERROR;
			ssize_t wr   = write(out_fd, (const void*)&byte,
					  sizeof(byte));
			(void)wr;
			exit(EXIT_FAILURE);
		}
		res          = fuzz_call_inner(t, args);
		uint8_t byte = (uint8_t)res;
		ssize_t wr   = write(out_fd, (const void*)&byte, sizeof(byte));
		exit(wr == 1 && res == FUZZ_RESULT_OK ? EXIT_SUCCESS
						      : EXIT_FAILURE);
	}

	// parent
	close(t->workers[0].fds[1]);
	t->workers[0].pid = pid;

	t->workers[0].state = WS_ACTIVE;
	res                 = parent_handle_child_call(t, pid, &t->workers[0]);
	close(t->workers[0].fds[0]);
	t->workers[0].state = WS_INACTIVE;

	if (!step_waitpid(t)) {
		return FUZZ_RESULT_ERROR;
	}
	return res;
}

static int
parent_handle_child_call(struct fuzz* t, pid_t pid, struct worker_info* worker)
{
	const int     fd     = worker->fds[0];
	struct pollfd pfd[1] = {
			{.fd = fd, .events = POLLIN},
	};
	assert(t->fork.timeout <= INT_MAX);
	const size_t timeout = t->fork.timeout;
	int          res     = 0;
	for (;;) {
		struct timeval tv_pre = {0, 0};
		gettimeofday(&tv_pre, NULL);
		res = poll(pfd, 1, (timeout == 0 ? -1 : (int)timeout));
		struct timeval tv_post = {0, 0};
		gettimeofday(&tv_post, NULL);

		const size_t delta = 1000 * tv_post.tv_sec -
				     1000 * tv_pre.tv_sec +
				     ((tv_post.tv_usec / 1000) -
						     (tv_pre.tv_usec / 1000));
		LOG(3 - LOG_CALL, "%s: POLL res %d, elapsed %zd\n", __func__,
				res, delta);
		(void)delta;

		if (res == -1) {
			if (errno == EAGAIN) {
				errno = 0;
				continue;
			} else if (errno == EINTR) {
				errno = 0;
				continue;
			} else {
				return FUZZ_RESULT_ERROR;
			}
		} else {
			break;
		}
	}

	if (res == 0) { // timeout
		int kill_signal = t->fork.signal;
		if (kill_signal == 0) {
			kill_signal = DEF_KILL_SIGNAL;
		}
		LOG(2 - LOG_CALL, "%s: kill(%d, %d)\n", __func__, pid,
				kill_signal);
		assert(pid != -1); // do not do this.
		if (-1 == kill(pid, kill_signal)) {
			return FUZZ_RESULT_ERROR;
		}

		// Check if kill's signal made the child process terminate (or
		// if it exited successfully, and there was just a race on the
		// timeout). If so, save its exit status.
		//
		// If it still hasn't exited after the exit_timeout, then
		// send it SIGKILL and wait for _that_ to make it exit.
		const size_t kill_time = 10; // time to exit after SIGKILL
		const size_t timeout_msec =
				(t->fork.exit_timeout == 0 ? FUZZ_DEF_EXIT_TIMEOUT_MSEC
							   : t->fork.exit_timeout);

		// After sending the signal to the timed out process,
		// give it timeout_msec to actually exit (in case a custom
		// signal is triggering some sort of cleanup) before sending
		// SIGKILL and waiting up to kill_time it to change state.
		if (!wait_for_exit(t, worker, timeout_msec, kill_time)) {
			return FUZZ_RESULT_ERROR;
		}

		// If the child still exited successfully, then consider it a
		// PASS, even though it exceeded the timeout.
		if (worker->state == WS_STOPPED) {
			const int st = worker->wstatus;
			LOG(2 - LOG_CALL, "exited? %d, exit_status %d\n",
					WIFEXITED(st), WEXITSTATUS(st));
			if (WIFEXITED(st) && WEXITSTATUS(st) == EXIT_SUCCESS) {
				return FUZZ_RESULT_OK;
			}
		}

		return FUZZ_RESULT_FAIL;
	} else {
		// As long as the result isn't a timeout, the worker can
		// just be cleaned up by the next batch of waitpid()s.
		int     trial_res = FUZZ_RESULT_ERROR;
		uint8_t res_byte  = 0xFF;
		ssize_t rd        = 0;
		for (;;) {
			rd = read(fd, &res_byte, sizeof(res_byte));
			if (rd == -1) {
				if (errno == EINTR) {
					errno = 0;
					continue;
				}
				return FUZZ_RESULT_ERROR;
			} else {
				break;
			}
		}

		if (rd == 0) {
			// closed without response -> crashed
			trial_res = FUZZ_RESULT_FAIL;
		} else {
			assert(rd == 1);
			trial_res = (int)res_byte;
		}

		return trial_res;
	}
}

// Clean up after all child processes that have changed state.
// Save the exit/termination status for worker processes.
static bool
step_waitpid(struct fuzz* t)
{
	int wstatus   = 0;
	int old_errno = errno;
	for (;;) {
		errno     = 0;
		pid_t res = waitpid(-1, &wstatus, WNOHANG);
		LOG(2 - LOG_CALL, "%s: waitpid? %d\n", __func__, res);
		if (res == -1) {
			if (errno == ECHILD) {
				break;
			} // No Children
			perror("waitpid");
			return FUZZ_RESULT_ERROR;
		} else if (res == 0) {
			break; // no children have changed state
		} else {
			if (res == t->workers[0].pid) {
				t->workers[0].state   = WS_STOPPED;
				t->workers[0].wstatus = wstatus;
			}
		}
	}
	errno = old_errno;
	return true;
}

// Wait timeout msec. for the worker to exit. If kill_timeout is
// non-zero, then send SIGKILL and wait that much longer.
static bool
wait_for_exit(struct fuzz* t, struct worker_info* worker, size_t timeout,
		size_t kill_timeout)
{
	for (size_t i = 0; i < timeout + kill_timeout; i++) {
		if (!step_waitpid(t)) {
			return false;
		}
		if (worker->state == WS_STOPPED) {
			break;
		}

		// If worker hasn't exited yet and kill_timeout is
		// non-zero, send SIGKILL.
		if (i == timeout) {
			assert(kill_timeout > 0);
			assert(worker->pid != -1);
			int kill_res = kill(worker->pid, SIGKILL);
			if (kill_res == -1) {
				if (kill_res == ESRCH) {
					// Process no longer exists (it
					// probably just exited); let waitpid
					// handle it.
				} else {
					perror("kill");
					return false;
				}
			}
		}

		const struct timespec one_msec = {.tv_nsec = 1000000};
		if (-1 == nanosleep(&one_msec, NULL)) {
			perror("nanosleep");
			return false;
		}
	}
	return true;
}

static int
fuzz_call_inner(struct fuzz* t, void** args)
{
	switch (t->prop.arity) {
	case 1:
		return t->prop.u.fun1(t, args[0]);
		break;
	case 2:
		return t->prop.u.fun2(t, args[0], args[1]);
		break;
	case 3:
		return t->prop.u.fun3(t, args[0], args[1], args[2]);
		break;
	case 4:
		return t->prop.u.fun4(t, args[0], args[1], args[2], args[3]);
		break;
	case 5:
		return t->prop.u.fun5(t, args[0], args[1], args[2], args[3],
				args[4]);
		break;
	case 6:
		return t->prop.u.fun6(t, args[0], args[1], args[2], args[3],
				args[4], args[5]);
		break;
	case 7:
		return t->prop.u.fun7(t, args[0], args[1], args[2], args[3],
				args[4], args[5], args[6]);
		break;
	// ...
	default:
		return FUZZ_RESULT_ERROR;
	}
}

// Populate a buffer with hashes of all the arguments.
static void
get_arg_hash_buffer(uint64_t* buffer, struct fuzz* t)
{
	for (uint8_t i = 0; i < t->prop.arity; i++) {
		struct fuzz_type_info* ti = t->prop.type_info[i];

		uint64_t h = 0;
		if (ti->autoshrink_config.enable) {
			h = fuzz_autoshrink_hash(t, t->trial.args[i].instance,
					t->trial.args[i].u.as.env, ti->env);
		} else {
			h = ti->hash(t->trial.args[i].instance, ti->env);
		}

		LOG(4, "%s: arg %d hash; 0x%016" PRIx64 "\n", __func__, i, h);
		buffer[i] = h;
	}
}

// Check if this combination of argument instances has been called.
bool
fuzz_call_check_called(struct fuzz* t)
{
	uint64_t buffer[FUZZ_MAX_ARITY];
	get_arg_hash_buffer(buffer, t);
	return fuzz_bloom_check(t->bloom, (uint8_t*)buffer,
			t->prop.arity * sizeof(uint64_t));
}

// Mark the tuple of argument instances as called in the bloom filter.
void
fuzz_call_mark_called(struct fuzz* t)
{
	uint64_t buffer[FUZZ_MAX_ARITY];
	get_arg_hash_buffer(buffer, t);
	fuzz_bloom_mark(t->bloom, (uint8_t*)buffer,
			t->prop.arity * sizeof(uint64_t));
}

static int
run_fork_post_hook(struct fuzz* t, void** args)
{
	if (t->hooks.fork_post == NULL) {
		return FUZZ_HOOK_RUN_CONTINUE;
	}

	struct fuzz_post_fork_info info = {
			.prop_name    = t->prop.name,
			.total_trials = t->prop.trial_count,
			.failures     = t->counters.fail,
			.run_seed     = t->seeds.run_seed,
			.arity        = t->prop.arity,
			.args         = args, // real_args
	};
	return t->hooks.fork_post(&info, t->hooks.env);
}
// SPDX-License-Identifier: CC0-1.0
#include <assert.h>

// Fowler/Noll/Vo hash, 64-bit FNV-1a.
// This hashing algorithm is in the public domain.
// For more details, see: http://www.isthe.com/chongo/tech/comp/fnv/.
static const uint64_t fnv64_prime        = 1099511628211L;
static const uint64_t fnv64_offset_basis = 14695981039346656037UL;

// Initialize a hasher for incremental hashing.
void
fuzz_hash_init(uint64_t* h)
{
	assert(h);
	*h = fnv64_offset_basis;
}

// Sink more data into an incremental hash.
void
fuzz_hash_sink(uint64_t* h, const uint8_t* data, size_t bytes)
{
	assert(h);
	assert(data);
	if (h == NULL || data == NULL) {
		return;
	}
	uint64_t a = *h;
	for (size_t i = 0; i < bytes; i++) {
		a = (a ^ data[i]) * fnv64_prime;
	}
	*h = a;
}

// Finish hashing and get the result.
uint64_t
fuzz_hash_finish(uint64_t* h)
{
	assert(h);
	uint64_t res = *h;
	fuzz_hash_init(h); // reset
	return res;
}

// Hash a buffer in one pass. (Wraps the above functions.)
uint64_t
fuzz_hash_onepass(const uint8_t* data, size_t bytes)
{
	assert(data);
	uint64_t h = 0;
	fuzz_hash_init(&h);
	fuzz_hash_sink(&h, data, bytes);
	return fuzz_hash_finish(&h);
}
// Public domain
//
// poll(2) emulation for Windows
//
// This emulates just-enough poll functionality on Windows to work in the
// context of the openssl(1) program. This is not a replacement for
// POSIX.1-2001 poll(2), though it may come closer than I care to admit.
//
// Dongsheng Song <dongsheng.song@gmail.com>
// Brent Cook <bcook@openbsd.org>

#if !defined(_WIN32)

extern int errno;

#else
#include <conio.h>
#include <errno.h>
#include <io.h>
#include <poll.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32")

static int
conn_is_closed(int fd)
{
	char buf[1];
	int  ret = recv(fd, buf, 1, MSG_PEEK);
	if (ret == -1) {
		switch (WSAGetLastError()) {
		case WSAECONNABORTED:
		case WSAECONNRESET:
		case WSAENETRESET:
		case WSAESHUTDOWN:
			return 1;
		}
	}
	return 0;
}

static int
conn_has_oob_data(int fd)
{
	char buf[1];
	return (recv(fd, buf, 1, MSG_PEEK | MSG_OOB) == 1);
}

static int
is_socket(int fd)
{
	if (fd < 3)
		return 0;
	WSANETWORKEVENTS events;
	return (WSAEnumNetworkEvents((SOCKET)fd, NULL, &events) == 0);
}

static int
compute_select_revents(
		int fd, short events, fd_set* rfds, fd_set* wfds, fd_set* efds)
{
	int rc = 0;

	if ((events & (POLLIN | POLLRDNORM | POLLRDBAND)) &&
			FD_ISSET(fd, rfds)) {
		if (conn_is_closed(fd))
			rc |= POLLHUP;
		else
			rc |= POLLIN | POLLRDNORM;
	}

	if ((events & (POLLOUT | POLLWRNORM | POLLWRBAND)) &&
			FD_ISSET(fd, wfds))
		rc |= POLLOUT;

	if (FD_ISSET(fd, efds)) {
		if (conn_is_closed(fd))
			rc |= POLLHUP;
		else if (conn_has_oob_data(fd))
			rc |= POLLRDBAND | POLLPRI;
	}

	return rc;
}

static int
compute_wait_revents(HANDLE h, short events, int object, int wait_rc)
{
	int          rc = 0;
	INPUT_RECORD record;
	DWORD        num_read;

	// Assume we can always write to file handles (probably a bad
	// assumption but works for now, at least it doesn't block).
	if (events & (POLLOUT | POLLWRNORM))
		rc |= POLLOUT;

	// Check if this handle was signaled by WaitForMultipleObjects
	if (wait_rc >= WAIT_OBJECT_0 &&
			(object == (wait_rc - WAIT_OBJECT_0)) &&
			(events & (POLLIN | POLLRDNORM))) {

		// Check if this file is stdin, and if so, if it is a console.
		if (h == GetStdHandle(STD_INPUT_HANDLE) &&
				PeekConsoleInput(h, &record, 1, &num_read) ==
						1) {

			// Handle the input console buffer differently,
			// since it can signal on other events like
			// window and mouse, but read can still block.
			if (record.EventType == KEY_EVENT &&
					record.Event.KeyEvent.bKeyDown) {
				rc |= POLLIN;
			} else {
				// Flush non-character events from the
				// console buffer.
				ReadConsoleInput(h, &record, 1, &num_read);
			}
		} else {
			rc |= POLLIN;
		}
	}

	return rc;
}

static int
wsa_select_errno(int err)
{
	switch (err) {
	case WSAEINTR:
	case WSAEINPROGRESS:
		errno = EINTR;
		break;
	case WSAEFAULT:
		// Windows uses WSAEFAULT for both resource allocation failures
		// and arguments not being contained in the user's address
		// space. So, we have to choose EFAULT or ENOMEM.
		errno = EFAULT;
		break;
	case WSAEINVAL:
		errno = EINVAL;
		break;
	case WSANOTINITIALISED:
		errno = EPERM;
		break;
	case WSAENETDOWN:
		errno = ENOMEM;
		break;
	}
	return -1;
}

int
poll(struct pollfd* pfds, nfds_t nfds, int timeout_ms)
{
	nfds_t i;
	int    timespent_ms, looptime_ms;

	// select machinery
	fd_set rfds, wfds, efds;
	int    rc;
	int    num_sockets;

	// wait machinery
	DWORD  wait_rc;
	HANDLE handles[FD_SETSIZE];
	int    num_handles;

	if (pfds == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (nfds <= 0) {
		return 0;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	num_sockets = 0;
	num_handles = 0;

	for (i = 0; i < nfds; i++) {
		if ((int)pfds[i].fd < 0)
			continue;

		if (is_socket(pfds[i].fd)) {
			if (num_sockets >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			FD_SET(pfds[i].fd, &efds);

			if (pfds[i].events &
					(POLLIN | POLLRDNORM | POLLRDBAND)) {
				FD_SET(pfds[i].fd, &rfds);
			}

			if (pfds[i].events &
					(POLLOUT | POLLWRNORM | POLLWRBAND)) {
				FD_SET(pfds[i].fd, &wfds);
			}
			num_sockets++;

		} else {
			if (num_handles >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			handles[num_handles++] =
					(HANDLE)_get_osfhandle(pfds[i].fd);
		}
	}

	// Determine if the files, pipes, sockets, consoles, etc. have signaled.
	//
	// Do this by alternating a loop between WaitForMultipleObjects for
	// non-sockets and and select for sockets.
	//
	// I tried to implement this all in terms of WaitForMultipleObjects
	// with a select-based 'poll' of the sockets at the end to get extra
	// specific socket status.
	//
	// However, the cost of setting up an event handle for each socket and
	// cleaning them up reliably was pretty high. Since the event handle
	// associated with a socket is also global, creating a new one here
	// cancels one that may exist externally to this function.
	//
	// At any rate, even if global socket event handles were not an issue,
	// the 'FD_WRITE' status of a socket event handle does not behave in an
	// expected fashion, being triggered by an edge on a write buffer rather
	// than simply triggering if there is space available.
	timespent_ms = 0;
	wait_rc      = WAIT_FAILED;

	if (timeout_ms < 0)
		timeout_ms = INFINITE;
	looptime_ms = timeout_ms > 100 ? 100 : timeout_ms;

	do {
		struct timeval tv;
		tv.tv_sec           = 0;
		tv.tv_usec          = looptime_ms * 1000;
		int handle_signaled = 0;

		// Check if any file handles have signaled
		if (num_handles) {
			wait_rc = WaitForMultipleObjects(
					num_handles, handles, FALSE, 0);
			if (wait_rc == WAIT_FAILED) {
				// The documentation for WaitForMultipleObjects
				// does not specify what values GetLastError
				// may return here. Rather than enumerate
				// badness like for wsa_select_errno, assume a
				// general errno value.
				errno = ENOMEM;
				return 0;
			}
		}

		// If we signaled on a file handle, don't wait on the sockets.
		if (wait_rc >= WAIT_OBJECT_0 &&
				(wait_rc <= WAIT_OBJECT_0 + num_handles - 1)) {
			tv.tv_usec      = 0;
			handle_signaled = 1;
		}

		// Check if any sockets have signaled
		rc = select(0, &rfds, &wfds, &efds, &tv);
		if (!handle_signaled && rc == SOCKET_ERROR)
			return wsa_select_errno(WSAGetLastError());

		if (handle_signaled || (num_sockets && rc > 0))
			break;

		timespent_ms += looptime_ms;

	} while (timespent_ms < timeout_ms);

	rc          = 0;
	num_handles = 0;
	for (i = 0; i < nfds; i++) {
		pfds[i].revents = 0;

		if ((int)pfds[i].fd < 0)
			continue;

		if (is_socket(pfds[i].fd)) {

			pfds[i].revents = compute_select_revents(pfds[i].fd,
					pfds[i].events, &rfds, &wfds, &efds);

		} else {
			pfds[i].revents = compute_wait_revents(
					handles[num_handles], pfds[i].events,
					num_handles, wait_rc);
			num_handles++;
		}

		if (pfds[i].revents)
			rc++;
	}

	return rc;
}

#endif
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2022 Ayman El Didi

extern int errno;

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#undef WIN32_LEAN_AND_MEAN

// Public domain
//
// poll(2) emulation for Windows
//
// This emulates just-enough poll functionality on Windows to work in the
// context of the openssl(1) program. This is not a replacement for
// POSIX.1-2001 poll(2).
//
// Dongsheng Song <dongsheng.song@gmail.com>
// Brent Cook <bcook@openbsd.org>

#ifndef LIBCRYPTOCOMPAT_POLL_H
#define LIBCRYPTOCOMPAT_POLL_H

#if defined(_WIN32)

#include <winsock2.h>

// Type used for the number of file descriptors.
typedef unsigned long int nfds_t;

#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600)
// Data structure describing a polling request.
struct pollfd {
	int   fd;      // file descriptor
	short events;  // requested events
	short revents; // returned events
};

// Event types that can be polled
#define POLLIN  0x001 // There is data to read.
#define POLLPRI 0x002 // There is urgent data to read.
#define POLLOUT 0x004 // Writing now will not block.

#define POLLRDNORM 0x040 // Normal data may be read.
#define POLLRDBAND 0x080 // Priority data may be read.
#define POLLWRNORM 0x100 // Writing now will not block.
#define POLLWRBAND 0x200 // Priority data may be written.

// Event types always implicitly polled.
#define POLLERR  0x008 // Error condition.
#define POLLHUP  0x010 // Hung up.
#define POLLNVAL 0x020 // Invalid polling request.

#endif

#ifdef __cplusplus
extern "C" {
#endif

int poll(struct pollfd* pfds, nfds_t nfds, int timeout);

#ifdef __cplusplus
}
#endif

#endif

#endif // LIBCRYPTOCOMPAT_POLL_H

int
pipe(int pipefd[2])
{
	return _pipe(pipefd, BUFSIZ, O_BINARY);
}

int
nanosleep(const struct timespec* req, struct timespec* rem)
{
	(void)rem;
	time_t ms = (req->tv_sec * 1000) + (req->tv_nsec / 1000000);
	if (ms > UINT32_MAX) {
		Sleep(UINT32_MAX);
		return 0;
	}
	Sleep((DWORD)ms);
	return 0;
}

int
fork()
{
	errno = ENOSYS;
	return -1;
}

int
kill(int pid, int sig)
{
	(void)pid;
	(void)sig;
	errno = ENOSYS;
	return -1;
}

int
wait(int* status)
{
	(void)status;
	errno = ENOSYS;
	return -1;
}

int
waitpid(int pid, int* status, int options)
{
	(void)pid;
	(void)status;
	(void)options;
	errno = ENOSYS;
	return -1;
}

int
sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
	(void)signum;
	(void)act;
	(void)oldact;
	errno = ENOSYS;
	return -1;
}

int
setrlimit(int resource, const struct rlimit* rlim)
{
	(void)resource;
	(void)rlim;
	errno = ENOSYS;
	return -1;
}

int
getrlimit(int resource, struct rlimit* rlim)
{
	(void)resource;
	(void)rlim;
	return -1;
}

int
gettimeofday(struct timeval* tp, struct timezone* tzp)
{
	(void)tzp;
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME system_time = {0};
	FILETIME   file_time   = {0};
	uint64_t   time        = 0;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec  = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}

// Public domain
//
// poll(2) emulation for Windows from LibreSSL
//
// This emulates just-enough poll functionality on Windows to work in the
// context of the openssl(1) program. This is not a replacement for
// POSIX.1-2001 poll(2), though it may come closer than I care to admit.
//
// Dongsheng Song <dongsheng.song@gmail.com>
// Brent Cook <bcook@openbsd.org>

#include <conio.h>
#include <errno.h>
#include <io.h>
#include <ws2tcpip.h>

static int
conn_is_closed(SOCKET fd)
{
	char buf[1];
	int  ret = recv(fd, buf, 1, MSG_PEEK);
	if (ret == -1) {
		switch (WSAGetLastError()) {
		case WSAECONNABORTED:
		case WSAECONNRESET:
		case WSAENETRESET:
		case WSAESHUTDOWN:
			return 1;
		}
	}
	return 0;
}

static int
conn_has_oob_data(SOCKET fd)
{
	char buf[1];
	return (recv(fd, buf, 1, MSG_PEEK | MSG_OOB) == 1);
}

static int
is_socket(SOCKET fd)
{
	if (fd < 3)
		return 0;
	WSANETWORKEVENTS events;
	return (WSAEnumNetworkEvents(fd, NULL, &events) == 0);
}

static SHORT
compute_select_revents(SOCKET fd, short events, fd_set* rfds, fd_set* wfds,
		fd_set* efds)
{
	SHORT rc = 0;

	if ((events & (POLLIN | POLLRDNORM | POLLRDBAND)) &&
			FD_ISSET(fd, rfds)) {
		if (conn_is_closed(fd))
			rc |= POLLHUP;
		else
			rc |= POLLIN | POLLRDNORM;
	}

	if ((events & (POLLOUT | POLLWRNORM | POLLWRBAND)) &&
			FD_ISSET(fd, wfds))
		rc |= POLLOUT;

	if (FD_ISSET(fd, efds)) {
		if (conn_is_closed(fd))
			rc |= POLLHUP;
		else if (conn_has_oob_data(fd))
			rc |= POLLRDBAND | POLLPRI;
	}

	return rc;
}

static SHORT
compute_wait_revents(HANDLE h, short events, int object, int wait_rc)
{
	SHORT        rc = 0;
	INPUT_RECORD record;
	DWORD        num_read;

	// Assume we can always write to file handles (probably a bad
	// assumption but works for now, at least it doesn't block).
	if (events & (POLLOUT | POLLWRNORM)) {
		rc |= POLLOUT;
	}

	// Check if this handle was signaled by WaitForMultipleObjects
	if ((DWORD)wait_rc >= WAIT_OBJECT_0 &&
			(object == (int)(wait_rc - WAIT_OBJECT_0)) &&
			(events & (POLLIN | POLLRDNORM))) {

		// Check if this file is stdin, and if so, if it is a console.
		if (h == GetStdHandle(STD_INPUT_HANDLE) &&
				PeekConsoleInput(h, &record, 1, &num_read) ==
						1) {

			// Handle the input console buffer differently,
			// since it can signal on other events like
			// window and mouse, but read can still block.
			if (record.EventType == KEY_EVENT &&
					record.Event.KeyEvent.bKeyDown) {
				rc |= POLLIN;
			} else {
				// Flush non-character events from the
				// console buffer.
				ReadConsoleInput(h, &record, 1, &num_read);
			}
		} else {
			rc |= POLLIN;
		}
	}

	return rc;
}

static int
wsa_select_errno(int err)
{
	switch (err) {
	case WSAEINTR:
	case WSAEINPROGRESS:
		errno = EINTR;
		break;
	case WSAEFAULT:
		// Windows uses WSAEFAULT for both resource allocation failures
		// and arguments not being contained in the user's address
		// space. So, we have to choose EFAULT or ENOMEM.
		errno = EFAULT;
		break;
	case WSAEINVAL:
		errno = EINVAL;
		break;
	case WSANOTINITIALISED:
		errno = EPERM;
		break;
	case WSAENETDOWN:
		errno = ENOMEM;
		break;
	}
	return -1;
}

int
poll(struct pollfd* pfds, nfds_t nfds, int timeout_ms)
{
	nfds_t i;
	int    timespent_ms, looptime_ms;

	// select machinery
	fd_set rfds, wfds, efds;
	int    rc;
	int    num_sockets;

	// wait machinery
	DWORD  wait_rc;
	HANDLE handles[FD_SETSIZE];
	int    num_handles;

	if (pfds == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (nfds <= 0) {
		return 0;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	num_sockets = 0;
	num_handles = 0;

	for (i = 0; i < nfds; i++) {
		if ((int)pfds[i].fd < 0)
			continue;

		if (is_socket(pfds[i].fd)) {
			if (num_sockets >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			FD_SET(pfds[i].fd, &efds);

			if (pfds[i].events &
					(POLLIN | POLLRDNORM | POLLRDBAND)) {
				FD_SET(pfds[i].fd, &rfds);
			}

			if (pfds[i].events &
					(POLLOUT | POLLWRNORM | POLLWRBAND)) {
				FD_SET(pfds[i].fd, &wfds);
			}
			num_sockets++;

		} else {
			if (num_handles >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			handles[num_handles++] = (HANDLE)_get_osfhandle(
					(int)pfds[i].fd);
		}
	}

	// Determine if the files, pipes, sockets, consoles, etc. have signaled.
	//
	// Do this by alternating a loop between WaitForMultipleObjects for
	// non-sockets and and select for sockets.
	//
	// I tried to implement this all in terms of WaitForMultipleObjects
	// with a select-based 'poll' of the sockets at the end to get extra
	// specific socket status.
	//
	// However, the cost of setting up an event handle for each socket and
	// cleaning them up reliably was pretty high. Since the event handle
	// associated with a socket is also global, creating a new one here
	// cancels one that may exist externally to this function.
	//
	// At any rate, even if global socket event handles were not an issue,
	// the 'FD_WRITE' status of a socket event handle does not behave in an
	// expected fashion, being triggered by an edge on a write buffer rather
	// than simply triggering if there is space available.
	timespent_ms = 0;
	wait_rc      = WAIT_FAILED;

	if (timeout_ms < 0)
		timeout_ms = INFINITE;
	looptime_ms = timeout_ms > 100 ? 100 : timeout_ms;

	do {
		struct timeval tv;
		tv.tv_sec           = 0;
		tv.tv_usec          = looptime_ms * 1000;
		int handle_signaled = 0;

		// Check if any file handles have signaled
		if (num_handles) {
			wait_rc = WaitForMultipleObjects(
					num_handles, handles, FALSE, 0);
			if (wait_rc == WAIT_FAILED) {
				// The documentation for WaitForMultipleObjects
				// does not specify what values GetLastError
				// may return here. Rather than enumerate
				// badness like for wsa_select_errno, assume a
				// general errno value.
				errno = ENOMEM;
				return 0;
			}
		}

		// If we signaled on a file handle, don't wait on the sockets.
		if (wait_rc >= WAIT_OBJECT_0 &&
				(wait_rc <= WAIT_OBJECT_0 + num_handles - 1)) {
			tv.tv_usec      = 0;
			handle_signaled = 1;
		}

		// Check if any sockets have signaled
		rc = select(0, &rfds, &wfds, &efds, &tv);
		if (!handle_signaled && rc == SOCKET_ERROR)
			return wsa_select_errno(WSAGetLastError());

		if (handle_signaled || (num_sockets && rc > 0))
			break;

		timespent_ms += looptime_ms;

	} while (timespent_ms < timeout_ms);

	rc          = 0;
	num_handles = 0;
	for (i = 0; i < nfds; i++) {
		pfds[i].revents = 0;

		if ((int)pfds[i].fd < 0)
			continue;

		if (is_socket(pfds[i].fd)) {

			pfds[i].revents = compute_select_revents(pfds[i].fd,
					pfds[i].events, &rfds, &wfds, &efds);

		} else {
			pfds[i].revents = compute_wait_revents(
					handles[num_handles], pfds[i].events,
					num_handles, wait_rc);
			num_handles++;
		}

		if (pfds[i].revents)
			rc++;
	}

	return rc;
}

#endif
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <inttypes.h>

static uint64_t
get_random_mask(uint8_t bits)
{
	if (bits == 64) {
		return ~(uint64_t)0; // just set all bits -- would overflow
	} else {
		return (1LLU << bits) - 1;
	}
}

// (Re-)initialize the random number generator with a specific seed.
// This stops using the current bit pool.
void
fuzz_random_set_seed(struct fuzz* t, uint64_t seed)
{
	fuzz_random_stop_using_bit_pool(t);
	t->prng.buf            = 0;
	t->prng.bits_available = 0;

	fuzz_rng_reset(t->prng.rng, seed);
	LOG(2, "%s: SET_SEED: %" PRIx64 "\n", __func__, seed);
}

void
fuzz_random_inject_autoshrink_bit_pool(
		struct fuzz* t, struct autoshrink_bit_pool* bit_pool)
{
	t->prng.bit_pool = bit_pool;
}

void
fuzz_random_stop_using_bit_pool(struct fuzz* t)
{
	t->prng.bit_pool = NULL;
}

// Get BITS random bits from the test runner's PRNG.
// Bits can be retrieved at most 64 at a time.
uint64_t
fuzz_random_bits(struct fuzz* t, uint8_t bit_count)
{
	assert(bit_count <= 64);
	LOG(4,
			"RANDOM_BITS: available %u, bit_count: %u, buf "
			"%016" PRIx64 "\n",
			t->prng.bits_available, bit_count, t->prng.buf);

	uint64_t res = 0;
	fuzz_random_bits_bulk(t, bit_count, &res);
	return res;
}

void
fuzz_random_bits_bulk(struct fuzz* t, uint32_t bit_count, uint64_t* buf)
{
	LOG(5, "%s: bit_count %u\n", __func__, bit_count);
	assert(buf);
	if (t->prng.bit_pool) {
		fuzz_autoshrink_bit_pool_random(
				t, t->prng.bit_pool, bit_count, true, buf);
		return;
	}

	uint32_t rem    = bit_count;
	uint8_t  shift  = 0;
	size_t   offset = 0;

	while (rem > 0) {
		if (t->prng.bits_available == 0) {
			t->prng.buf            = fuzz_rng_random(t->prng.rng);
			t->prng.bits_available = 64;
		}
		LOG(5, "%% buf 0x%016" PRIx64 "\n", t->prng.buf);

		uint8_t take = 64 - shift;
		if (take > rem) {
			take = (uint8_t)rem;
		}
		if (take > t->prng.bits_available) {
			take = t->prng.bits_available;
		}

		LOG(5,
				"%s: rem %u, available %u, buf 0x%016" PRIx64
				", offset %zd, take %u\n",
				__func__, rem, t->prng.bits_available,
				t->prng.buf, offset, take);

		const uint64_t mask = get_random_mask(take);
		buf[offset] |= (t->prng.buf & mask) << shift;
		LOG(5, "== buf[%zd]: %016" PRIx64 " (%u / %u)\n", offset,
				buf[offset], bit_count - rem, bit_count);
		t->prng.bits_available -= take;
		if (take == 64) {
			t->prng.buf = 0;
		} else {
			t->prng.buf >>= take;
		}

		shift += take;
		if (shift == 64) {
			offset++;
			shift = 0;
		}

		rem -= take;
	}
}

#if FUZZ_USE_FLOATING_POINT
// Get a random double from the test runner's PRNG.
double
fuzz_random_double(struct fuzz* t)
{
	double res = fuzz_rng_uint64_to_double(fuzz_random_bits(t, 64));
	LOG(4, "RANDOM_DOUBLE: %g\n", res);
	return res;
}

uint64_t
fuzz_random_choice(struct fuzz* t, uint64_t ceil)
{
	if (ceil < 2) {
		return 0;
	}
	uint64_t bits;
	double   limit;

	// If ceil is a power of two, just return that many bits.
	if ((ceil & (ceil - 1)) == 0) {
		uint8_t log2_ceil = 1;
		while (ceil > (1LLU << log2_ceil)) {
			log2_ceil++;
		}
		assert((1LLU << log2_ceil) == ceil);
		return fuzz_random_bits(t, log2_ceil);
	}

	// If the choice values are fairly small (which shoud be
	// the common case), sample less than 64 bits to reduce
	// time spent managing the random bitstream.
	if (ceil < UINT8_MAX) {
		bits  = fuzz_random_bits(t, 16);
		limit = (double)(1LLU << 16);
	} else if (ceil < UINT16_MAX) {
		bits  = fuzz_random_bits(t, 32);
		limit = (double)(1LLU << 32);
	} else {
		bits  = fuzz_random_bits(t, 64);
		limit = (double)UINT64_MAX;
	}

	double   mul = (double)bits / limit;
	uint64_t res = (uint64_t)(mul * ceil);
	return res;
}

uint64_t
fuzz_random_range(struct fuzz* f, const uint64_t min, const uint64_t max)
{
	assert(min < max);
	return fuzz_random_choice(f, max - min + 1) + min;
}
#endif
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: 2004 Makoto Matsumoto and Takuji Nishimura

// A C-program for MT19937-64 (2004/9/29 version).
// Coded by Takuji Nishimura and Makoto Matsumoto.
//
// This is a 64-bit version of Mersenne Twister pseudorandom number
// generator.
//
// Before using, initialize the state by using init_genrand64(seed)
// or init_by_array64(init_key, key_length).
//
// References:
// T. Nishimura, ``Tables of 64-bit Mersenne Twisters''
//   ACM Transactions on Modeling and
//   Computer Simulation 10. (2000) 348--357.
// M. Matsumoto and T. Nishimura,
//   ``Mersenne Twister: a 623-dimensionally equidistributed
//     uniform pseudorandom number generator''
//   ACM Transactions on Modeling and
//   Computer Simulation 8. (Jan. 1998) 3--30.
//
// Any feedback is very welcome.
// http://www.math.hiroshima-u.ac.jp/~m-mat/MT/emt.html
// email: m-mat @ math.sci.hiroshima-u.ac.jp (remove spaces)

// The code has been modified to store internal state in heap/stack
// allocated memory, rather than statically allocated memory, to allow
// multiple instances running in the same address space.
//
// Also, the functions in the module's public interface have
// been prefixed with "fuzz_rng_".

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define FUZZ_MT_PARAM_N 312
struct fuzz_rng {
	uint64_t mt[FUZZ_MT_PARAM_N]; // the array for the state vector
	int16_t  mti;
};

#define NN       FUZZ_MT_PARAM_N
#define MM       156
#define MATRIX_A 0xB5026F5AA96619E9ULL
#define UM       0xFFFFFFFF80000000ULL // Most significant 33 bits
#define LM       0x7FFFFFFFULL         // Least significant 31 bits

static uint64_t genrand64_int64(struct fuzz_rng* r);

// Heap-allocate a mersenne twister struct.
struct fuzz_rng*
fuzz_rng_init(uint64_t seed)
{
	struct fuzz_rng* mt = malloc(sizeof(struct fuzz_rng));
	if (mt == NULL) {
		return NULL;
	}
	fuzz_rng_reset(mt, seed);
	return mt;
}

// Free a heap-allocated mersenne twister struct.
void
fuzz_rng_free(struct fuzz_rng* mt)
{
	free(mt);
}

// initializes mt[NN] with a seed
void
fuzz_rng_reset(struct fuzz_rng* mt, uint64_t seed)
{
	mt->mt[0]    = seed;
	uint16_t mti = 0;
	for (mti = 1; mti < NN; mti++) {
		uint64_t tmp = (mt->mt[mti - 1] ^ (mt->mt[mti - 1] >> 62));
		mt->mt[mti]  = 6364136223846793005ULL * tmp + mti;
	}

	mt->mti = mti;
}

// Get a 64-bit random number.
uint64_t
fuzz_rng_random(struct fuzz_rng* mt)
{
	return genrand64_int64(mt);
}

// Generate a random number on [0,1]-real-interval.
double
fuzz_rng_uint64_to_double(uint64_t x)
{
	return (x >> 11) * (1.0 / 9007199254740991.0);
}

// generates a random number on [0, 2^64-1]-interval
static uint64_t
genrand64_int64(struct fuzz_rng* r)
{
	int             i;
	uint64_t        x;
	static uint64_t mag01[2] = {0ULL, MATRIX_A};

	if (r->mti >= NN) { // generate NN words at one time

		// if init has not been called,
		// a default initial seed is used
		if (r->mti == NN + 1)
			fuzz_rng_reset(r, 5489ULL);

		for (i = 0; i < NN - MM; i++) {
			x        = (r->mt[i] & UM) | (r->mt[i + 1] & LM);
			r->mt[i] = r->mt[i + MM] ^ (x >> 1) ^
				   mag01[(int)(x & 1ULL)];
		}
		for (; i < NN - 1; i++) {
			x        = (r->mt[i] & UM) | (r->mt[i + 1] & LM);
			r->mt[i] = r->mt[i + (MM - NN)] ^ (x >> 1) ^
				   mag01[(int)(x & 1ULL)];
		}
		x             = (r->mt[NN - 1] & UM) | (r->mt[0] & LM);
		r->mt[NN - 1] = r->mt[MM - 1] ^ (x >> 1) ^
				mag01[(int)(x & 1ULL)];

		r->mti = 0;
	}

	x = r->mt[r->mti++];

	x ^= (x >> 29) & 0x5555555555555555ULL;
	x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
	x ^= (x << 37) & 0xFFF7EEE000000000ULL;
	x ^= (x >> 43);

	return x;
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_RUN_H
#define FUZZ_RUN_H

struct fuzz;
struct fuzz_run_config;

enum fuzz_run_init_res {
	FUZZ_RUN_INIT_OK,
	FUZZ_RUN_INIT_ERROR_MEMORY   = -1,
	FUZZ_RUN_INIT_ERROR_BAD_ARGS = -2,
};
enum fuzz_run_init_res fuzz_run_init(
		const struct fuzz_run_config* cfg, struct fuzz** output);

// Actually run the trials, with all arguments made explicit.
int fuzz_run_trials(struct fuzz* t);

void fuzz_run_free(struct fuzz* t);

#endif

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_TRIAL_H
#define FUZZ_TRIAL_H

#include <stdbool.h>

struct fuzz;

bool fuzz_trial_run(struct fuzz* t, int* post_trial_res);

void fuzz_trial_get_args(struct fuzz* t, void** args);

void fuzz_trial_free_args(struct fuzz* t);

#endif

static uint8_t infer_arity(const struct fuzz_run_config* cfg);

enum run_step_res {
	RUN_STEP_OK,
	RUN_STEP_HALT,
	RUN_STEP_GEN_ERROR,
	RUN_STEP_TRIAL_ERROR,
};
static enum run_step_res run_step(
		struct fuzz* t, size_t trial, uint64_t* seed);

static bool copy_propfun_for_arity(
		const struct fuzz_run_config* cfg, struct prop_info* prop);

static bool check_all_args(uint8_t arity, const struct fuzz_run_config* cfg,
		bool* all_hashable);

enum all_gen_res {
	ALL_GEN_OK,    // all arguments generated okay
	ALL_GEN_SKIP,  // skip due to user constraints
	ALL_GEN_DUP,   // skip probably duplicated trial
	ALL_GEN_ERROR, // memory error or other failure
};

static bool init_arg_info(struct fuzz* t, struct trial_info* trial_info);

static enum all_gen_res gen_all_args(struct fuzz* t);

static void free_print_trial_result_env(struct fuzz* t);

#define LOG_RUN 0

enum fuzz_run_init_res
fuzz_run_init(const struct fuzz_run_config* cfg, struct fuzz** output)
{
	enum fuzz_run_init_res res = FUZZ_RUN_INIT_OK;
	struct fuzz*           t   = malloc(sizeof(*t));
	if (t == NULL) {
		return FUZZ_RUN_INIT_ERROR_MEMORY;
	}
	memset(t, 0, sizeof(*t));

	t->out      = stdout;
	t->prng.rng = fuzz_rng_init(DEFAULT_uint64_t);
	if (t->prng.rng == NULL) {
		free(t);
		return FUZZ_RUN_INIT_ERROR_MEMORY;
	}

	const uint8_t arity = infer_arity(cfg);
	if (arity == 0) {
		res = FUZZ_RUN_INIT_ERROR_BAD_ARGS;
		goto cleanup;
	}

	bool all_hashable = false;
	if (!check_all_args(arity, cfg, &all_hashable)) {
		res = FUZZ_RUN_INIT_ERROR_BAD_ARGS;
		goto cleanup;
	}

	struct seed_info seeds = {
			.run_seed = cfg->seed ? cfg->seed : DEFAULT_uint64_t,
			.always_seed_count = (cfg->always_seeds == NULL
							      ? 0
							      : cfg->always_seed_count),
			.always_seeds      = cfg->always_seeds,
	};
	memcpy(&t->seeds, &seeds, sizeof(seeds));

	struct fork_info fork = {
			.enable  = cfg->fork.enable && FUZZ_POLYFILL_HAVE_FORK,
			.timeout = cfg->fork.timeout,
			.signal  = cfg->fork.signal,
			.exit_timeout = cfg->fork.exit_timeout,
	};
	memcpy(&t->fork, &fork, sizeof(fork));

	struct prop_info prop = {
			.name        = cfg->name,
			.arity       = arity,
			.trial_count = cfg->trials == 0 ? FUZZ_DEF_TRIALS
							: cfg->trials,
			// .type_info is memcpy'd below
	};
	if (!copy_propfun_for_arity(cfg, &prop)) {
		res = FUZZ_RUN_INIT_ERROR_BAD_ARGS;
		goto cleanup;
	}
	memcpy(&prop.type_info, cfg->type_info, sizeof(prop.type_info));
	memcpy(&t->prop, &prop, sizeof(prop));

	struct hook_info hooks = {
			.pre_run      = (cfg->hooks.pre_run != NULL
							     ? cfg->hooks.pre_run
							     : fuzz_pre_run_hook_print_info),
			.post_run     = (cfg->hooks.post_run != NULL
							    ? cfg->hooks.post_run
							    : fuzz_post_run_hook_print_info),
			.pre_gen_args = cfg->hooks.pre_gen_args,
			.trial_pre    = cfg->hooks.pre_trial,
			.fork_post    = cfg->hooks.post_fork,
			.trial_post   = (cfg->hooks.post_trial != NULL
							  ? cfg->hooks.post_trial
							  : fuzz_hook_trial_post_print_result),

			.counterexample    = (cfg->hooks.counterexample != NULL
							      ? cfg->hooks.counterexample
							      : fuzz_print_counterexample),
			.shrink_pre        = cfg->hooks.pre_shrink,
			.shrink_post       = cfg->hooks.post_shrink,
			.shrink_trial_post = cfg->hooks.post_shrink_trial,
			.env               = cfg->hooks.env,
	};
	memcpy(&t->hooks, &hooks, sizeof(hooks));

	LOG(3 - LOG_RUN, "%s: SETTING RUN SEED TO 0x%016" PRIx64 "\n",
			__func__, t->seeds.run_seed);
	fuzz_random_set_seed(t, t->seeds.run_seed);

	// If all arguments are hashable, then attempt to use
	// a bloom filter to avoid redundant checking.
	if (all_hashable) {
		t->bloom = fuzz_bloom_init(NULL);
	}

	// If using the default trial_post callback, allocate its
	// environment, with info relating to printing progress.
	if (t->hooks.trial_post == fuzz_hook_trial_post_print_result) {
		t->print_trial_result_env =
				calloc(1, sizeof(*t->print_trial_result_env));
		if (t->print_trial_result_env == NULL) {
			return FUZZ_RUN_INIT_ERROR_MEMORY;
		}
		t->print_trial_result_env->tag =
				FUZZ_PRINT_TRIAL_RESULT_ENV_TAG;
	}

	*output = t;
	return res;

cleanup:
	fuzz_rng_free(t->prng.rng);
	free(t);
	return res;
}

void
fuzz_run_free(struct fuzz* t)
{
	if (t->bloom) {
		fuzz_bloom_free(t->bloom);
		t->bloom = NULL;
	}
	fuzz_rng_free(t->prng.rng);

	if (t->print_trial_result_env != NULL) {
		free(t->print_trial_result_env);
	}

	free(t);
}

// Actually run the trials, with all arguments made explicit.
int
fuzz_run_trials(struct fuzz* t)
{
	if (t->hooks.pre_run != NULL) {
		struct fuzz_pre_run_info hook_info = {
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.run_seed     = t->seeds.run_seed,
		};
		int res = t->hooks.pre_run(&hook_info, t->hooks.env);
		if (res != FUZZ_HOOK_RUN_CONTINUE) {
			goto cleanup;
		}
	}

	size_t   limit = t->prop.trial_count;
	uint64_t seed  = t->seeds.run_seed;

	for (size_t trial = 0; trial < limit; trial++) {
		enum run_step_res res = run_step(t, trial, &seed);
		memset(&t->trial, 0x00, sizeof(t->trial));

		LOG(3 - LOG_RUN,
				"  -- trial %zd/%zd, new seed 0x%016" PRIx64
				"\n",
				trial, limit, seed);

		switch (res) {
		case RUN_STEP_OK:
			continue;
		case RUN_STEP_HALT:
			limit = trial;
			break;
		default:
		case RUN_STEP_GEN_ERROR:
		case RUN_STEP_TRIAL_ERROR:
			goto cleanup;
		}
	}

	fuzz_post_run_hook_cb* post_run = t->hooks.post_run;
	if (post_run != NULL) {
		struct fuzz_post_run_info hook_info = {
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.run_seed     = t->seeds.run_seed,
				.report =
						{
								.pass = t->counters.pass,
								.fail = t->counters.fail,
								.skip = t->counters.skip,
								.dup = t->counters.dup,
						},
		};

		int res = post_run(&hook_info, t->hooks.env);
		if (res != FUZZ_HOOK_RUN_CONTINUE) {
			goto cleanup;
		}
	}

	free_print_trial_result_env(t);

	if (t->counters.fail > 0) {
		return FUZZ_RESULT_FAIL;
	} else if (t->counters.pass > 0) {
		return FUZZ_RESULT_OK;
	} else {
		return FUZZ_RESULT_SKIP;
	}

cleanup:
	free_print_trial_result_env(t);
	return FUZZ_RESULT_ERROR;
}

static enum run_step_res
run_step(struct fuzz* t, size_t trial, uint64_t* seed)
{
	// If any seeds to always run were specified, use those before
	// reverting to the specified starting seed.
	const size_t always_seeds = t->seeds.always_seed_count;
	if (trial < always_seeds) {
		*seed = t->seeds.always_seeds[trial];
	} else if ((always_seeds > 0) && (trial == always_seeds)) {
		*seed = t->seeds.run_seed;
	}

	struct trial_info trial_info = {
			.trial = trial,
			.seed  = *seed,
	};
	if (!init_arg_info(t, &trial_info)) {
		return RUN_STEP_GEN_ERROR;
	}

	memcpy(&t->trial, &trial_info, sizeof(trial_info));

	fuzz_hook_gen_args_pre_cb* pre_gen_args = t->hooks.pre_gen_args;
	if (pre_gen_args != NULL) {
		struct fuzz_pre_gen_args_info hook_info = {
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.failures     = t->counters.fail,
				.run_seed     = t->seeds.run_seed,
				.trial_id     = t->trial.trial,
				.trial_seed   = t->trial.seed,
				.arity        = t->prop.arity};
		int res = pre_gen_args(&hook_info, t->hooks.env);

		switch (res) {
		case FUZZ_HOOK_RUN_CONTINUE:
			break;
		case FUZZ_HOOK_RUN_HALT:
			return RUN_STEP_HALT;
		default:
			assert(false);
		case FUZZ_HOOK_RUN_ERROR:
			return RUN_STEP_GEN_ERROR;
		}
	}

	// Set seed for this trial
	LOG(3 - LOG_RUN, "%s: SETTING TRIAL SEED TO 0x%016" PRIx64 "\n",
			__func__, trial_info.seed);
	fuzz_random_set_seed(t, trial_info.seed);

	enum run_step_res res  = RUN_STEP_OK;
	enum all_gen_res  gres = gen_all_args(t);
	// anything after this point needs to free all args

	fuzz_hook_trial_post_cb* post_cb = t->hooks.trial_post;
	void* hook_env = (t->hooks.trial_post == fuzz_hook_trial_post_print_result
					  ? t->print_trial_result_env
					  : t->hooks.env);

	void* args[FUZZ_MAX_ARITY];
	for (size_t i = 0; i < t->prop.arity; i++) {
		args[i] = t->trial.args[i].instance;
	}

	struct fuzz_post_trial_info hook_info = {
			.t            = t,
			.prop_name    = t->prop.name,
			.total_trials = t->prop.trial_count,
			.failures     = t->counters.fail,
			.run_seed     = *seed,
			.trial_id     = trial,
			.trial_seed   = trial_info.seed,
			.arity        = t->prop.arity,
			.args         = args,
	};

	int pres;

	switch (gres) {
	case ALL_GEN_SKIP: // skip generating these args
		LOG(3 - LOG_RUN, "gen -- skip\n");
		t->counters.skip++;
		hook_info.result = FUZZ_RESULT_SKIP;
		pres             = post_cb(&hook_info, hook_env);
		break;
	case ALL_GEN_DUP: // skip these args -- probably already tried
		LOG(3 - LOG_RUN, "gen -- dup\n");
		t->counters.dup++;
		hook_info.result = FUZZ_RESULT_DUPLICATE;
		pres             = post_cb(&hook_info, hook_env);
		break;
	default:
	case ALL_GEN_ERROR: // error while generating args
		LOG(1 - LOG_RUN, "gen -- error\n");
		hook_info.result = FUZZ_RESULT_ERROR;
		pres             = post_cb(&hook_info, hook_env);
		res              = RUN_STEP_GEN_ERROR;
		goto cleanup;
	case ALL_GEN_OK:
		LOG(4 - LOG_RUN, "gen -- ok\n");
		if (t->hooks.trial_pre != NULL) {
			struct fuzz_pre_trial_info info = {
					.prop_name    = t->prop.name,
					.total_trials = t->prop.trial_count,
					.failures     = t->counters.fail,
					.run_seed     = t->seeds.run_seed,
					.trial_id     = trial,
					.trial_seed   = trial_info.seed,
					.arity        = t->prop.arity,
			};

			int tpres;
			tpres = t->hooks.trial_pre(&info, t->hooks.env);
			if (tpres == FUZZ_HOOK_RUN_HALT) {
				res = RUN_STEP_HALT;
				goto cleanup;
			} else if (tpres == FUZZ_HOOK_RUN_ERROR) {
				res = RUN_STEP_TRIAL_ERROR;
				goto cleanup;
			}
		}

		if (!fuzz_trial_run(t, &pres)) {
			res = RUN_STEP_TRIAL_ERROR;
			goto cleanup;
		}
	}

	if (pres == FUZZ_HOOK_RUN_ERROR) {
		res = RUN_STEP_TRIAL_ERROR;
		goto cleanup;
	}

	// Update seed for next trial
	*seed = fuzz_random_bits(t, 64);
	LOG(3 - LOG_RUN, "end of trial, new seed is 0x%016" PRIx64 "\n",
			*seed);
cleanup:
	fuzz_trial_free_args(t);
	return res;
}

static uint8_t
infer_arity(const struct fuzz_run_config* cfg)
{
	for (uint8_t i = 0; i < FUZZ_MAX_ARITY; i++) {
		if (cfg->type_info[i] == NULL) {
			return i;
		}
	}
	return FUZZ_MAX_ARITY;
}

static bool
copy_propfun_for_arity(
		const struct fuzz_run_config* cfg, struct prop_info* prop)
{
	switch (prop->arity) {
#define COPY_N(N)                                                             \
	case N:                                                               \
		if (cfg->prop##N == NULL) {                                   \
			return false;                                         \
		} else {                                                      \
			prop->u.fun##N = cfg->prop##N;                        \
			break;                                                \
		}

	default:
	case 0:
		assert(false);
		return false;
		COPY_N(1);
		COPY_N(2);
		COPY_N(3);
		COPY_N(4);
		COPY_N(5);
		COPY_N(6);
		COPY_N(7);
#undef COPY_N
	}
	return true;
}

// Check if all argument info structs have all required callbacks.
static bool
check_all_args(uint8_t arity, const struct fuzz_run_config* cfg,
		bool* all_hashable)
{
	bool ah = true;
	for (uint8_t i = 0; i < arity; i++) {
		const struct fuzz_type_info* ti = cfg->type_info[i];
		if (ti->alloc == NULL) {
			return false;
		}
		if (ti->autoshrink_config.enable && ti->shrink) {
			return false;
		}
		if (ti->hash == NULL && !ti->autoshrink_config.enable) {
			ah = false;
		}
	}
	*all_hashable = ah;
	return true;
}

static bool
init_arg_info(struct fuzz* t, struct trial_info* trial_info)
{
	for (size_t i = 0; i < t->prop.arity; i++) {
		const struct fuzz_type_info* ti = t->prop.type_info[i];
		if (ti->autoshrink_config.enable) {
			trial_info->args[i].type = ARG_AUTOSHRINK;
			trial_info->args[i].u.as.env =
					fuzz_autoshrink_alloc_env(t, i, ti);
			if (trial_info->args[i].u.as.env == NULL) {
				return false;
			}
		} else {
			trial_info->args[i].type = ARG_BASIC;
		}
	}
	return true;
}

// Attempt to instantiate arguments, starting with the current seed.
static enum all_gen_res
gen_all_args(struct fuzz* t)
{
	for (uint8_t i = 0; i < t->prop.arity; i++) {
		struct fuzz_type_info* ti = t->prop.type_info[i];
		void*                  p  = NULL;

		int res = (ti->autoshrink_config.enable
						? fuzz_autoshrink_alloc(t,
								  t->trial.args[i].u
										  .as
										  .env,
								  &p)
						: ti->alloc(t, ti->env, &p));

		if (res == FUZZ_RESULT_SKIP) {
			return ALL_GEN_SKIP;
		} else if (res == FUZZ_RESULT_ERROR) {
			return ALL_GEN_ERROR;
		} else {
			t->trial.args[i].instance = p;
			LOG(3 - LOG_RUN, "%s: arg %u -- %p\n", __func__, i, p);
		}
	}

	// check bloom filter
	if (t->bloom && fuzz_call_check_called(t)) {
		return ALL_GEN_DUP;
	}

	return ALL_GEN_OK;
}

static void
free_print_trial_result_env(struct fuzz* t)
{
	if (t->hooks.trial_post == fuzz_hook_trial_post_print_result &&
			t->print_trial_result_env != NULL) {
		free(t->print_trial_result_env);
		t->print_trial_result_env = NULL;
	}
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>

// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_SHRINK_H
#define FUZZ_SHRINK_H

#include <stdbool.h>

struct fuzz;

// Attempt to simplify all arguments, breadth first. Continue as long as
// progress is made, i.e., until a local minimum is reached.
bool fuzz_shrink(struct fuzz* t);

#endif

enum shrink_res {
	SHRINK_OK,       // simplified argument further
	SHRINK_DEAD_END, // at local minima
	SHRINK_ERROR,    // hard error during shrinking
	SHRINK_HALT,     // don't shrink any further
};

static enum shrink_res attempt_to_shrink_arg(struct fuzz* t, uint8_t arg_i);

static int shrink_pre_hook(
		struct fuzz* t, uint8_t arg_index, void* arg, uint32_t tactic);

static int shrink_post_hook(struct fuzz* t, uint8_t arg_index, void* arg,
		uint32_t tactic, int sres);

static int shrink_trial_post_hook(struct fuzz* t, uint8_t arg_index,
		void** args, uint32_t last_tactic, int result);

#define LOG_SHRINK 0

// Attempt to simplify all arguments, breadth first. Continue as long as
// progress is made, i.e., until a local minimum is reached.
bool
fuzz_shrink(struct fuzz* t)
{
	bool progress = false;
	assert(t->prop.arity > 0);

	do {
		progress = false;
		// Greedily attempt to simplify each argument as much as
		// possible before switching to the next.
		for (uint8_t arg_i = 0; arg_i < t->prop.arity; arg_i++) {
			struct fuzz_type_info* ti = t->prop.type_info[arg_i];
		greedy_continue:
			if (ti->shrink || ti->autoshrink_config.enable) {
				// attempt to simplify this argument by one
				// step
				enum shrink_res rres = attempt_to_shrink_arg(
						t, arg_i);

				switch (rres) {
				case SHRINK_OK:
					LOG(3 - LOG_SHRINK,
							"%s %u: progress\n",
							__func__, arg_i);
					progress = true;
					goto greedy_continue; // keep trying to
							      // shrink same
							      // argument
				case SHRINK_HALT:
					LOG(3 - LOG_SHRINK, "%s %u: HALT\n",
							__func__, arg_i);
					return true;
				case SHRINK_DEAD_END:
					LOG(3 - LOG_SHRINK,
							"%s %u: DEAD END\n",
							__func__, arg_i);
					continue; // try next argument, if any
				default:
				case SHRINK_ERROR:
					LOG(1 - LOG_SHRINK, "%s %u: ERROR\n",
							__func__, arg_i);
					return false;
				}
			}
		}
	} while (progress);
	return true;
}

// Simplify an argument by trying all of its simplification tactics, in
// order, and checking whether the property still fails. If it passes,
// then revert the simplification and try another tactic.
//
// If the bloom filter is being used (i.e., if all arguments have hash
// callbacks defined), then use it to skip over areas of the state
// space that have probably already been tried.
static enum shrink_res
attempt_to_shrink_arg(struct fuzz* t, uint8_t arg_i)
{
	struct fuzz_type_info* ti             = t->prop.type_info[arg_i];
	const bool             use_autoshrink = ti->autoshrink_config.enable;

	for (uint32_t tactic = 0; tactic < FUZZ_MAX_TACTICS; tactic++) {
		LOG(2 - LOG_SHRINK, "SHRINKING arg %u, tactic %u\n", arg_i,
				tactic);
		void* current   = t->trial.args[arg_i].instance;
		void* candidate = NULL;

		int shrink_pre_res;
		shrink_pre_res = shrink_pre_hook(t, arg_i, current, tactic);
		if (shrink_pre_res == FUZZ_HOOK_RUN_HALT) {
			return SHRINK_HALT;
		} else if (shrink_pre_res != FUZZ_HOOK_RUN_CONTINUE) {
			return SHRINK_ERROR;
		}

		struct autoshrink_env*      as_env             = NULL;
		struct autoshrink_bit_pool* current_bit_pool   = NULL;
		struct autoshrink_bit_pool* candidate_bit_pool = NULL;
		if (use_autoshrink) {
			as_env = t->trial.args[arg_i].u.as.env;
			assert(as_env);
			current_bit_pool = t->trial.args[arg_i]
							   .u.as.env->bit_pool;
		}

		int sres = (use_autoshrink ? fuzz_autoshrink_shrink(t, as_env,
							     tactic,
							     &candidate,
							     &candidate_bit_pool)
					   : ti->shrink(t, current, tactic,
							     ti->env,
							     &candidate));

		LOG(3 - LOG_SHRINK, "%s: tactic %u -> res %d\n", __func__,
				tactic, sres);

		t->trial.shrink_count++;

		int shrink_post_res;
		shrink_post_res = shrink_post_hook(t, arg_i,
				sres == FUZZ_SHRINK_OK ? candidate : current,
				tactic, sres);
		if (shrink_post_res != FUZZ_HOOK_RUN_CONTINUE) {
			if (ti->free) {
				ti->free(candidate, ti->env);
			}
			if (candidate_bit_pool) {
				fuzz_autoshrink_free_bit_pool(
						t, candidate_bit_pool);
			}
			return SHRINK_ERROR;
		}

		switch (sres) {
		case FUZZ_SHRINK_OK:
			break;
		case FUZZ_SHRINK_DEAD_END:
			continue; // try next tactic
		case FUZZ_SHRINK_NO_MORE_TACTICS:
			return SHRINK_DEAD_END;
		case FUZZ_SHRINK_ERROR:
		default:
			return SHRINK_ERROR;
		}

		t->trial.args[arg_i].instance = candidate;
		if (use_autoshrink) {
			as_env->bit_pool = candidate_bit_pool;
		}

		if (t->bloom) {
			if (fuzz_call_check_called(t)) {
				LOG(3 - LOG_SHRINK,
						"%s: already called, "
						"skipping\n",
						__func__);
				if (ti->free) {
					ti->free(candidate, ti->env);
				}
				if (use_autoshrink) {
					as_env->bit_pool = current_bit_pool;
					fuzz_autoshrink_free_bit_pool(
							t, candidate_bit_pool);
				}
				t->trial.args[arg_i].instance = current;
				continue;
			} else {
				fuzz_call_mark_called(t);
			}
		}

		int  res;
		bool repeated = false;
		for (;;) {
			void* args[FUZZ_MAX_ARITY];
			fuzz_trial_get_args(t, args);

			res = fuzz_call(t, args);
			LOG(3 - LOG_SHRINK, "%s: call -> res %d\n", __func__,
					res);

			if (!repeated) {
				if (res == FUZZ_RESULT_FAIL) {
					t->trial.successful_shrinks++;
					fuzz_autoshrink_update_model(
							t, arg_i, res, 3);
				} else {
					t->trial.failed_shrinks++;
				}
			}

			int stpres;
			stpres = shrink_trial_post_hook(
					t, arg_i, args, tactic, res);
			if (stpres == FUZZ_HOOK_RUN_REPEAT ||
					(stpres == FUZZ_HOOK_RUN_REPEAT_ONCE &&
							!repeated)) {
				repeated = true;
				continue; // loop and run again
			} else if (stpres == FUZZ_HOOK_RUN_REPEAT_ONCE &&
					repeated) {
				break;
			} else if (stpres == FUZZ_HOOK_RUN_CONTINUE) {
				break;
			} else {
				if (ti->free) {
					ti->free(current, ti->env);
				}
				if (use_autoshrink && current_bit_pool) {
					fuzz_autoshrink_free_bit_pool(
							t, current_bit_pool);
				}
				return SHRINK_ERROR;
			}
		}

		fuzz_autoshrink_update_model(t, arg_i, res, 8);

		switch (res) {
		case FUZZ_RESULT_OK:
		case FUZZ_RESULT_SKIP:
			LOG(2 - LOG_SHRINK,
					"PASS or SKIP: REVERTING %u: "
					"candidate %p (pool %p), back to %p "
					"(pool %p)\n",
					arg_i, (void*)candidate,
					(void*)candidate_bit_pool,
					(void*)current,
					(void*)current_bit_pool);
			t->trial.args[arg_i].instance = current;
			if (use_autoshrink) {
				fuzz_autoshrink_free_bit_pool(
						t, candidate_bit_pool);
				t->trial.args[arg_i].u.as.env->bit_pool =
						current_bit_pool;
			}
			if (ti->free) {
				ti->free(candidate, ti->env);
			}
			break;
		case FUZZ_RESULT_FAIL:
			LOG(2 - LOG_SHRINK,
					"FAIL: COMMITTING %u: was %p (pool "
					"%p), now %p (pool %p)\n",
					arg_i, (void*)current,
					(void*)current_bit_pool,
					(void*)candidate,
					(void*)candidate_bit_pool);
			if (use_autoshrink) {
				assert(t->trial.args[arg_i].u.as.env
								->bit_pool ==
						candidate_bit_pool);
				fuzz_autoshrink_free_bit_pool(
						t, current_bit_pool);
			}
			assert(t->trial.args[arg_i].instance == candidate);
			if (ti->free) {
				ti->free(current, ti->env);
			}
			return SHRINK_OK;
		default:
		case FUZZ_RESULT_ERROR:
			if (ti->free) {
				ti->free(current, ti->env);
			}
			if (use_autoshrink) {
				fuzz_autoshrink_free_bit_pool(
						t, current_bit_pool);
			}
			return SHRINK_ERROR;
		}
	}
	(void)t;
	return SHRINK_DEAD_END;
}

static int
shrink_pre_hook(struct fuzz* t, uint8_t arg_index, void* arg, uint32_t tactic)
{
	if (t->hooks.shrink_pre != NULL) {
		struct fuzz_pre_shrink_info hook_info = {
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.failures     = t->counters.fail,
				.run_seed     = t->seeds.run_seed,
				.trial_id     = t->trial.trial,
				.trial_seed   = t->trial.seed,
				.arity        = t->prop.arity,
				.shrink_count = t->trial.shrink_count,
				.successful_shrinks =
						t->trial.successful_shrinks,
				.failed_shrinks = t->trial.failed_shrinks,
				.arg_index      = arg_index,
				.arg            = arg,
				.tactic         = tactic,
		};
		return t->hooks.shrink_pre(&hook_info, t->hooks.env);
	} else {
		return FUZZ_HOOK_RUN_CONTINUE;
	}
}

static int
shrink_post_hook(struct fuzz* t, uint8_t arg_index, void* arg, uint32_t tactic,
		int sres)
{
	if (t->hooks.shrink_post != NULL) {
		enum fuzz_post_shrink_state state;
		switch (sres) {
		case FUZZ_SHRINK_OK:
			state = FUZZ_SHRINK_POST_SHRUNK;
			break;
		case FUZZ_SHRINK_NO_MORE_TACTICS:
			state = FUZZ_SHRINK_POST_DONE_SHRINKING;
			break;
		case FUZZ_SHRINK_DEAD_END:
			state = FUZZ_SHRINK_POST_SHRINK_FAILED;
			break;
		default:
			assert(false);
			return FUZZ_HOOK_RUN_ERROR;
		}

		struct fuzz_post_shrink_info hook_info = {
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.run_seed     = t->seeds.run_seed,
				.trial_id     = t->trial.trial,
				.trial_seed   = t->trial.seed,
				.arity        = t->prop.arity,
				.shrink_count = t->trial.shrink_count,
				.successful_shrinks =
						t->trial.successful_shrinks,
				.failed_shrinks = t->trial.failed_shrinks,
				.arg_index      = arg_index,
				.arg            = arg,
				.tactic         = tactic,
				.state          = state,
		};
		return t->hooks.shrink_post(&hook_info, t->hooks.env);
	} else {
		return FUZZ_HOOK_RUN_CONTINUE;
	}
}

static int
shrink_trial_post_hook(struct fuzz* t, uint8_t arg_index, void** args,
		uint32_t last_tactic, int result)
{
	if (t->hooks.shrink_trial_post != NULL) {
		struct fuzz_post_shrink_trial_info hook_info = {
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.failures     = t->counters.fail,
				.run_seed     = t->seeds.run_seed,
				.trial_id     = t->trial.trial,
				.trial_seed   = t->trial.seed,
				.arity        = t->prop.arity,
				.shrink_count = t->trial.shrink_count,
				.successful_shrinks =
						t->trial.successful_shrinks,
				.failed_shrinks = t->trial.failed_shrinks,
				.arg_index      = arg_index,
				.args           = args,
				.tactic         = last_tactic,
				.result         = result,
		};
		return t->hooks.shrink_trial_post(&hook_info, t->hooks.env);
	} else {
		return FUZZ_HOOK_RUN_CONTINUE;
	}
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <string.h>

#if (-1 & 3) != 3
#error "fuzz requires 2s complement representation for integers"
#endif

static int should_not_run(struct fuzz* t, void* arg1);

// Change T's output stream handle to OUT. (Default: stdout.)
void
fuzz_set_output_stream(struct fuzz* t, FILE* out)
{
	t->out = out;
}

// Run a series of randomized trials of a property function.
//
// Configuration is specified in CFG; many fields are optional.
int
fuzz_run(const struct fuzz_run_config* cfg)
{
	if (cfg == NULL) {
		return FUZZ_RESULT_ERROR;
	}

	if (cfg->fork.enable && !FUZZ_POLYFILL_HAVE_FORK) {
		return FUZZ_RESULT_SKIP;
	}

	struct fuzz* t = NULL;

	enum fuzz_run_init_res init_res = fuzz_run_init(cfg, &t);
	switch (init_res) {
	case FUZZ_RUN_INIT_ERROR_MEMORY:
		return FUZZ_RESULT_ERROR_MEMORY;
	default:
		assert(false);
	case FUZZ_RUN_INIT_ERROR_BAD_ARGS:
		return FUZZ_RESULT_ERROR;
	case FUZZ_RUN_INIT_OK:
		break; // continue below
	}

	int res = fuzz_run_trials(t);
	fuzz_run_free(t);
	return res;
}

int
fuzz_generate(FILE* f, uint64_t seed, const struct fuzz_type_info* info,
		void* hook_env)
{
	int          res = FUZZ_RESULT_OK;
	struct fuzz* t   = NULL;

	struct fuzz_run_config cfg = {
			.name      = "generate",
			.prop1     = should_not_run,
			.type_info = {info},
			.seed      = seed,
			.hooks =
					{
							.env = hook_env,
					},
	};

	enum fuzz_run_init_res init_res = fuzz_run_init(&cfg, &t);
	switch (init_res) {
	case FUZZ_RUN_INIT_ERROR_MEMORY:
		return FUZZ_RESULT_ERROR_MEMORY;
	default:
		assert(false);
	case FUZZ_RUN_INIT_ERROR_BAD_ARGS:
		return FUZZ_RESULT_ERROR;
	case FUZZ_RUN_INIT_OK:
		break; // continue below
	}

	void* instance = NULL;
	int   ares     = info->alloc(t, info->env, &instance);
	switch (ares) {
	case FUZZ_RESULT_OK:
		break; // continue below
	case FUZZ_RESULT_SKIP:
		res = FUZZ_RESULT_SKIP;
		goto cleanup;
	case FUZZ_RESULT_ERROR:
		res = FUZZ_RESULT_ERROR_MEMORY;
		goto cleanup;
	}

	if (info->print) {
		fprintf(f, "-- Seed 0x%016" PRIx64 "\n", seed);
		info->print(f, instance, info->env);
		fprintf(f, "\n");
	}
	if (info->free) {
		info->free(instance, info->env);
	}

cleanup:
	fuzz_run_free(t);
	return res;
}

static int
should_not_run(struct fuzz* t, void* arg1)
{
	(void)t;
	(void)arg1;
	return FUZZ_RESULT_ERROR; // should never be run
}
// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <inttypes.h>

static int report_on_failure(struct fuzz*    t,
		struct fuzz_post_trial_info* hook_info,
		fuzz_hook_trial_post_cb* trial_post, void* trial_post_env);

fuzz_hook_trial_post_cb def_trial_post_cb;

// Now that arguments have been generated, run the trial and update
// counters, call cb with results, etc.
bool
fuzz_trial_run(struct fuzz* t, int* tpres)
{
	assert(t->prop.arity > 0);

	if (t->bloom) {
		fuzz_call_mark_called(t);
	}

	void* args[FUZZ_MAX_ARITY];
	fuzz_trial_get_args(t, args);

	bool                     repeated   = false;
	int                      tres       = fuzz_call(t, args);
	fuzz_hook_trial_post_cb* trial_post = t->hooks.trial_post;
	void* trial_post_env = (trial_post == fuzz_hook_trial_post_print_result
						? t->print_trial_result_env
						: t->hooks.env);

	struct fuzz_post_trial_info hook_info = {
			.t            = t,
			.prop_name    = t->prop.name,
			.total_trials = t->prop.trial_count,
			.run_seed     = t->seeds.run_seed,
			.trial_id     = t->trial.trial,
			.trial_seed   = t->trial.seed,
			.arity        = t->prop.arity,
			.args         = args,
			.result       = tres,
	};

	switch (tres) {
	case FUZZ_RESULT_OK:
		if (!repeated) {
			t->counters.pass++;
		}
		*tpres = trial_post(&hook_info, trial_post_env);
		break;
	case FUZZ_RESULT_FAIL:
		if (!fuzz_shrink(t)) {
			hook_info.result = FUZZ_RESULT_ERROR;
			// We may not have a valid reference to the arguments
			// anymore, so remove the stale pointers.
			for (size_t i = 0; i < t->prop.arity; i++) {
				hook_info.args[i] = NULL;
			}
			*tpres = trial_post(&hook_info, trial_post_env);
			return false;
		}

		if (!repeated) {
			t->counters.fail++;
		}

		fuzz_trial_get_args(t, hook_info.args);
		*tpres = report_on_failure(
				t, &hook_info, trial_post, trial_post_env);
		break;
	case FUZZ_RESULT_SKIP:
		if (!repeated) {
			t->counters.skip++;
		}
		*tpres = trial_post(&hook_info, trial_post_env);
		break;
	case FUZZ_RESULT_DUPLICATE:
		// user callback should not return this; fall through
	case FUZZ_RESULT_ERROR:
		*tpres = trial_post(&hook_info, trial_post_env);
		return false;
	}

	if (*tpres == FUZZ_HOOK_RUN_ERROR) {
		return false;
	}

	return true;
}

void
fuzz_trial_free_args(struct fuzz* t)
{
	for (size_t i = 0; i < t->prop.arity; i++) {
		struct fuzz_type_info* ti = t->prop.type_info[i];

		struct arg_info* ai = &t->trial.args[i];
		if (ai->type == ARG_AUTOSHRINK) {
			fuzz_autoshrink_free_env(t, ai->u.as.env);
		}
		if (ai->instance != NULL && ti->free != NULL) {
			ti->free(t->trial.args[i].instance, ti->env);
		}
	}
}

void
fuzz_trial_get_args(struct fuzz* t, void** args)
{
	for (size_t i = 0; i < t->prop.arity; i++) {
		args[i] = t->trial.args[i].instance;
	}
}

// Print info about a failure.
static int
report_on_failure(struct fuzz* t, struct fuzz_post_trial_info* hook_info,
		fuzz_hook_trial_post_cb* trial_post, void* trial_post_env)
{
	fuzz_hook_counterexample_cb* counterexample = t->hooks.counterexample;
	if (counterexample != NULL) {
		struct fuzz_counterexample_info counterexample_hook_info = {
				.t            = t,
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.trial_id     = t->trial.trial,
				.trial_seed   = t->trial.seed,
				.arity        = t->prop.arity,
				.type_info    = t->prop.type_info,
				.args         = hook_info->args,
		};

		if (counterexample(&counterexample_hook_info, t->hooks.env) !=
				FUZZ_HOOK_RUN_CONTINUE) {
			return FUZZ_HOOK_RUN_ERROR;
		}
	}

	int res;
	res = trial_post(hook_info, trial_post_env);

	while (res == FUZZ_HOOK_RUN_REPEAT ||
			res == FUZZ_HOOK_RUN_REPEAT_ONCE) {
		hook_info->repeat = true;

		int tres = fuzz_call(t, hook_info->args);
		if (tres == FUZZ_RESULT_FAIL) {
			res = trial_post(hook_info, t->hooks.env);
			if (res == FUZZ_HOOK_RUN_REPEAT_ONCE) {
				break;
			}
		} else if (tres == FUZZ_RESULT_OK) {
			fprintf(t->out, "Warning: Failed property passed when "
					"re-run.\n");
			res = FUZZ_HOOK_RUN_ERROR;
		} else if (tres == FUZZ_RESULT_ERROR) {
			return FUZZ_HOOK_RUN_ERROR;
		} else {
			return FUZZ_HOOK_RUN_CONTINUE;
		}
	}
	return res;
}
