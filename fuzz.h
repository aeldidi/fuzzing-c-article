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
