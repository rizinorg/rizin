# Benchmarks

You can find here several benchmarks for data structures.

## Adding a new benchmark

A new benchmark should always test against the API and the API alone.

The measurement of the code is done by wrapping it into `RZ_BENCH_RUN`
or `RZ_BENCH_RUN_I` macros.

- `RZ_BENCH_RUN` uses a running iteration counter with the name `i`.
- `RZ_BENCH_RUN_I` allows you to define the counter variable name.

**Example**

```c
static void bench_rz_vector_swap(RzTable *t_out) {
	RzVector *v = rz_vector_new(sizeof(ut64), NULL, NULL);

	for (size_t i = 0; i < ITERATION_COUNT; ++i) {
		rz_vector_push(v, &i);
	}

	{
		RZ_BENCH_RUN_I("[RzVector] rz_vector_swap", i, t_out, ITERATION_COUNT, {
      // <BEGIN: Your code>
			size_t index_a = rz_num_rand32(ITERATION_COUNT - 1);
			size_t index_b = rz_num_rand32(ITERATION_COUNT - 1);
			rz_vector_swap(v, index_a, index_b);
      // <END: Your code>
		});
	}

	rz_vector_free(v);
}
```

Check out other `bench_*.c` files for more examples.

### Benchmark guidelines

- Always build the benchmarks as "release" binary.
  Otherwise the measurements are not representative.
- Put the absolute minimum of code into the benchmark macro.
- One benchmark should be 1 commit.
- To run the benchmark against an older commit, check that commit out, cherry-pick
  the benchmark, build + run it.
  Do not duplicate old code!
- Include the benchmark results in the PR description.

### Corner cases

- There is an `RZ_DONT_OPTIMIZE` macro to prevent the compiler from optimizing
  the code within it. You should only use it if absolutely necessary.
  If you use it, document why.
  In general we _always_ want to test the optimized code.
