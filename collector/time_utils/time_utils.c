// time_utils.c
#include "time_utils.h"
#include <time.h>

/**
 * Function: monotonic_to_realtime_offset_ns
 * Summary:
 *   Computes the difference between the system's realtime clock and its
 *   monotonic clock, expressed in nanoseconds. This offset can be applied
 *   to timestamps originating from CLOCK_MONOTONIC to convert them into
 *   approximate realtime values.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - long long: The computed offset, in nanoseconds, where:
 *                offset = realtime_now - monotonic_now.
 */
long long monotonic_to_realtime_offset_ns(void)
{
	struct timespec mono, real;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	long long mono_ns = (long long)mono.tv_sec * 1000000000LL + mono.tv_nsec;
	long long real_ns = (long long)real.tv_sec * 1000000000LL + real.tv_nsec;
	return real_ns - mono_ns;
}
