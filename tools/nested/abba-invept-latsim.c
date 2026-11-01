/*
 * abba-invept-latsim.c -- Claude 27/10/2026, parere #85 §3.2.4: collaudo
 * OFFLINE di abba-invept-lat.d (gen-abba-lat.py) con DTrace vero (pid
 * provider). sim_invept() sta al posto di vmx_vept_invept: lavora su CPU
 * (attesa attiva) o dorme (fuori CPU), con valori attesi noti:
 *   300 chiamate da 40 us su CPU, 5 da 3 ms su CPU, 2 da 20 ms di SONNO,
 *   1 chiamata da 10 us che ne richiama un'altra (rientro).
 * Uso: abba-invept-latsim
 * cc -O0 -Wall -Wextra -Werror -o abba-invept-latsim abba-invept-latsim.c
 */
#include <time.h>
#include <unistd.h>

#define NI __attribute__((noinline))
typedef unsigned long long u64;

static u64
ora(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec);
}

/* modo 0: attesa attiva di ns; 1: sonno di ns; 2: attiva e poi rientro */
NI int
sim_invept(int modo, u64 ns)
{
	u64 t0 = ora();

	if (modo == 1) {
		usleep((useconds_t)(ns / 1000));
		return (0);
	}
	while (ora() - t0 < ns)
		;
	if (modo == 2)
		sim_invept(0, ns);
	return (0);
}

int
main(void)
{
	int i;

	for (i = 0; i < 300; i++)
		sim_invept(0, 40000);
	for (i = 0; i < 5; i++)
		sim_invept(0, 3000000);
	for (i = 0; i < 2; i++)
		sim_invept(1, 20000000);
	sim_invept(2, 10000);
	return (0);
}
