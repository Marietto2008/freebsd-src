/*
 * fintavm.c -- Claude 27/10/2026: processo finto per i collaudi degli script
 * ABBA. Compilato col NOME di un programma di VM (bhyve, qemu-system-x86_64)
 * perche' le guardie riconoscono le VM dal nome del programma (comm), non
 * dalla riga di comando. Non fa nulla: se SPENTO e' nell'ambiente aspetta che
 * quel file esista (Windows "spento"), altrimenti dorme per i secondi
 * dell'ULTIMO argomento.
 * cc -O0 -Wall -Wextra -Werror -o bhyve fintavm.c
 */
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	const char *f = getenv("SPENTO");
	int s = argc > 1 ? atoi(argv[argc - 1]) : 1;

	if (f != NULL) {
		while (access(f, F_OK) != 0)
			usleep(200000);
		return (0);
	}
	sleep(s > 0 ? (unsigned)s : 1);
	return (0);
}
