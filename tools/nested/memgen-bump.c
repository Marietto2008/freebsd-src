/*
 * tools/nested/memgen-bump.c -- Claude 21/10/2026, prova del parere #28 di
 * Astra (§4): fa avanzare UNA volta la generazione dei mapping di una VM
 * (ioctl VM_NESTED_MEMGEN_BUMP), senza cambiare i mapping. Il kernel prende
 * gli stessi lock di VM_MMAP_MEMSEG: memseg in esclusiva e tutti i vCPU
 * fermi. Serve hw.vmm.nested_memgen_inject=1.
 *
 *   cc -o memgen-bump memgen-bump.c && sudo ./memgen-bump vm2
 */
#include <sys/types.h>
#include <sys/ioctl.h>

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifndef VM_NESTED_MEMGEN_BUMP
#define	VM_NESTED_MEMGEN_BUMP	_IOR('v', 131, uint64_t)
#endif

int
main(int argc, char **argv)
{
	char path[256];
	uint64_t gen;
	int fd;

	snprintf(path, sizeof(path), "/dev/vmm/%s", argc > 1 ? argv[1] : "vm2");
	if ((fd = open(path, O_RDWR)) < 0)
		err(1, "%s", path);
	if (ioctl(fd, VM_NESTED_MEMGEN_BUMP, &gen) != 0)
		err(1, "VM_NESTED_MEMGEN_BUMP");
	printf("%s: generazione dei mapping ora %ju\n", path, (uintmax_t)gen);
	close(fd);
	return (0);
}
