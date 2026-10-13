SRCS+=	ppt.c			\
	vmmapi_machdep.c	\
	vmmapi_freebsd_machdep.c

.PATH:  ${SRCTOP}/sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

CFLAGS+= -DWITH_VMMAPI_SNAPSHOT
#CFLAGS.vmmapi_machdep.c+= -I${SRCTOP}/sys/amd64
