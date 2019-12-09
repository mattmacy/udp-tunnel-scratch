.if !defined(WITH_CTF)
WITH_CTF=1
.endif

.include <bsd.sys.mk>

SRCDIR= ${.CURDIR}
INCDIR=${.CURDIR:H}/include

KMOD=   if_wg

.PATH: ${SRCDIR}

CFLAGS+= -I${INCDIR}

CFLAGS+= -D__KERNEL__ -D__BSD_VISIBLE=1

.if defined(WITH_DEBUG) && ${WITH_DEBUG} == "true"
CFLAGS+= -DINVARIANTS -DWITNESS -g -O0
.else
CFLAGS += -DNDEBUG
.endif

DEBUG_FLAGS=-g

SRCS+= module.c


.include <bsd.kmod.mk>
