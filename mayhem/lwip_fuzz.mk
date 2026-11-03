# Builds the lwIP stack + apps + unix port with the test/fuzz configuration into $(OBJDIR)/liblwipfuzz.a.
# Variables: SRC (repo root), OBJDIR, CC, FUZZ_CFLAGS.
SRC ?= /mayhem
OBJDIR ?= $(SRC)/build/fuzz
LWIPDIR := $(SRC)/src
CONTRIBDIR := $(SRC)/contrib
LWIPARCH := $(CONTRIBDIR)/ports/unix/port
include $(CONTRIBDIR)/Filelists.mk
include $(LWIPDIR)/Filelists.mk

ALLSRC := $(LWIPNOAPPSFILES) $(CONTRIBAPPFILES) $(LWIPAPPFILES) $(LWIPARCH)/perf.c $(LWIPARCH)/sys_arch.c
OBJS := $(addprefix $(OBJDIR)/,$(notdir $(ALLSRC:.c=.o)))
INCS := -I$(SRC)/test/fuzz -I$(CONTRIBDIR) -I$(LWIPDIR)/include -I$(LWIPARCH)/include

define OBJRULE
$(OBJDIR)/$(notdir $(1:.c=.o)): $(1)
	$$(CC) $$(FUZZ_CFLAGS) $$(EXTRA_CFLAGS) $$(INCS) -c $$< -o $$@
endef
# The harness supplies a deterministic sys_now(); the unix port's wall-clock one is renamed out of the way.
$(OBJDIR)/sys_arch.o: EXTRA_CFLAGS := -Dsys_now=lwip_unix_sys_now
$(foreach f,$(ALLSRC),$(eval $(call OBJRULE,$(f))))

$(OBJDIR)/liblwipfuzz.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $^
