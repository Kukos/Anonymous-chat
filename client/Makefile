THIS_DIR := $(PROJECT_DIR)/client

IDIR := $(THIS_DIR)/include
SDIR := $(THIS_DIR)/src
LDIR := $(PROJECT_DIR)/external/libs

SRCS := $(wildcard $(SDIR)/*.c)
SRCS += $(ESDIR)/log.c
SRCS += $(ESDIR)/assert.c
SRCS += $(wildcard $(CSDIR)/*.c)
OBJS := $(SRCS:%.c=%.o)
DEPS := $(wildcard $(IDIR)/*.h)
DEPS += $(wildcard $(EIDIR)/*.h)
DEPS += $(wildcard $(CIDIR)/*.h)

LIBS := -lcrc -lssl -lcrypto

EXEC := $(THIS_DIR)/client.out

%.o: %.c
	$(call print_cc, $<)
	$(Q)$(CC) $(CFLAGS) -I$(IDIR) -I$(EIDIR) -I$(CIDIR) -c $< -o $@

$(EXEC): $(OBJS)
	$(call print_bin, $@)
	$(Q)$(CC) $(CFLAGS) -L$(LDIR) -I$(IDIR) -I$(EIDIR) -I$(CIDIR) $(OBJS) $(LIBS) -o $@

clean:
	$(call print_info,Cleaning)
	$(Q)$(RM) $(OBJS)
	$(Q)$(RM) $(T_OBJS)
	$(Q)$(RM) $(EXEC)
	$(Q)$(RM) $(T_EXEC)
