
CC=gcc
CFLAGS=-O0 -g -Wall
ODIR=build
DEPS=

ifeq ($(INIH_PATH),)
INCLUDE=-I.
LDFLAGS=-L.
else
INCLUDE=-I. -I$(INIH_PATH)
LDFLAGS=-L. -L$(INIH_PATH)
endif

LDLIBS=-linih

SRC = config_app.c fpga_5gnr_cfg_app.c fpga_5gnr_cfg_parser.c
OBJ = $(patsubst %.c,$(ODIR)/%.o,$(SRC))

.PHONY: clean

all: pf_config_app

$(ODIR):
	mkdir -p $(ODIR)

$(OBJ): $(ODIR)/%.o: ./%.c | $(DEPS) $(ODIR)
	@mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDE)

pf_config_app: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(ODIR)
	rm -rf pf_config_app
