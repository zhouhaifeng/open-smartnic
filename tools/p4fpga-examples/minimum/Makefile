P4FILE=min.p4

CONNECTALDIR?=$(DEV_ROOT)/p4fpga/connectal
P4FPGADIR?=$(DEV_ROOT)/p4fpga

CONNECTALFLAGS += --bsvpath=$(P4FPGADIR)/src/bsv/library
CONNECTALFLAGS += --bsvpath=$(P4FPGADIR)/src/bsv/datapath
CONNECTALFLAGS += --bsvpath=$(P4FPGADIR)/src/bsv/infra

CONNECTALFLAGS += -D PARSER=Parser
CONNECTALFLAGS += -D DEPARSER=Deparser
CONNECTALFLAGS += -D MATCHTABLE=Control
CONNECTALFLAGS += -D TYPEDEF=StructDefines
CONNECTALFLAGS += -m matchtable_model.cpp
CONNECTALFLAGS += -D NUM_RXCHAN=3
CONNECTALFLAGS += -D NUM_TXCHAN=3
CONNECTALFLAGS += -D NUM_HOSTCHAN=1
CONNECTALFLAGS += -D NUM_METAGEN=1
CONNECTALFLAGS += -D NUM_PKTGEN=3
CONNECTALFLAGS += -D STREAM

CPPFILES = $(P4FPGADIR)/src/control-plane/main.cpp $(P4FPGADIR)/src/control-plane/lpcap.c app_init.cpp
BSVFILES = $(P4FPGADIR)/src/bsv/infra/Main.bsv $(P4FPGADIR)/src/bsv/infra/MainAPI.bsv
BSVFILES += generatedbsv/ConnectalTypes.bsv
BSVFILES += $(P4FPGADIR)/src/bsv/library/DbgDefs.bsv

include ../Makefile.common
