CONTIKI = ../../contiki-2.4
#CONTIKI = ../../../../../../Contiki/contiki-2.x

ifndef TARGET
TARGET=cooja
endif


TIKIRIDB_DIR = ../node


ifeq ($(TARGET),)
  TARGET=cooja
endif

ifeq ($(TARGET),micaz)
DEFINES += QUEUEBUF_CONF_NUM=4,PLATFORM_AVR
endif

all: test-app

include $(TIKIRIDB_DIR)/Makefile.tikiridb

include $(CONTIKI)/Makefile.include


