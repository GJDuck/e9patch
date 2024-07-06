CC=gcc
CFLAGS=-fPIC -Os -I include/ -I dependencies/zycore/include/ -I src/

OBJS=src/Decoder.o \
     src/DecoderData.o \
     src/FormatterATT.o \
     src/FormatterBase.o \
     src/FormatterBuffer.o \
     src/Formatter.o \
     src/FormatterIntel.o \
     src/MetaInfo.o \
     src/Mnemonic.o \
     src/Register.o \
     src/SharedData.o \
     src/String.o \
     src/Utils.o \
     src/Zydis.o \
     dependencies/zycore/src/Allocator.o \
     dependencies/zycore/src/ArgParse.o \
     dependencies/zycore/src/Bitset.o \
     dependencies/zycore/src/Format.o \
     dependencies/zycore/src/List.o \
     dependencies/zycore/src/String.o \
     dependencies/zycore/src/Vector.o \
     dependencies/zycore/src/Zycore.o

all: $(OBJS)
	ar rcs libZydis.a $(OBJS)

clean:
	rm -rf libZydis.a $(OBJS)

