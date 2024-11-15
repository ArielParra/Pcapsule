# using GNU make:
ifdef OS  #Windows
	CC := g++.exe
	FLAGS := -lwpcap
	FixPath = $(subst /,\,$1)
	UNAME := Windows
	EXT := .exe
else  	  #*NIX
	CC := g++
	FLAGS := -lpcap
	RM := rm -f 
	FixPath = $1
	UNAME = $(shell uname)
	EXT :=
endif

CFLAGS := -O2 -s -w
Name := pcapsule-$(UNAME)
SRC := main.cpp

all: $(Name)$(EXT)

$(Name)$(EXT): $(SRC)
	$(CC) $(CFLAGS) -o $(call FixPath,$(Name)$(EXT)) $< $(FLAGS)

clean:
	rm -f  $(call FixPath,$(Name)$(EXT))

.PHONY: all clean