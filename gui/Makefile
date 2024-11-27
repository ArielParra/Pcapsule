# using GNU make:
ifdef OS  #Windows
	CC := g++.exe
	FLAGS := -lwpcap -lws2_32 -lraylib -mwindows
# -icon.res 
	FixPath = $(subst /,\,$1)
	InstallPath :=	C:\/Users\/$(USERNAME)\/AppData\/Local\/
	IconoPath   := InstallPath
	DesktopPath := C:\/Users\/$(USERNAME)\/Desktop\/
	UNAME := Windows
	EXT := .exe
else  	  #*NIX
	CC := g++
	FLAGS := -lpcap -lraylib
	RM := rm -f 
	FixPath = $1
	InstallPath := /usr/local/bin/
	IconoPath   := /usr/local/share/icons/
	DesktopPath := /home/$(USER)/Desktop
	UNAME = $(shell uname)
	EXT :=
endif

ICON := icon.ico
CFLAGS = -w -std=c++17
CFLAGS += -Ofast -funroll-loops -mavx2 # Optimizations
Name := pcapsule-$(UNAME)
DesktopFile := $(Name).desktop
SRC := main.cpp

all: $(Name)$(EXT)

$(Name)$(EXT): $(SRC)
	$(CC) $(CFLAGS) -o $(call FixPath,$(Name)$(EXT)) $< $(FLAGS)

install: $(Name)
	cp $(call FixPath,$(Name)$(EXT)) "$(call FixPath,$(InstallPath))"
ifeq ($(UNAME), Linux)
	cp $(ICON) $(IconoPath)
endif

uninstall:
	rm -f  "$(call FixPath,$(InstallPath))$(Name)$(EXT)"
ifeq ($(UNAME), Linux)
	rm -f $(InstallPath)$(Name)$(EXT)
	rm -f $(IconoPath)$(ICON)
endif

desktop: $(Name)
ifeq ($(UNAME), Linux)
	@echo "[Desktop Entry]" > $(DesktopFile)
	@echo "Version=1.0" >> $(DesktopFile)
	@echo "Name=$(Name)" >> $(DesktopFile)
	@echo "Comment=Solucionador de Klotski" >> $(DesktopFile)
	@echo "Exec=$(InstallPath)$(Name)" >> $(DesktopFile)
	@echo "Icon=$(IconoPath)$(ICON)" >> $(DesktopFile)
	@echo "Type=Application" >> $(DesktopFile)
	@echo "Categories=Network;System;Utility;" >> $(DesktopFile)
	@chmod +x $(DesktopFile)
	@mv $(DesktopFile) $(DesktopPath)
else ifeq ($(UNAME), Windows)
	@powershell.exe -Command " \
		$ws = New-Object -ComObject WScript.Shell; \
		$shortcut = $ws.CreateShortcut('$(call FixPath,$(DesktopPath))\\$(Name).lnk'); \
		$shortcut.TargetPath = '$(call FixPath,$(InstallPath))$(Name)$(EXT)'; \
		$shortcut.IconLocation = '$(call FixPath,$(IconoPath))'; \
		$shortcut.WorkingDirectory = '$(call FixPath,$(InstallPath))'; \
		$shortcut.Save(); \
	"
endif


clean:
	rm -f  $(call FixPath,$(Name)$(EXT))
ifeq ($(UNAME), Linux)
	rm -f  $(InstallPath)$(Name)$(EXT)
	rm -f  $(DesktopPath)$(DesktopFile)
endif

.PHONY: all clean install uninstall