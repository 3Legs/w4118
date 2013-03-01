APP := getcolors
ROOT:=$(HOME)
NDK_PLATFORM_VER := 14
INSTALL_DIR := /data/tmp

ANDROID_SDK_ROOT:=$(ROOT)/bin/android-sdk-linux
ANDROID_NDK_ROOT:=$(ROOT)/bin/android-ndk-r8d
ANDROID_NDK_HOST:=linux-x86
ANDROID_TARGET:=i686-linux-android
ANDROID_TARGET_ARCH:=x86
ANDROID_TOOLCHAIN:=x86-4.4.3

BINDIR:=$(ANDROID_NDK_ROOT)/toolchains/$(ANDROID_TOOLCHAIN)/prebuilt/$(ANDROID_NDK_HOST)
LIBDIR:=$(ANDROID_NDK_ROOT)/platforms/android-$(NDK_PLATFORM_VER)/arch-$(ANDROID_TARGET_ARCH)/usr/lib
INCDIR:=$(ANDROID_NDK_ROOT)/platforms/android-$(NDK_PLATFORM_VER)/arch-$(ANDROID_TARGET_ARCH)/usr/include
BIN := $(BINDIR)/bin
 
CPP := $(BIN)/$(ANDROID_TARGET)-g++
CC := $(BIN)/$(ANDROID_TARGET)-gcc
CFLAGS := -I$(INCDIR)
LDFLAGS := -Wl,-rpath-link=$(LIBDIR),-dynamic-linker=/system/bin/linker -L$(LIBDIR) 
LDFLAGS += $(LIBDIR)/crtbegin_dynamic.o $(LIBDIR)/crtend_android.o -nostdlib -lc -disable-multilib -lm
 
 
all: $(APP)
 
OBJS += $(APP).o
 
$(APP): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
 
%.o: %.c
	$(CC) -c $(INCLUDE) $(CFLAGS) $< -o $@ 
install: $(APP)
	$(ANDROID_SDK_ROOT)/platform-tools/adb push $(APP) $(INSTALL_DIR)/$(APP) 
	$(ANDROID_SDK_ROOT)/platform-tools/adb shell chmod 777 $(INSTALL_DIR)/$(APP)
 
shell:
	$(ANDROID_SDK_ROOT)/platform-tools/adb shell
 
run:
	$(ANDROID_SDK_ROOT)/platform-tools/adb shell $(INSTALL_DIR)/$(APP)
 
r: $(APP)
	$(ANDROID_SDK_ROOT)/platform-tools/adb push $(APP) $(INSTALL_DIR)/$(APP) 
	$(ANDROID_SDK_ROOT)/platform-tools/adb shell chmod 777 $(INSTALL_DIR)/$(APP)
	$(ANDROID_SDK_ROOT)/platform-tools/adb shell $(INSTALL_DIR)/$(APP)
 
clean:
	@rm -f $(APP).o $(APP)

