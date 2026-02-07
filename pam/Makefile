CC = clang
CFLAGS = -Wall -Wextra -fPIC -fobjc-arc -arch arm64 -arch x86_64
LDFLAGS = -framework LocalAuthentication -framework Security -framework CoreFoundation -lpam
TARGET = pam_mac_n_keys.so
PREFIX = /usr/lib/pam

.PHONY: all clean install

all: $(TARGET)

$(TARGET): pam_mac_n_keys.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) $(PREFIX)/
	@echo "Installed to $(PREFIX)/$(TARGET)"
	@echo ""
	@echo "Add to /etc/pam.d/sudo:"
	@echo "  auth sufficient pam_mac_n_keys.so"
