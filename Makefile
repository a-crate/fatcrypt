FUSE_DIR = fuse
FUSE_BUILD_DIR = $(FUSE_DIR)/build
FUSE_CLI = $(FUSE_BUILD_DIR)/fatcrypt

.PHONY: all fuse clean

all: fuse

fuse: $(FUSE_CLI)

$(FUSE_BUILD_DIR)/Makefile:
	mkdir -p $(FUSE_BUILD_DIR)
	cd $(FUSE_BUILD_DIR) && cmake $(FUSE_CMAKE_FLAGS) ..

$(FUSE_CLI): $(FUSE_BUILD_DIR)/Makefile $(wildcard $(FUSE_DIR)/*.c) $(wildcard $(FUSE_DIR)/*.h) $(wildcard $(FUSE_DIR)/fats/source/*.c) $(wildcard $(FUSE_DIR)/fatfs/source/*.h)
	$(MAKE) -C $(FUSE_BUILD_DIR) $(notdir $@)

clean:
	rm -rf $(FUSE_BUILD_DIR)/*
	rm -rf test/data/*

