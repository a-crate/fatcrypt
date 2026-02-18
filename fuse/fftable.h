#ifndef FFTABLE_H
#define FFTABLE_H
#include <ff.h>
#include <fatcrypt.h>

#define FFFF_RDONLY 1

struct fftab {
	int fd;
	int index;
	int flags;
	FATFS fs;
	fatcrypt_config_t config;
	char mountpoint_dir[1024];
	char path[];
};

int fftab_new(const char *path, int flags);
void fftab_del(int index);
struct fftab *fftab_get(int index);

#endif
