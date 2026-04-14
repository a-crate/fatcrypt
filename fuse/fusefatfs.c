/**
 * Copyright (c) 2020 Renzo Davoli <renzo@cs.unibo.it>
 *
 * This program  is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#if FUSE == 2
#define FUSE_USE_VERSION 29
#define FUSE3_ONLY(...)
#else
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 14)
#define FUSE3_ONLY(...) __VA_ARGS__
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fuse.h>
#include <time.h>
#include <stddef.h>
#include <pthread.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>

#include <ff.h>
#include <fftable.h>
#include <config.h>
#include <fatcrypt.h>

int fuse_reentrant_tag = 0;

#if FF_DEFINED == 80286
#define FF_VERSION "0.15"
#else
#error FuseFat version mismaatch
#endif

#define FAT_DEFAULT_CODEPAGE 850

static pthread_mutex_t fff_mutex = PTHREAD_MUTEX_INITIALIZER;
#define mutex_in() pthread_mutex_lock(&fff_mutex)
#define mutex_out() pthread_mutex_unlock(&fff_mutex)
#define mutex_out_return(RETVAL) do {mutex_out(); return(RETVAL); } while (0)

#define fffpath(index, path) \
  *fffpath; \
  ssize_t __fffpathlen = (index == 0) ? 0 : strlen(path) + 3; \
  char __fffpath[__fffpathlen]; \
  if (index != 0) { \
    snprintf(__fffpath, __fffpathlen, "%d:%s", index, path); \
    fffpath = __fffpath; \
  } else \
    fffpath = path

static int fr2errno(FRESULT fres) {
	switch (fres) {
		case FR_OK: return 0;
		case FR_NO_FILE:
		case FR_NO_PATH:
								return -ENOENT;
		case FR_INVALID_NAME:
		case FR_INVALID_PARAMETER:
								return -EINVAL;
		case FR_DENIED:
								return -EACCES;
		case FR_WRITE_PROTECTED:
								return -EROFS;
		case FR_EXIST:
								return -EEXIST;
		case FR_NOT_ENOUGH_CORE:
								return -ENOMEM;
		default:
								return -EIO;
	}
}

static BYTE flags2ffmode(int flags) {
	// O_RDONLY -> FA_READ, O_WRONLY -> FA_WRITE, O_RDWR -> FA_READ | FA_WRITE
	BYTE ffmode = ((flags & O_ACCMODE) + 1) & O_ACCMODE;
	if (flags & O_CREAT) {
		if (flags & O_EXCL)
			ffmode |= FA_CREATE_NEW;
		else if (flags & O_TRUNC)
			ffmode |= FA_CREATE_ALWAYS;
		else
			ffmode |= FA_OPEN_ALWAYS;
	}
	if (flags & O_APPEND) {
		ffmode |= FA_OPEN_APPEND;
	}
	return ffmode;
}

static time_t fftime2time(WORD fdate, WORD ftime) {
	if (fdate == 0 && ftime == 0)
		return 0;
	else {
		struct tm tm = {0};

		tm.tm_year = ((fdate >> 9) & 0x7f) + 80;
		tm.tm_mon = ((fdate >> 5) & 0xf) - 1;
		tm.tm_mday = fdate & 0x1f;

		tm.tm_hour = (ftime >> 11) & 0x1f;
		tm.tm_min = (ftime >> 5) & 0x3f;
		tm.tm_sec = (ftime & 0x1f) * 2;

		return mktime(&tm);
	}
}

static int fff_getattr(const char *path, struct stat *stbuf FUSE3_ONLY(, struct fuse_file_info *fi))
{
	FUSE3_ONLY((void) fi);
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	FRESULT fres;
	// f_stat path: The object must not be the root directory */
	if (strcmp(path, "/") == 0) {
		memset(stbuf, 0, sizeof(struct stat));
		stbuf->st_mode = 0755 | S_IFDIR;
		stbuf->st_nlink = 2;
		mutex_out_return(0);
	} else {
		const char fffpath(ffentry->index, path);
		FILINFO fileinfo;
		if (!ffentry->fs.master_key_loaded || fatcrypt_is_metadata_path(path) || fatcrypt_is_plaintext_path(path, &ffentry->config.plaintext)) {
			fres = f_stat(fffpath, &fileinfo);
		} else {
			fres = f_crypt_stat(fffpath, &fileinfo);
		}
		//printf("getattr %s %s -> %d\n", path, fffpath, fres);
		if (fres != FR_OK) goto err;
		memset(stbuf, 0, sizeof(struct stat));
		stbuf->st_size = fileinfo.fsize;
		stbuf->st_ctime = stbuf->st_mtime =
			fftime2time(fileinfo.fdate, fileinfo.ftime);
		if (fileinfo.fattrib & AM_DIR) {
			stbuf->st_mode = 0755 | S_IFDIR;
			stbuf->st_nlink = 2;
		} else {
			stbuf->st_nlink = 1;
			stbuf->st_mode = 0755 | S_IFREG;
		}
		if (fileinfo.fattrib & AM_RDO)
			stbuf->st_mode &= ~0222;
	}
	mutex_out_return(0);
err:
	mutex_out_return(fr2errno(fres));
}

static int fff_open(const char *path, struct fuse_file_info *fi){
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	if ((ffentry->flags & FFFF_RDONLY) && (fi->flags & O_ACCMODE) != O_RDONLY)
		mutex_out_return(-EROFS);
	FIL fp;
	FRESULT fres = f_open(&fp, fffpath, flags2ffmode(fi->flags));
	if (fres == FR_OK)
		f_close(&fp);
	mutex_out_return(fr2errno(fres));
}

static int fff_create(const char *path, mode_t mode, struct fuse_file_info *fi){
	(void) fi;
	(void) mode; // XXX set readonly?
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	FIL fp;
	FRESULT fres = f_open(&fp, fffpath, flags2ffmode(fi->flags | O_CREAT));
	if (fres == FR_OK)
		f_close(&fp);
	mutex_out_return(fr2errno(fres));
}

static int fff_release(const char *path, struct fuse_file_info *fi){
	(void) path;
	(void) fi;
	return 0;
}

static int fff_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	FIL fp;
	UINT br;
	FRESULT fres = f_open(&fp, fffpath, flags2ffmode(fi->flags));
	if (fres != FR_OK)
		goto earlyerr;

	// Check if path is under .fat_crypt directory
	int is_metadata = fatcrypt_is_metadata_path(path);
	if (is_metadata < 0) {
		// Path normalization error (path traversal attempt)
		fres = FR_INVALID_NAME;
		goto err;
	}

	// Use appropriate seek and read functions
	// If master key was never loaded, always use unencrypted operations
	if (!ffentry->fs.master_key_loaded || fatcrypt_is_metadata_path(path) || fatcrypt_is_plaintext_path(path, &ffentry->config.plaintext)) {
		fres = f_lseek(&fp, offset);
		if (fres != FR_OK) goto err;
		fres = f_read(&fp, buf, size, &br);
	} else {
		fres = f_crypt_lseek(&fp, offset);
		if (fres != FR_OK) goto err;
		fres = f_crypt_read(&fp, buf, size, &br);
	}

	if (fres != FR_OK) goto err;
	f_close(&fp);
	mutex_out_return(br);
err:
	f_close(&fp);
earlyerr:
	mutex_out_return(fr2errno(fres));
}

static int fff_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	FIL fp;
	UINT bw;

	BYTE ffmode = flags2ffmode(fi->flags);
	if (ffentry->fs.master_key_loaded && !fatcrypt_is_metadata_path(path) && !fatcrypt_is_plaintext_path(path, &ffentry->config.plaintext)) {
		ffmode |= FA_READ;  /* Encrypted files must have read for read-modify-write.
		*  It's slightly awkward to force it here, but it's worse to do it inside fatfs
		*  and potentially break locking semantics or something. */
	}

	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	FRESULT fres = f_open(&fp, fffpath, ffmode);
	if (fres != FR_OK)
		goto earlyerr;

	// If master key was never loaded, always use unencrypted operations
	if (!ffentry->fs.master_key_loaded || fatcrypt_is_metadata_path(path) || fatcrypt_is_plaintext_path(path, &ffentry->config.plaintext)) {
		fres = f_lseek(&fp, offset);
		if (fres != FR_OK) goto err;
		fres = f_write(&fp, buf, size, &bw);
	} else {
		fres = f_crypt_lseek(&fp, offset);
		if (fres != FR_OK) goto err;
		fres = f_crypt_write(&fp, buf, size, &bw);
	}

	if (fres != FR_OK) goto err;
	fres = f_sync(&fp);
	if (fres != FR_OK) goto err;
	f_close(&fp);
	mutex_out_return(bw);
err:
	f_close(&fp);
earlyerr:
	mutex_out_return(fr2errno(fres));
}

static int fff_opendir(const char *path, struct fuse_file_info *fi){
	(void) fi;
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	DIR dp;
	FRESULT fres = f_opendir(&dp, fffpath);
	f_closedir(&dp);
	mutex_out_return(fr2errno(fres));
}

static int fff_releasedir(const char *path, struct fuse_file_info *fi){
	(void) path;
	(void) fi;
	return 0;
}

static int fff_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi FUSE3_ONLY(, enum fuse_readdir_flags fl)){
	(void) offset;
	(void) fi;
	FUSE3_ONLY((void) fl);
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	DIR dp;
	FRESULT fres = f_opendir(&dp, fffpath);
	if (fres != FR_OK)
		goto mutexout_leave;
	filler(buf, ".", NULL, 0 FUSE3_ONLY(, 0));
	filler(buf, "..", NULL, 0 FUSE3_ONLY(, 0));
	while(1) {
		FILINFO fileinfo;
		fres = f_readdir(&dp, &fileinfo);
		if (fres != FR_OK) break;
		if (fileinfo.fname[0] == 0) break;
		filler(buf, fileinfo.fname, NULL, 0 FUSE3_ONLY(, 0));
	}
	f_closedir(&dp);
mutexout_leave:
	mutex_out_return(fr2errno(fres));
}

static int fff_mkdir(const char *path, mode_t mode) {
	(void) mode;  // XXX set readonly
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	FRESULT fres = f_mkdir(fffpath);
	if (fres != FR_OK) return fr2errno(fres);
	// XXX mode?
	mutex_out_return(0);
}

static int fff_unlink(const char *path) {
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	// XXX ck is it reg file ?
	FRESULT fres = f_unlink(fffpath);
	mutex_out_return(fr2errno(fres));
}

static int fff_rmdir(const char *path) {
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	// XXX ck is it a dir ?
	FRESULT fres = f_unlink(fffpath);
	mutex_out_return(fr2errno(fres));
}

static int fff_rename(const char *path, const char *newpath FUSE3_ONLY(, unsigned int flags)) {
	FUSE3_ONLY(if(flags) return -ENOSYS;)

	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	FRESULT fres = f_rename(fffpath, newpath);
	mutex_out_return(fr2errno(fres));
}

static int fff_truncate(const char *path, off_t size FUSE3_ONLY(, struct fuse_file_info *fi)) {
	FUSE3_ONLY((void) fi);
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
	struct fftab *ffentry = cntx->private_data;
	const char fffpath(ffentry->index, path);
	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	FIL fp;
	memset(&fp, 0, sizeof(fp));
	FRESULT fres = f_open(&fp, fffpath, FA_WRITE);
	if (fres != FR_OK) goto openerr;

	// Use unencrypted truncate for .fat_crypt paths and plaintext paths
	// If master key was never loaded, always use unencrypted operations
	if (!ffentry->fs.master_key_loaded || fatcrypt_is_metadata_path(path) || fatcrypt_is_plaintext_path(path, &ffentry->config.plaintext)) {
		fres = f_lseek(&fp, size);
		if (fres != FR_OK) goto err;
		fres = f_truncate(&fp);
	} else {
		// Encrypted file - use f_crypt_truncate with logical size
		fres = f_crypt_truncate(&fp, size);
	}

	if (fres != FR_OK) goto err;
	fres = f_close(&fp);
openerr:
	mutex_out_return(fr2errno(fres));
err:
	f_close(&fp);
	mutex_out_return(fr2errno(fres));
}

static int fff_utimens(const char *path, const struct timespec tv[2] FUSE3_ONLY(, struct fuse_file_info *fi)) {
	FUSE3_ONLY((void) fi);
	mutex_in();
	struct fuse_context *cntx=fuse_get_context();
  struct fftab *ffentry = cntx->private_data;
  const char fffpath(ffentry->index, path);
	if (ffentry->flags & FFFF_RDONLY)
		mutex_out_return(-EROFS);
	FILINFO fno;
	struct tm tm;
	time_t newtime = tv[1].tv_sec;
	if (gmtime_r(&newtime, &tm) == NULL)
		mutex_out_return(-EINVAL);
	fno.fdate =
		/* bit15:9: Year origin from the 1980 (0..127, e.g. 37 for 2017) */
		(((tm.tm_year - 80) & 0x7f) << 9) |
		/* bit8:5: Month (1..12) */
		(((tm.tm_mon + 1) & 0xf) << 5) |
		/* bit4:0: Day of the month (1..31) */
		(tm.tm_mday & 0x1f);
	fno.ftime =
		/* bit15:11: Hour (0..23)) */
		((tm.tm_hour & 0x1f) << 11) |
		/* bit10:5: Minute (0..59) */
		((tm.tm_min & 0x3f) << 5) |
		/* bit4:0 Second / 2 (0..29, e.g. 25 for 50) */
		((tm.tm_sec & 0x3f) / 2);
	FRESULT fres = f_utime(fffpath, &fno);
	mutex_out_return(fr2errno(fres));
}

static int fff_statfs(const char *path, struct statvfs *buf) {
	(void) path;
	mutex_in();
  struct fuse_context *cntx=fuse_get_context();
  struct fftab *ffentry = cntx->private_data;
  const char fffpath(ffentry->index, "");
	memset(buf, 0, sizeof(*buf));
	FATFS *fs;
	DWORD fre_clust;
  FRESULT fres = f_getfree(fffpath, &fre_clust, &fs);
	if (fres == FR_OK) {
		WORD ssize =
#if FF_MAX_SS != FF_MIN_SS
			fs->ssize
#else
			FF_MAX_SS
#endif
			;
		buf->f_bsize = buf->f_frsize = fs->csize * ssize;
		buf->f_blocks = ((fs->n_fatent - 2) * ssize) / S_BLKSIZE;
		buf->f_bfree = buf->f_bavail = (fre_clust * ssize) / S_BLKSIZE;
		buf->f_namemax = 255;
	}
  mutex_out_return(fr2errno(fres));
}

// Helper function to prompt for passphrase if the master key is encrypted
// Returns: passphrase in provided buffer, or NULL if not needed or failed
static const char *fff_prompt_passphrase(const void *key_buf, size_t key_buf_size, char *passphrase_buf, size_t buf_size) {
	// Check minimum size for header (magic + version + encrypted flag)
	if (key_buf_size < 10) {
		fprintf(stderr, "Master key buffer too short\n");
		return NULL;
	}

	const uint8_t *header = key_buf;

	// Check encrypted flag (offset 9)
	if (header[9] != 1) {
		// Key is not encrypted, no passphrase needed
		return NULL;
	}

	// Key is encrypted, prompt for passphrase
	struct termios old_term, new_term;
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty) {
		fprintf(stderr, "Cannot open /dev/tty for passphrase input\n");
		return NULL;
	}

	fprintf(tty, "Enter passphrase to unlock encrypted filesystem: ");
	fflush(tty);

	// Disable echo
	tcgetattr(fileno(tty), &old_term);
	new_term = old_term;
	new_term.c_lflag &= ~ECHO;
	tcsetattr(fileno(tty), TCSANOW, &new_term);

	// Read passphrase
	const char *result = NULL;
	if (fgets(passphrase_buf, buf_size, tty)) {
		// Remove trailing newline
		size_t len = strlen(passphrase_buf);
		if (len > 0 && passphrase_buf[len-1] == '\n') {
			passphrase_buf[len-1] = '\0';
		}
		result = passphrase_buf;
	}

	// Restore terminal
	tcsetattr(fileno(tty), TCSANOW, &old_term);
	fprintf(tty, "\n");
	fclose(tty);

	return result;
}


static struct fftab *fff_init(const char *source, const char *mountpoint, int codepage, int flags, int encrypt) {
	int index = fftab_new(source, flags);
	if (index >= 0) {
		struct fftab *ffentry = fftab_get(index);
		char sdrv[12];
		snprintf(sdrv, 12, "%d:", index);
		FRESULT fres = f_mount(&ffentry->fs, sdrv, 1);
		if (fres != FR_OK) {
			fftab_del(index);
			return NULL;
		}
		if (codepage != 0) {
			if (f_setcp(codepage) != FR_OK) {
				fprintf(stderr, "codepage %d unavailable\n", codepage);
				f_setcp(FAT_DEFAULT_CODEPAGE);
			}
		} else
			f_setcp(FAT_DEFAULT_CODEPAGE);

		// Store mountpoint directory for config access
		snprintf(ffentry->mountpoint_dir, sizeof(ffentry->mountpoint_dir), "%s", mountpoint);
		snprintf(ffentry->fs.mountpoint_dir, sizeof(ffentry->fs.mountpoint_dir), "%s", mountpoint);

		// Initialize config with defaults (will be loaded if encryption enabled)
		ffentry->config.version = 1;
		ffentry->config.kdf.name = NULL;
		ffentry->config.kdf.cost = 0;
		ffentry->config.kdf.blockSize = 0;
		ffentry->config.kdf.parallel = 0;
		ffentry->config.plaintext.files = NULL;
		ffentry->config.plaintext.files_count = 0;
		ffentry->config.plaintext.directories = NULL;
		ffentry->config.plaintext.directories_count = 0;
		ffentry->fs.master_key_loaded = 0;

		// Only perform crypto initialization if encryption is enabled
		if (encrypt) {
			fprintf(stderr, "Initializing encryption from .fat_crypt/\n");

			// Read config.json from FAT filesystem
			char config_path[64];
			snprintf(config_path, sizeof(config_path), "%d:/.fat_crypt/config.json", index);
			void *config_buf = NULL;
			UINT config_size = 0;
			fres = f_preread_file(config_path, &config_buf, &config_size);
			if (fres != FR_OK) {
				fprintf(stderr, "Error: Could not read .fat_crypt/config.json (error %d)\n", fres);
				f_mount(0, sdrv, 1);
				fftab_del(index);
				return NULL;
			}

			// Parse config
			if (fatcrypt_load_config(config_buf, config_size, &ffentry->config) != 0) {
				fprintf(stderr, "Error: Could not parse config.json\n");
				free(config_buf);
				f_mount(0, sdrv, 1);
				fftab_del(index);
				return NULL;
			}
			free(config_buf);

			// Read master key from FAT filesystem
			char key_path[64];
			snprintf(key_path, sizeof(key_path), "%d:/.fat_crypt/keys/master.blob", index);
			void *key_buf = NULL;
			UINT key_size = 0;
			fres = f_preread_file(key_path, &key_buf, &key_size);
			if (fres != FR_OK) {
				fprintf(stderr, "Error: Could not read .fat_crypt/keys/master.blob (error %d)\n", fres);
				fatcrypt_free_config(&ffentry->config);
				f_mount(0, sdrv, 1);
				fftab_del(index);
				return NULL;
			}

			// Prompt for passphrase if master key is encrypted
			char passphrase_buf[256] = {0};
			const char *passphrase = fff_prompt_passphrase(key_buf, key_size, passphrase_buf, sizeof(passphrase_buf));

			// Load master key
			if (fatcrypt_load_master_key(key_buf, key_size, passphrase, &ffentry->config,
			                              ffentry->fs.master_key,
			                              sizeof(ffentry->fs.master_key)) != 0) {
				fprintf(stderr, "Error: Could not load master key\n");
				if (passphrase) {
					memset(passphrase_buf, 0, sizeof(passphrase_buf));
				}
				free(key_buf);
				fatcrypt_free_config(&ffentry->config);
				f_mount(0, sdrv, 1);
				fftab_del(index);
				return NULL;
			}
			free(key_buf);

			ffentry->fs.master_key_loaded = 1;
			fprintf(stderr, "Master key loaded successfully\n");

			// Clear passphrase from memory after successful initialization
			if (passphrase) {
				memset(passphrase_buf, 0, sizeof(passphrase_buf));
			}

			fprintf(stderr, "Crypto initialization complete, filesystem ready for mount\n");
		} else {
			fprintf(stderr, "Mounting without encryption\n");
		}

		return ffentry;
	} else
		return NULL;
}

static void fff_destroy(struct fftab *ffentry) {
	char sdrv[12];
	snprintf(sdrv, 12, "%d:", ffentry->index);

	// Clear master key from memory before unmount
	if (ffentry->fs.master_key_loaded) {
		memset(ffentry->fs.master_key, 0, sizeof(ffentry->fs.master_key));
		ffentry->fs.master_key_loaded = 0;
	}

	f_mount(0, sdrv, 1);
	fatcrypt_free_config(&ffentry->config);
	fftab_del(ffentry->index);
}

int fff_access (const char *path, int mode) {
	(void) path;
	(void) mode;
	return 0;
}

static const struct fuse_operations fusefat_ops = {
	.getattr  = fff_getattr,
	.open           = fff_open,
	.create         = fff_create,
	.read           = fff_read,
	.write          = fff_write,
	.release        = fff_release,
	.opendir        = fff_opendir,
	.readdir        = fff_readdir,
	.releasedir     = fff_releasedir,
	.mkdir          = fff_mkdir,
	.unlink         = fff_unlink,
	.rmdir          = fff_rmdir,
	.rename         = fff_rename,
	.truncate       = fff_truncate,
	.utimens        = fff_utimens,
	.statfs         = fff_statfs,
	.access         = fff_access,
};

static void usage(void)
{
	fprintf(stderr,
			"usage: " PROGNAME " image mountpoint [options]\n"
			"   or: " PROGNAME " keygen <directory|device> [options]\n"
			"\n"
			"general options:\n"
			"    -o opt,[opt...]    mount options\n"
			"    -h   --help        print help\n"
			"    -V   --version     print version\n"
			"\n"
			PROGNAME " options:\n"
			"    -o ro     disable write support\n"
			"    -o rw+    enable write support\n"
			"    -o rw     enable write support only together with -force\n"
			"    -o force  enable write support only together with -rw\n"
			"    -o codepage=XXX         set codepage (default 850)\n"
			"    -e, --encrypt           enable encryption (reads key and config from .fat_crypt/)\n"
			"\n"
			"keygen options:\n"
			"    -p, --passphrase=PASS      passphrase to protect master key\n"
			"    -i, --interactive          prompt for passphrase interactively\n"
			"    --3ds                      add 3DS-specific plaintext files (boot.firm, kernel.bin, luma/payloads/)\n"
			"    --plaintext-file=PATH      add file to plaintext list (repeatable)\n"
			"    --plaintext-dir=PATH       add directory to plaintext list (repeatable)\n"
			"\n"
			"    this software is still experimental\n"
			"\n");
}

struct options {
	const char *source;
	const char *mountpoint;
	int encrypt;
	int ro;
	int rw;
	int rwplus;
	int force;
	int codepage;
};

#define FFF_OPT(t, p, v) { t, offsetof(struct options, p), v }

static struct fuse_opt fff_opts[] =
{
	FFF_OPT("ro", ro, 1),
	FFF_OPT("rw", rw, 1),
	FFF_OPT("rw+", rwplus, 1),
	FFF_OPT("force", force, 1),
	FFF_OPT("codepage=%u", codepage, 1),
	FFF_OPT("-e", encrypt, 1),
	FFF_OPT("--encrypt", encrypt, 1),
	FFF_OPT("encrypt", encrypt, 1),

	FUSE_OPT_KEY("-V", 'V'),
	FUSE_OPT_KEY("--version", 'V'),
	FUSE_OPT_KEY("-h", 'h'),
	FUSE_OPT_KEY("--help", 'h'),
	FUSE_OPT_END
};

	static int
fff_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	struct options *options = data;
	switch(key) {
		case FUSE_OPT_KEY_OPT:
			return 1;
		case FUSE_OPT_KEY_NONOPT:
			if (!options->source) {
				options->source = arg;
				return 0;
			} else if(!options->mountpoint) {
				options->mountpoint = arg;
				return 1;
			} else
				return -1;
			break;
		case 'h':
			usage();
			fuse_opt_add_arg(outargs, "-ho");
			fuse_main(outargs->argc, outargs->argv, &fusefat_ops, NULL);
			return -1;

		case 'V':
			fprintf(stderr, PROGNAME " version %s -- FatFS %s\n", VERSION, FF_VERSION);
			fuse_opt_add_arg(outargs, "--version");
			fuse_main(outargs->argc, outargs->argv, &fusefat_ops, NULL);
			return -1;

		default:
			return -1;
	}
}

// Mount a device using this binary as a FUSE filesystem.
// The FUSE process daemonizes once mounted, so waitpid returning means mount is ready.
// Returns 0 on success, -1 on failure.
static int mount_device_for_keygen(const char *device, const char *mountpoint, const char *self_path) {
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		execlp(self_path, self_path, "-o", "rw+", device, mountpoint, NULL);
		fprintf(stderr, "exec failed: %s\n", strerror(errno));
		_exit(1);
	}

	int status;
	waitpid(pid, &status, 0);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "Mount failed\n");
		return -1;
	}

	return 0;
}

static int unmount_device(const char *mountpoint) {
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		execlp("fusermount", "fusermount", "-u", mountpoint, NULL);
		execlp("fusermount3", "fusermount3", "-u", mountpoint, NULL);
		fprintf(stderr, "exec fusermount failed: %s\n", strerror(errno));
		_exit(1);
	}

	int status;
	waitpid(pid, &status, 0);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "Unmount failed\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	// Check for keygen subcommand
	if (argc >= 2 && strcmp(argv[1], "keygen") == 0) {
		fatcrypt_keygen_config_t config = {
			.mountpoint_dir = NULL,
			.passphrase = NULL,
			.interactive = 0,
			.use_3ds_defaults = 0,
			.plaintext_files = NULL,
			.plaintext_files_count = 0,
			.plaintext_dirs = NULL,
			.plaintext_dirs_count = 0
		};

		// Parse keygen options first
		for (int i = 2; i < argc; i++) {
			if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
				usage();
				return 0;
			} else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
				config.interactive = 1;
			} else if (strcmp(argv[i], "--3ds") == 0) {
				config.use_3ds_defaults = 1;
			} else if (strncmp(argv[i], "-p=", 3) == 0 || strncmp(argv[i], "--passphrase=", 13) == 0) {
				config.passphrase = strchr(argv[i], '=') + 1;
			} else if (strncmp(argv[i], "--plaintext-file=", 17) == 0) {
				char *file = argv[i] + 17;
				config.plaintext_files = realloc(config.plaintext_files,
					sizeof(char*) * (config.plaintext_files_count + 1));
				config.plaintext_files[config.plaintext_files_count++] = file;
			} else if (strncmp(argv[i], "--plaintext-dir=", 16) == 0) {
				char *dir = argv[i] + 16;
				config.plaintext_dirs = realloc(config.plaintext_dirs,
					sizeof(char*) * (config.plaintext_dirs_count + 1));
				config.plaintext_dirs[config.plaintext_dirs_count++] = dir;
			} else if (argv[i][0] != '-') {
				// Non-option argument is the directory
				if (config.mountpoint_dir == NULL) {
					config.mountpoint_dir = argv[i];
				} else {
					fprintf(stderr, "Error: multiple directory arguments provided\n\n");
					usage();
					return -1;
				}
			} else {
				fprintf(stderr, "Unknown keygen option: %s\n\n", argv[i]);
				usage();
				return -1;
			}
		}

		// Validate directory/device was provided
		if (config.mountpoint_dir == NULL) {
			fprintf(stderr, "Error: keygen requires a directory or device argument\n\n");
			usage();
			free(config.plaintext_files);
			free(config.plaintext_dirs);
			return -1;
		}

		// Check if argument is a block device
		struct stat sbuf;
		if (stat(config.mountpoint_dir, &sbuf) < 0) {
			fprintf(stderr, "%s: %s\n", config.mountpoint_dir, strerror(errno));
			free(config.plaintext_files);
			free(config.plaintext_dirs);
			return -1;
		}

		int ret;
		if (S_ISBLK(sbuf.st_mode)) {
			// Block device: create tmpdir, mount, keygen, unmount
			char tmpdir[] = "/tmp/fatcrypt.XXXXXX";
			if (mkdtemp(tmpdir) == NULL) {
				fprintf(stderr, "Failed to create temp directory: %s\n", strerror(errno));
				free(config.plaintext_files);
				free(config.plaintext_dirs);
				return -1;
			}

			const char *device_path = config.mountpoint_dir;
			printf("Mounting %s at %s...\n", device_path, tmpdir);

			if (mount_device_for_keygen(device_path, tmpdir, argv[0]) != 0) {
				rmdir(tmpdir);
				free(config.plaintext_files);
				free(config.plaintext_dirs);
				return -1;
			}

			config.mountpoint_dir = tmpdir;
			ret = fatcrypt_keygen(&config);

			printf("Unmounting %s...\n", tmpdir);
			if (unmount_device(tmpdir) != 0) {
				fprintf(stderr, "Warning: unmount failed\n");
			}
			rmdir(tmpdir);
		} else if (S_ISDIR(sbuf.st_mode)) {
			ret = fatcrypt_keygen(&config);
		} else {
			fprintf(stderr, "Error: %s is not a directory or block device\n", config.mountpoint_dir);
			free(config.plaintext_files);
			free(config.plaintext_dirs);
			return -1;
		}

		free(config.plaintext_files);
		free(config.plaintext_dirs);
		return ret;
	}

	int err;
	struct options options = {0};
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fftab *ffentry;
	int flags = 0;
	struct stat sbuf;
	putenv("TZ=UTC0");
	if (fuse_opt_parse(&args, &options, fff_opts, fff_opt_proc) == -1) {
		fuse_opt_free_args(&args);
		return -1;
	}
	if (options.rw == 0 && options.rwplus == 0)
		options.ro = 1;
	if (options.rw == 1 && options.force == 0) {
		fprintf(stderr,
				"The file system will be mounted in read-only mode.\n"
				"This is still experimental code.\n"
				"The option to mount in read-write mode is: -o rw+\n"
				"or: -o rw,force\n\n");
		options.ro = 1;
	}

	if (options.source == NULL || options.mountpoint == NULL) {
		usage();
		goto returnerr;
	}

	if (stat(options.source, &sbuf) < 0) {
		fprintf(stderr, "%s: %s\n", options.source, strerror(errno));
		goto returnerr;
	}

	if (! S_ISREG(sbuf.st_mode) && ! S_ISBLK(sbuf.st_mode)) {
		fprintf(stderr, "%s: source must be a block device or a regular file (image)\n", options.source);
		goto returnerr;
	}

	if (options.ro) flags |= FFFF_RDONLY;

	// Initialize filesystem with optional encryption
	if ((ffentry = fff_init(options.source, options.mountpoint, options.codepage, flags, options.encrypt)) == NULL) {
		fprintf(stderr, "Filesystem initialization failed\n");
		goto returnerr;
	}
	err = fuse_main(args.argc, args.argv, &fusefat_ops, ffentry);
	fff_destroy(ffentry);
	fuse_opt_free_args(&args);
	if (err) fprintf(stderr, "Fuse error %d\n", err);
	return err;
returnerr:
	fuse_opt_free_args(&args);
	return -1;
}
