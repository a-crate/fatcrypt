# fatcrypt

Fatcrypt is a partially encrypted filesystem with the same on-disk format as FAT.

It is capable of leaving some files un-encrypted (and therefore readable by any other FAT implementation) while
transparently encrypting all other files. This is done by embedding all data about the encrypted file in the file
contents. This has some noteable drawbacks, most obviously and primarily that no file metadata is encrypted whatsoever.

The primary use case for this project is embedded devices with the following conditions:

1. all files must live on a single FAT32 partition
2. the contents of most files should be encrypted
3. select files known ahead of time must remain plaintext (bootloader, kernels, etc)

Using this fileysystem is not a good idea. It is a toy. The on-disk format will change again, consider it stable once
I tag a release.

## Implementation

The implementation in this repository is a FUSE binary for Linux. I plan to port this to Luma3DS.
Maybe someday I'll port this to grub or systemd-boot for fun.

The FUSE implementation requires selecting the config and master key from outside of the filesystem,
which obviously allows one to mix up keys and configs, curdle your data, and create really problematic state.
A good implementation would instead mount the FS read-only, detect the key & config out of `fat_crypt`,
initialize crypto, and then remount in the final mount mode.

## Usage

This will walk through setup and usage of an example filesystem on a loopback device.

1. Make and mount a FAT filesystem
```bash
mkfs.vfat -F 32 /dev/loop0
mkdir -p /run/fatcrypt
mount -o rw /dev/loop0 /run/fatcrypt
```

2. Generate fatcrypt keys and configuration
```bash
fatcrypt keygen /run/fatcrypt --interactive \
    --plaintext-file=config.text --plaintext-dir=grub/ \ # Repeat for whatever files should remain unencrypted
    --3ds # Use appropriate key sizes and plaintext options for the nintendo 3DS with Luma3DS

cp /run/fatcrypt/.fat_crypt/keys/master.blob ./fatcrypt_key.blob
cp /run/fatcrypt/.fat_crypt/config.json ./fatcrypt_config.json
cp /run/fatcrypt/.fat_crypt/config.sig ./fatcrypt_config.sig # TODO: add CLI tool to verify config signatures and generate an up to date signature. This isn't very useful right now
```

3. Re-mount fatcrypt with encryption keys
```bash
umount /dev/loop0
fatcrypt -o rw+ /dev/loop0 /run/fatcrypt --master-key ./fatcrypt_key.blob --config ./fatcrypt_config.json
```

4. Use the filesystem
```bash
echo "hello world!" > /run/fatcrypt/hello.text

cat /run/fatcrypt/hello.txt
```

## Building

The top-level Makefile is wrapper around the cmake build system that wolfcrypt and the FUSE binary
use. Do this:

```
nix-shell --run make
install -Dm0755 fuse/build/fatcrypt /usr/bin/fatcrypt
```

TODO: better docs I guess

## Prior Art

Built off of [fusefatfs](https://github.com/virtualsquare/fusefatfs), which is built off of [fatfs](https://www.elm-chan.org/fsw/ff/).

