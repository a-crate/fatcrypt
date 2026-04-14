# fatcrypt

Fatcrypt is a partially encrypted filesystem with the same on-disk format as FAT.

It is capable of leaving some files un-encrypted (and therefore readable by any other FAT implementation) while
transparently encrypting all other files. This is done by embedding all data about the encrypted file in the file
contents. This has some noteable drawbacks, most obviously and primarily that no file metadata is encrypted whatsoever.

The primary use case for this project is embedded devices with the following conditions:

1. all files must live on a single FAT32 partition
2. the contents of most files should be encrypted
3. select files known ahead of time must remain plaintext (bootloader, kernels, etc)

Using this fileysystem is not a good idea. It is a toy.

## Implementation

The implementation in this repository is a FUSE binary for Linux. I plan to port this to Luma3DS.
Maybe someday I'll port this to grub or systemd-boot for fun.

## Usage

This will walk through setup and usage of an example filesystem on a loopback device.

1. Make a FAT filesystem
```bash
sudo mkfs.vfat -F 32 /dev/loop0
```

2. Generate fatcrypt keys and configuration

The keygen subcommand accepts either a directory (mounted filesystem) or a device file directly.
When given a device, it temporarily mounts it, generates keys, and unmounts.

```bash
sudo fatcrypt keygen /dev/loop0 --interactive \
    --plaintext-file=config.text --plaintext-dir=grub/
```

OR
```bash
sudo mkdir -p /run/fatcrypt
sudo mount -o rw /dev/loop0 /run/fatcrypt
sudo fatcrypt keygen /run/fatcrypt --interactive \
    --plaintext-file=config.text --plaintext-dir=grub/
sudo umount /dev/loop0
```

After keygen, back up the generated keys:
```bash
sudo mkdir -p /run/fatcrypt
sudo mount -o rw /dev/loop0 /run/fatcrypt
sudo cp /run/fatcrypt/.fat_crypt/keys/master.blob ./fatcrypt_key.blob
sudo cp /run/fatcrypt/.fat_crypt/config.json ./fatcrypt_config.json
sudo umount /dev/loop0
```

3. Mount fatcrypt with encryption
```bash
sudo mkdir -p /run/fatcrypt
sudo fatcrypt -o rw+ /dev/loop0 /run/fatcrypt
```

4. Use the filesystem
```bash
echo "hello world!" > /run/fatcrypt/hello.txt

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

