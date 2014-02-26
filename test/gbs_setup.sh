#!/bin/sh

sudo mkdir -p ~/GBS-ROOT/8974-eur-open/local/BUILD-ROOTS/scratch.armv7l.0/var/tmp/dts_fw
sudo mount -o bind . ~/GBS-ROOT/8974-eur-open/local/BUILD-ROOTS/scratch.armv7l.0/var/tmp/dts_fw
gbs chroot -r ~/GBS-ROOT/8974-eur-open/local/BUILD-ROOTS/scratch.armv7l.0

# do somgthing...

sudo umount ~/GBS-ROOT/8974-eur-open/local/BUILD-ROOTS/scratch.armv7l.0/var/tmp/dts_fw
