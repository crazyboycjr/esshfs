# esshfs

esshfs (Encrypted Secure Shell Filesytem)is an encrypted filesystem based on [sshfs](https://github.com/libfuse/sshfs)

## Build

The build  method is inherted from sshfs(using autotools).

```
autoreconf -if
./configure --prefix=$PREFIX
make && make install
```
and the executable binary should locate at `$PREFIX/bin/esshfs`

## Usage

The usage is quite similar to sshfs
```
esshfs [user@]hostname:[directory] mountpoint
```

Other options can be learned from the manual of esshfs.

To unmount the filesystem
```
fusermount -u mountpoint
```

## Other

The filesystem is transparent encrypted, so you can use it as usual in theory.

At the server side, you can see the file are all encrypted.

__Warning__: Some softwares such as gedit, eog... will fail, because the file size read from stat system call is inconsistent with the decrypted file size since I use the block cipher algorithm.
