## pam_sed

PAM module to unlock self-encrypting drives on user login

### Build

```shell script
git submodule update --init
mkdir build
cd build
cmake ..
make
```

This creates `build/pam_sed.so`.

### Usage

1. Build `pam_sed.so`
2. Place `pam_sed.so` in the correct location
3. Add `/etc/sedtab`
4. Add `pam_sed.so` to PAM config files

The location of PAM modules is usually `/lib/security` or `/lib64/security`.
Alternatively you can use full paths in config files.

The module supports `auth` and `session` types.
`auth` unlocks drives and `session` mounts partitions.

```
auth optional pam_sed.so
session optional pam_sed.so
```

**It is recommended to set the control value to `optional`
and not `required` because if something breaks you might get locked out of your system.**

### `/etc/sedtab` configuration file

The config file contains two types of lines: Drive Lines and Mount Lines.

#### Drive Line

```
drive USERNAME /dev/DRIVE
```

If `USERNAME` logs in, unlock `/dev/DRIVE` using his password (unless the drive is already unlocked).

#### Mount Line

```
mount USERNAME /dev/PART PATH TYPE
```

A session for `USERNAME` is opened by mounting `/dev/PART` to `PATH` with filesystem type `TYPE`.

### Known Issues

- After a disk is unlocked it takes a second or two for the OS to recognize its partitions.
  If you can unlock your drives using `sedutil-cli` but not this module, try increasing
  `SLEEP_AFTER_UNLOCK` in `library.hpp`.
- When a `session` is closed no partitions are unmounted.

### License

This module is released under GPLv3+ and uses code from `sedutil`.
