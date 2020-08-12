/*
 * pam_sed - unlock self-encrypting drives via PAM
 * Copyright (C) 2020 Fabian Stiewitz <fabian@stiewitz.pw>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef PAM_SED_LIBRARY_H
#define PAM_SED_LIBRARY_H

#include <security/pam_modules.h>

#include <vector>

#define SEDTAB "/etc/sedtab"
#define SLEEP_AFTER_UNLOCK 2
#define MAX_TOKEN_LENGTH 1024
#define DRIVE_LINE_FORMAT "%1023s %1023s"
#define MOUNT_LINE_FORMAT "%1023s %1023s %1023s %1023s"

/**
 * \brief Unlock all drives mapped to user
 * \param handle PAM handle for logging
 * \param user Username
 * \param password Password
 * \return PAM_SUCCESS on success
 */
int pam_sed_unlock(pam_handle_t *handle, const char* user, const char* password);

/**
 * \brief Mount all partitions mapped to user
 * \param handle PAM handle for logging
 * \param user Username
 * \return PAM_SUCCESS on success
 */
int pam_sed_mount(pam_handle_t *handle, const char* user);

/**
 * \brief Unmount all partitions mapped to user
 * \param handle PAM handle for logging
 * \param user Username
 * \return PAM_SUCCESS on success
 * \warning currently unused
 */
int pam_sed_umount(pam_handle_t *handle, const char* user);

struct drive_line_t {
    char user[MAX_TOKEN_LENGTH];
    char path[MAX_TOKEN_LENGTH];
};

struct mount_line_t {
    char user[MAX_TOKEN_LENGTH];
    char drive[MAX_TOKEN_LENGTH];
    char path[MAX_TOKEN_LENGTH];
    char type[MAX_TOKEN_LENGTH];
};

/**
 * \brief Read all drive and mount lines from SEDTAB (:= `/etc/sedtab`)
 *
 * SEDTAB contains two types of lines:
 *   - drive lines: `drive USERNAME DISK` (ex.: `drive fabian /dev/sda`)
 *   - mount lines: `mount USERNAME PARTITION MOUNTPOINT TYPE` (ex.: `mount fabian /dev/sda1 /home ext4`)
 *
 * \param drives
 * \param mounts
 * \return PAM_SUCCESS on success
 */
int pam_sed_read_config(std::vector<drive_line_t> &drives, std::vector<mount_line_t> &mounts);

/**
 * \brief Try to unlock drive with password
 * \param handle PAM handle for logging
 * \param drive Drive to unlock
 * \param password Password
 * \return PAM_SUCCESS on success
 * \note After unlocking the drive this function waits for SLEEP_AFTER_UNLOCK (:= 2) seconds because the partitions are not discovered
 *       immediately. This can potentially mean that the mount operation will fail because the partition has not been
 *       discovered yet. On a RPi 4B this delay seems to work though.
 */
int pam_sed_try_drive_unlock(pam_handle_t *handle, const drive_line_t &drive, const char* password);

/**
 * \brief Try to mount a partition
 * \param handle PAM handle for logging
 * \param drive Partition to mount
 * \return PAM_SUCCESS on success
 */
int pam_sed_try_mount(pam_handle_t *handle, const mount_line_t &drive);

/**
 * \brief Try to unmount a partition
 * \param handle PAM handle for logging
 * \param drive Partition to unmount
 * \return PAM_SUCCESS on success
 */
int pam_sed_try_umount(pam_handle_t *handle, const mount_line_t &drive);

/**
 * \brief Check `/proc/mounts` if a mountpoint is already used
 * \param handle PAM handle for logging
 * \param drive Partition to check
 * \return 1 if mountpoint is already used
 */
int pam_sed_is_mounted(pam_handle_t *handle, const mount_line_t &drive);

#endif //PAM_SED_LIBRARY_H
