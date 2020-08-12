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
#include "library.h"

#include <iostream>
#include <cstring>
#include <string>
#include <fstream>

#include <sys/mount.h>
#include <DtaLexicon.h>
#include <DtaDevGeneric.h>
#include <DtaDevOpal2.h>
#include <DtaDevOpal1.h>
#include <DtaDevEnterprise.h>

#include <security/pam_ext.h>
#include <syslog.h>

sedutiloutput outputFormat = sedutilNormal;

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    const char *pass;
    auto err = pam_get_item(pamh, PAM_USER, reinterpret_cast<const void **>(&user));
    if (err != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): %s\n", pam_strerror(pamh, err));
        return PAM_AUTH_ERR;
    }
    if (user == nullptr) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): no user specified\n");
        return PAM_AUTH_ERR;
    }

    err = pam_get_item(pamh, PAM_AUTHTOK, reinterpret_cast<const void **>(&pass));
    if (err != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): %s\n", pam_strerror(pamh, err));
        return PAM_AUTH_ERR;
    }
    if (pass == nullptr) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): no password specified\n");
        return PAM_AUTH_ERR;
    }

    return pam_sed_unlock(pamh, user, pass);
}

int pam_sm_setcred(pam_handle_t *, int, int, const char **) {
    return PAM_IGNORE;
}

int pam_sm_acct_mgmt(pam_handle_t *, int, int, const char **) {
    return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    auto err = pam_get_item(pamh, PAM_USER, reinterpret_cast<const void **>(&user));
    if (err != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): %s\n", pam_strerror(pamh, err));
        return PAM_AUTH_ERR;
    }
    if (user == nullptr) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): no user specified\n");
        return PAM_AUTH_ERR;
    }

    return pam_sed_mount(pamh, user);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
    const char *user;
    auto err = pam_get_item(pamh, PAM_USER, reinterpret_cast<const void **>(&user));
    if (err != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): %s\n", pam_strerror(pamh, err));
        return PAM_AUTH_ERR;
    }
    if (user == nullptr) {
        pam_syslog(pamh, LOG_NOTICE, "pam error (libpam_sed): no user specified\n");
        return PAM_AUTH_ERR;
    }

    return pam_sed_umount(pamh, user);
}

int pam_sm_chauthtok(pam_handle_t *, int, int, const char **) {
    return PAM_IGNORE;
}

int pam_sed_unlock(pam_handle_t *handle, const char *user, const char *password) {
    std::vector<drive_line_t> drives{};
    std::vector<mount_line_t> mounts{};

    auto err = pam_sed_read_config(drives, mounts);
    if (err != PAM_SUCCESS) return err;

    bool all_unlocked = true;
    for (const auto &mount : mounts) {
        if (strcmp(mount.user, user) == 0) {
            if (!pam_sed_is_mounted(handle, mount)) {
                all_unlocked = false;
                break;
            }
        }
    }

    if (all_unlocked) return PAM_SUCCESS;

    pam_syslog(handle, LOG_NOTICE, "unlocking SED drives\n");

    for (const auto &drive : drives) {
        if (strcmp(drive.user, user) == 0) {
            err = pam_sed_try_drive_unlock(handle, drive, password);
            if (err != PAM_SUCCESS) return err;
        }
    }

    return PAM_SUCCESS;
}

int pam_sed_mount(pam_handle_t *handle, const char *user) {
    std::vector<drive_line_t> drives{};
    std::vector<mount_line_t> mounts{};

    auto err = pam_sed_read_config(drives, mounts);
    if (err != PAM_SUCCESS) return err;

    for (const auto &mount : mounts) {
        if (strcmp(mount.user, user) == 0) {
            err = pam_sed_try_mount(handle, mount);
            if (err != PAM_SUCCESS) return err;
        }
    }

    return PAM_SUCCESS;
}

int pam_sed_umount(pam_handle_t *handle, const char *user) {
    std::vector<drive_line_t> drives{};
    std::vector<mount_line_t> mounts{};

    auto err = pam_sed_read_config(drives, mounts);
    if (err != PAM_SUCCESS) return err;

    for (const auto &mount : mounts) {
        if (strcmp(mount.user, user) == 0) {
            err = pam_sed_try_umount(handle, mount);
            if (err != PAM_SUCCESS) return err;
        }
    }

    return PAM_SUCCESS;
}

int pam_sed_read_config(std::vector<drive_line_t> &drives, std::vector<mount_line_t> &mounts) {
    std::ifstream ifd{SEDTAB, std::ios_base::in};
    if (!ifd.is_open()) {
        return PAM_AUTH_ERR;
    }

    for (std::string line; std::getline(ifd, line, '\n');) {
        if (memcmp(line.c_str(), "drive", 5) == 0) {
            drive_line_t drive{};
            if (sscanf(line.c_str() + 6, DRIVE_LINE_FORMAT, drive.user, drive.path) == 2) {
                drives.push_back(drive);
            }
        } else if (memcmp(line.c_str(), "mount", 5) == 0) {
            mount_line_t mount{};
            if (sscanf(line.c_str() + 6, MOUNT_LINE_FORMAT, mount.user, mount.drive, mount.path, mount.type) == 4) {
                mounts.push_back(mount);
            }
        }
    }

    return PAM_SUCCESS;
}

int pam_sed_try_drive_unlock(pam_handle_t *handle, const drive_line_t &drive, const char *password) {
    auto lockingOption = OPAL_LOCKINGSTATE::READWRITE;
    auto range = 0;

    DtaDev *d = nullptr;
    auto tempDev = new DtaDevGeneric(drive.path);
    if ((!tempDev->isPresent()) || (!tempDev->isAnySSC())) {
        pam_syslog(handle, LOG_NOTICE, "pam error (libpam_sed): Invalid or unsupported disk %s", drive.path);
        delete tempDev;
        return PAM_AUTH_ERR;
    }
    if (tempDev->isOpal2())
        d = new DtaDevOpal2(drive.path);
    else if (tempDev->isOpal1())
        d = new DtaDevOpal1(drive.path);
    else if (tempDev->isEprise())
        d = new DtaDevEnterprise(drive.path);
    else {
        delete tempDev;
        pam_syslog(handle, LOG_NOTICE, "pam error (libpam_sed): Unknown OPAL SSC");
        return PAM_AUTH_ERR;
    }
    delete tempDev;
    if (nullptr == d) {
        pam_syslog(handle, LOG_NOTICE, "pam error (libpam_sed): Create device object failed");
        return PAM_AUTH_ERR;
    }
    d->output_format = sedutilNormal;
    d->no_hash_passwords = false;

    if (!d->Locked()) {
        pam_syslog(handle, LOG_NOTICE, "sed already unlocked");
        delete d;
        return PAM_SUCCESS;
    }

    pam_syslog(handle, LOG_NOTICE, "unlocking sed %s", drive.path);
    auto err = d->setLockingRange(range, lockingOption, const_cast<char *>(password));
    if (err != 0) {
        delete d;
        pam_syslog(handle, LOG_NOTICE, "set locking range failed on device %s (ret %i)", drive.path, err);
        return PAM_AUTH_ERR;
    }

    err = d->setMBRDone(1, const_cast<char *>(password));
    if (err != 0) {
        delete d;
        pam_syslog(handle, LOG_NOTICE, "set mbr done failed on device %s (ret %i)", drive.path, err);
        return PAM_AUTH_ERR;
    }
    delete d;
#if SLEEP_AFTER_UNLOCK > 0
    sleep(SLEEP_AFTER_UNLOCK); // is there a better way?
#endif
    return PAM_SUCCESS;
}

int pam_sed_try_mount(pam_handle_t *handle, const mount_line_t &drive) {
    if (pam_sed_is_mounted(handle, drive)) {
        pam_syslog(handle, LOG_NOTICE, "sed already mounted");
        return PAM_SUCCESS;
    }
    if (mount(drive.drive, drive.path, drive.type, 0, nullptr)) {
        pam_syslog(handle, LOG_NOTICE, "error during mount: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    pam_syslog(handle, LOG_NOTICE, "libpam_sed: mounting drive\n");
    return PAM_SUCCESS;
}

int pam_sed_try_umount(pam_handle_t *handle, const mount_line_t &drive) {
    return PAM_IGNORE;
}

int pam_sed_is_mounted(pam_handle_t *handle, const mount_line_t &drive) {
    std::ifstream ifd{"/proc/mounts", std::ios_base::in};
    for (std::string line; std::getline(ifd, line, '\n');) {
        auto it = line.find(drive.path);
        if (it != std::string::npos && it > 0 && it < line.size() - 2) {
            if (isspace(line[it - 1])) {
                return 1;
            }
        }
    }
    return 0;
}
