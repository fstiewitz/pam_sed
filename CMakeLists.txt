cmake_minimum_required(VERSION 3.13)
project(pam_sed)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_SHARED_LIBRARY_PREFIX "")

add_library(pam_sed SHARED library.cpp library.h
        sedutil/Common/DtaAnnotatedDump.cpp
        sedutil/Common/DtaAnnotatedDump.h
        sedutil/Common/DtaCommand.cpp
        sedutil/Common/DtaCommand.h
        sedutil/Common/DtaDev.cpp
        sedutil/Common/DtaDev.h
        sedutil/Common/DtaDevEnterprise.cpp
        sedutil/Common/DtaDevEnterprise.h
        sedutil/Common/DtaDevGeneric.cpp
        sedutil/Common/DtaDevGeneric.h
        sedutil/Common/DtaDevOpal1.cpp
        sedutil/Common/DtaDevOpal1.h
        sedutil/Common/DtaDevOpal2.cpp
        sedutil/Common/DtaDevOpal2.h
        sedutil/Common/DtaDevOpal.cpp
        sedutil/Common/DtaDevOpal.h
        sedutil/Common/DtaDiskType.cpp
        sedutil/Common/DtaDiskType.h
        sedutil/Common/DtaHashPwd.cpp
        sedutil/Common/DtaHashPwd.h
        sedutil/Common/DtaHexDump.cpp
        sedutil/Common/DtaHexDump.h
        sedutil/Common/DtaResponse.cpp
        sedutil/Common/DtaResponse.h
        sedutil/Common/DtaSession.cpp
        sedutil/Common/DtaSession.h
        sedutil/Common/DtaStructures.h
        sedutil/Common/log.h
        sedutil/Common/DtaLexicon.h
        sedutil/Common/DtaConstants.h
        sedutil/Common/DtaEndianFixup.h
        sedutil/Common/pbkdf2/blockwise.c
        sedutil/Common/pbkdf2/blockwise.h
        sedutil/Common/pbkdf2/chash.c
        sedutil/Common/pbkdf2/chash.h
        sedutil/Common/pbkdf2/handy.h
        sedutil/Common/pbkdf2/hmac.c
        sedutil/Common/pbkdf2/hmac.h
        sedutil/Common/pbkdf2/pbkdf2.c
        sedutil/Common/pbkdf2/pbkdf2.h
        sedutil/Common/pbkdf2/sha1.c
        sedutil/Common/pbkdf2/sha1.h
        sedutil/Common/pbkdf2/tassert.h
        sedutil/Common/pbkdf2/bitops.h
        sedutil/linux/DtaDevLinuxNvme.cpp
        sedutil/linux/DtaDevLinuxNvme.h
        sedutil/linux/DtaDevLinuxSata.cpp
        sedutil/linux/DtaDevLinuxSata.h
        sedutil/linux/DtaDevOS.cpp
        sedutil/linux/DtaDevOS.h
        sedutil/linux/DtaDevLinuxDrive.h
        sedutil/linux/os.h)

target_include_directories(pam_sed PRIVATE sedutil/linux)
target_include_directories(pam_sed PRIVATE sedutil/Common)
target_include_directories(pam_sed PRIVATE sedutil/Common/pbkdf2)

