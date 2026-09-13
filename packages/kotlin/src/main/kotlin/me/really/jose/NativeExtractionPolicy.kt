// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//

package me.really.jose

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.util.EnumSet
import java.util.Locale

internal object NativeExtractionPolicy {
    private const val POSIX_GROUP_WRITE: Int = 0x10
    private const val POSIX_OTHER_WRITE: Int = 0x02
    private const val POSIX_STICKY: Int = 0x200
    private val trustedWindowsSidPattern: Regex =
        Regex("(?:^|[^0-9])(?:s-1-5-18|s-1-5-32-544)(?:$|[^0-9])")

    internal fun createPrivateExtractionDirectory(
        configuredRoot: String? = System.getProperty("java.io.tmpdir"),
    ): Path? {
        return try {
            val rootValue = configuredRoot ?: return null
            val root = Path.of(rootValue).toRealPath(LinkOption.NOFOLLOW_LINKS)
            if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                return null
            }
            val posixView = Files.getFileAttributeView(
                root,
                PosixFileAttributeView::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            if (posixView != null) {
                val attributes = posixView.readAttributes()
                val mode = Files.getAttribute(
                    root,
                    "unix:mode",
                    LinkOption.NOFOLLOW_LINKS,
                ) as? Int ?: return null
                val currentUser = System.getProperty("user.name") ?: return null
                if (
                    !isSecurePosixTempMode(mode) ||
                    !isTrustedPosixTempOwner(attributes.owner().name, currentUser)
                ) {
                    return null
                }
                Files.createTempDirectory(
                    root,
                    "reallyme-jose-native-",
                    PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rwx------"),
                    ),
                )
            } else {
                val aclView = Files.getFileAttributeView(
                    root,
                    AclFileAttributeView::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ) ?: return null
                val currentUser = System.getProperty("user.name") ?: return null
                if (!isSecureAclTempRoot(aclView, currentUser)) {
                    return null
                }
                val directory = Files.createTempDirectory(root, "reallyme-jose-native-")
                if (!restrictAclToOwner(directory, writable = true)) {
                    deleteExtractionFiles(directory.resolve("unused"), directory)
                    return null
                }
                directory
            }
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        }
    }

    internal fun isSecurePosixTempMode(mode: Int): Boolean {
        val writableByAnotherPrincipal =
            mode and (POSIX_GROUP_WRITE or POSIX_OTHER_WRITE) != 0
        return !writableByAnotherPrincipal || mode and POSIX_STICKY != 0
    }

    internal fun isTrustedPosixTempOwner(owner: String, currentUser: String): Boolean =
        owner == currentUser || owner == "root" || owner == "0"

    private fun isSecureAclTempRoot(
        view: AclFileAttributeView,
        currentUser: String,
    ): Boolean {
        val owner = view.owner
        if (!isTrustedAclPrincipal(owner.name, currentUser, owner.toString())) {
            return false
        }
        val mutatingPermissions = EnumSet.of(
            AclEntryPermission.ADD_FILE,
            AclEntryPermission.ADD_SUBDIRECTORY,
            AclEntryPermission.APPEND_DATA,
            AclEntryPermission.DELETE,
            AclEntryPermission.DELETE_CHILD,
            AclEntryPermission.WRITE_ACL,
            AclEntryPermission.WRITE_ATTRIBUTES,
            AclEntryPermission.WRITE_DATA,
            AclEntryPermission.WRITE_NAMED_ATTRS,
            AclEntryPermission.WRITE_OWNER,
        )
        return view.acl.none { entry ->
            entry.type() == AclEntryType.ALLOW &&
                !isTrustedAclPrincipal(
                    entry.principal().name,
                    currentUser,
                    entry.principal().toString(),
                ) &&
                entry.permissions().any { it in mutatingPermissions }
        }
    }

    internal fun isTrustedAclPrincipal(
        principal: String,
        currentUser: String,
        description: String = principal,
    ): Boolean {
        val normalizedPrincipal = principal.lowercase(Locale.ROOT)
        val normalizedUser = currentUser.lowercase(Locale.ROOT)
        val normalizedDescription = description.lowercase(Locale.ROOT)
        return normalizedPrincipal == normalizedUser ||
            normalizedPrincipal.endsWith("\\$normalizedUser") ||
            normalizedPrincipal == "builtin\\administrators" ||
            normalizedPrincipal == "nt authority\\system" ||
            trustedWindowsSidPattern.containsMatchIn(normalizedDescription)
    }

    internal fun restrictAclToOwner(path: Path, writable: Boolean): Boolean {
        return try {
            val view = Files.getFileAttributeView(
                path,
                AclFileAttributeView::class.java,
                LinkOption.NOFOLLOW_LINKS,
            ) ?: return false
            val permissions = if (writable) {
                EnumSet.allOf(AclEntryPermission::class.java)
            } else {
                EnumSet.of(
                    AclEntryPermission.EXECUTE,
                    AclEntryPermission.READ_ACL,
                    AclEntryPermission.READ_ATTRIBUTES,
                    AclEntryPermission.READ_DATA,
                    AclEntryPermission.READ_NAMED_ATTRS,
                    AclEntryPermission.SYNCHRONIZE,
                )
            }
            val ownerEntry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(view.owner)
                .setPermissions(permissions)
                .build()
            view.acl = listOf(ownerEntry)
            true
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    internal fun deleteExtractionFiles(target: Path, directory: Path) {
        try {
            Files.deleteIfExists(target)
        } catch (_: IOException) {
            // Cleanup is best effort; a failed extraction is never loaded.
        } catch (_: SecurityException) {
            // Cleanup is best effort; a failed extraction is never loaded.
        }
        try {
            Files.deleteIfExists(directory)
        } catch (_: IOException) {
            // Cleanup is best effort; a failed extraction is never loaded.
        } catch (_: SecurityException) {
            // Cleanup is best effort; a failed extraction is never loaded.
        }
    }
}
