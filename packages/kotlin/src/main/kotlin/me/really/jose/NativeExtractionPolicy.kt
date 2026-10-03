// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.jose

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryFlag
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
    private val aclRootMutationPermissions: Set<AclEntryPermission> = EnumSet.of(
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
    private val aclAncestorReplacementPermissions: Set<AclEntryPermission> = EnumSet.of(
        AclEntryPermission.ADD_FILE,
        AclEntryPermission.DELETE,
        AclEntryPermission.DELETE_CHILD,
        AclEntryPermission.WRITE_ACL,
        AclEntryPermission.WRITE_ATTRIBUTES,
        AclEntryPermission.WRITE_DATA,
        AclEntryPermission.WRITE_NAMED_ATTRS,
        AclEntryPermission.WRITE_OWNER,
    )

    internal fun createPrivateExtractionDirectory(
        configuredRoot: String? = System.getProperty("java.io.tmpdir"),
    ): Path? {
        return try {
            val rootValue = configuredRoot ?: return null
            // Resolve every ancestor before checking permissions. NOFOLLOW_LINKS
            // only checks the final component and leaves a writable ancestor
            // available for replacement before the native library is loaded.
            val root = Path.of(rootValue).toRealPath()
            if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                return null
            }
            val posixView = Files.getFileAttributeView(
                root,
                PosixFileAttributeView::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            if (posixView != null) {
                val currentUser = System.getProperty("user.name") ?: return null
                if (!hasSecurePosixAncestors(root, currentUser)) {
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
                if (!hasSecureAclAncestors(root, currentUser)) {
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

    private fun hasSecurePosixAncestors(root: Path, currentUser: String): Boolean {
        var ancestor: Path? = root
        while (ancestor != null) {
            val view = Files.getFileAttributeView(
                ancestor,
                PosixFileAttributeView::class.java,
                LinkOption.NOFOLLOW_LINKS,
            ) ?: return false
            val mode = Files.getAttribute(
                ancestor,
                "unix:mode",
                LinkOption.NOFOLLOW_LINKS,
            ) as? Int ?: return false
            if (!Files.isDirectory(ancestor, LinkOption.NOFOLLOW_LINKS) ||
                !isSecurePosixTempMode(mode) ||
                !isTrustedPosixTempOwner(view.readAttributes().owner().name, currentUser)
            ) {
                return false
            }
            ancestor = ancestor.parent
        }
        return true
    }

    private fun hasSecureAclAncestors(root: Path, currentUser: String): Boolean {
        var ancestor: Path? = root
        var isExtractionRoot = true
        while (ancestor != null) {
            val view = Files.getFileAttributeView(
                ancestor,
                AclFileAttributeView::class.java,
                LinkOption.NOFOLLOW_LINKS,
            ) ?: return false
            if (!Files.isDirectory(ancestor, LinkOption.NOFOLLOW_LINKS) ||
                !isSecureAclDirectory(view, currentUser, isExtractionRoot)
            ) {
                return false
            }
            isExtractionRoot = false
            ancestor = ancestor.parent
        }
        return true
    }

    private fun isSecureAclDirectory(
        view: AclFileAttributeView,
        currentUser: String,
        isExtractionRoot: Boolean,
    ): Boolean {
        val owner = view.owner
        if (!isTrustedAclPrincipal(owner.name, currentUser, owner.toString())) {
            return false
        }
        // Windows commonly permits users to create siblings under a profile
        // ancestor. That cannot replace an existing protected path component.
        // The extraction root itself must forbid all untrusted creation because
        // its new child briefly inherits that root's ACL before restriction.
        return view.acl.none { entry ->
            isUntrustedAclMutation(entry, currentUser, isExtractionRoot)
        }
    }

    internal fun isUntrustedAclMutation(
        entry: AclEntry,
        currentUser: String,
        isExtractionRoot: Boolean,
    ): Boolean {
        if (entry.type() != AclEntryType.ALLOW || AclEntryFlag.INHERIT_ONLY in entry.flags()) {
            return false
        }
        if (isTrustedAclPrincipal(entry.principal().name, currentUser, entry.principal().toString())) {
            return false
        }
        val mutatingPermissions = if (isExtractionRoot) {
            aclRootMutationPermissions
        } else {
            aclAncestorReplacementPermissions
        }
        return entry.permissions().any { it in mutatingPermissions }
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
            normalizedPrincipal == "nt service\\trustedinstaller" ||
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
