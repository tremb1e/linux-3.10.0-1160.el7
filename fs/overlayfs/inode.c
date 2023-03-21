/*
 *
 * Copyright (C) 2011 Novell Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/cred.h>
#include <linux/posix_acl.h>
#include <linux/ratelimit.h>
#include "overlayfs.h"


int ovl_setattr(struct dentry *dentry, struct iattr *attr)
{
	int err;
	struct dentry *upperdentry;
	const struct cred *old_cred;

	/*
	 * Check for permissions before trying to copy-up.  This is redundant
	 * since it will be rechecked later by ->setattr() on upper dentry.  But
	 * without this, copy-up can be triggered by just about anybody.
	 *
	 * We don't initialize inode->size, which just means that
	 * inode_newsize_ok() will always check against MAX_LFS_FILESIZE and not
	 * check for a swapfile (which this won't be anyway).
	 */
	err = inode_change_ok(dentry->d_inode, attr);
	if (err)
		return err;

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	err = ovl_copy_up(dentry);
	if (!err) {
		upperdentry = ovl_dentry_upper(dentry);

		if (attr->ia_valid & (ATTR_KILL_SUID|ATTR_KILL_SGID))
			attr->ia_valid &= ~ATTR_MODE;

		inode_lock(upperdentry->d_inode);
		old_cred = ovl_override_creds(dentry->d_sb);
		err = notify_change(upperdentry, attr, NULL);
		revert_creds(old_cred);
		if (!err)
			ovl_copyattr(upperdentry->d_inode, dentry->d_inode);
		inode_unlock(upperdentry->d_inode);
	}
	ovl_drop_write(dentry);
out:
	return err;
}

static int ovl_map_dev_ino(struct dentry *dentry, struct kstat *stat,
			   struct ovl_layer *lower_layer)
{
	bool samefs = ovl_same_sb(dentry->d_sb);
	unsigned int xinobits = ovl_xino_bits(dentry->d_sb);

	if (samefs) {
		/*
		 * When all layers are on the same fs, all real inode
		 * number are unique, so we use the overlay st_dev,
		 * which is friendly to du -x.
		 */
		stat->dev = dentry->d_sb->s_dev;
		return 0;
	} else if (xinobits) {
		unsigned int shift = 64 - xinobits;
		/*
		 * All inode numbers of underlying fs should not be using the
		 * high xinobits, so we use high xinobits to partition the
		 * overlay st_ino address space. The high bits holds the fsid
		 * (upper fsid is 0). This way overlay inode numbers are unique
		 * and all inodes use overlay st_dev. Inode numbers are also
		 * persistent for a given layer configuration.
		 */
		if (stat->ino >> shift) {
			pr_warn_ratelimited("overlayfs: inode number too big (%pd2, ino=%llu, xinobits=%d)\n",
					    dentry, stat->ino, xinobits);
		} else {
			if (lower_layer)
				stat->ino |= ((u64)lower_layer->fsid) << shift;

			stat->dev = dentry->d_sb->s_dev;
			return 0;
		}
	}

	/* The inode could not be mapped to a unified st_ino address space */
	if (S_ISDIR(dentry->d_inode->i_mode)) {
		/*
		 * Always use the overlay st_dev for directories, so 'find
		 * -xdev' will scan the entire overlay mount and won't cross the
		 * overlay mount boundaries.
		 *
		 * If not all layers are on the same fs the pair {real st_ino;
		 * overlay st_dev} is not unique, so use the non persistent
		 * overlay st_ino for directories.
		 */
		stat->dev = dentry->d_sb->s_dev;
		stat->ino = dentry->d_inode->i_ino;
	} else if (lower_layer && lower_layer->fsid) {
		/*
		 * For non-samefs setup, if we cannot map all layers st_ino
		 * to a unified address space, we need to make sure that st_dev
		 * is unique per lower fs. Upper layer uses real st_dev and
		 * lower layers use the unique anonymous bdev assigned to the
		 * lower fs.
		 */
		stat->dev = lower_layer->fs->pseudo_dev;
	}

	return 0;
}

int ovl_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	enum ovl_path_type type;
	struct path realpath;
	const struct cred *old_cred;
	bool is_dir = S_ISDIR(dentry->d_inode->i_mode);
	bool samefs = ovl_same_sb(dentry->d_sb);
	struct ovl_layer *lower_layer = NULL;
	int err;

	type = ovl_path_real(dentry, &realpath);
	old_cred = ovl_override_creds(dentry->d_sb);
	err = vfs_getattr(&realpath, stat);
	if (err)
		goto out;

	/*
	 * For non-dir or same fs, we use st_ino of the copy up origin.
	 * This guaranties constant st_dev/st_ino across copy up.
	 * With xino feature and non-samefs, we use st_ino of the copy up
	 * origin masked with high bits that represent the layer id.
	 *
	 * If lower filesystem supports NFS file handles, this also guaranties
	 * persistent st_ino across mount cycle.
	 */
	if (!is_dir || samefs || ovl_xino_bits(dentry->d_sb)) {
		if (!OVL_TYPE_UPPER(type)) {
			lower_layer = ovl_layer_lower(dentry);
		} else if (OVL_TYPE_ORIGIN(type)) {
			struct kstat lowerstat;

			ovl_path_lower(dentry, &realpath);
			err = vfs_getattr(&realpath, &lowerstat);
			if (err)
				goto out;

			/*
			 * Lower hardlinks may be broken on copy up to different
			 * upper files, so we cannot use the lower origin st_ino
			 * for those different files, even for the same fs case.
			 *
			 * Similarly, several redirected dirs can point to the
			 * same dir on a lower layer. With the "verify_lower"
			 * feature, we do not use the lower origin st_ino, if
			 * we haven't verified that this redirect is unique.
			 *
			 * With inodes index enabled, it is safe to use st_ino
			 * of an indexed origin. The index validates that the
			 * upper hardlink is not broken and that a redirected
			 * dir is the only redirect to that origin.
			 */
			if (ovl_test_flag(OVL_INDEX, d_inode(dentry)) ||
			    (!ovl_verify_lower(dentry->d_sb) &&
			     (is_dir || lowerstat.nlink == 1))) {
				stat->ino = lowerstat.ino;
				lower_layer = ovl_layer_lower(dentry);
			}
		}
	}

	err = ovl_map_dev_ino(dentry, stat, lower_layer);
	if (err)
		goto out;

	/*
	 * It's probably not worth it to count subdirs to get the
	 * correct link count.  nlink=1 seems to pacify 'find' and
	 * other utilities.
	 */
	if (is_dir && OVL_TYPE_MERGE(type))
		stat->nlink = 1;

	/*
	 * Return the overlay inode nlinks for indexed upper inodes.
	 * Overlay inode nlink counts the union of the upper hardlinks
	 * and non-covered lower hardlinks. It does not include the upper
	 * index hardlink.
	 */
	if (!is_dir && ovl_test_flag(OVL_INDEX, d_inode(dentry)))
		stat->nlink = dentry->d_inode->i_nlink;

out:
	revert_creds(old_cred);

	return err;
}

int ovl_permission(struct inode *inode, int mask)
{
	struct inode *upperinode = ovl_inode_upper(inode);
	struct inode *realinode = upperinode ?: ovl_inode_lower(inode);
	const struct cred *old_cred;
	int err;

	/* Careful in RCU walk mode */
	if (!realinode) {
		WARN_ON(!(mask & MAY_NOT_BLOCK));
		return -ECHILD;
	}

	/*
	 * Check overlay inode with the creds of task and underlying inode
	 * with creds of mounter
	 */
	err = generic_permission(inode, mask);
	if (err)
		return err;

	old_cred = ovl_override_creds(inode->i_sb);
	if (!upperinode &&
	    !special_file(realinode->i_mode) && mask & MAY_WRITE) {
		mask &= ~(MAY_WRITE | MAY_APPEND);
		/* Make sure mounter can read file for copy up later */
		mask |= MAY_READ;
	}
	err = inode_permission(realinode, mask);
	revert_creds(old_cred);

	return err;
}


struct ovl_link_data {
	struct dentry *realdentry;
	void *cookie;
};

static void *ovl_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	void *ret;
	struct dentry *realdentry;
	struct inode *realinode;
	struct ovl_link_data *data = NULL;
	const struct cred *old_cred;

	realdentry = ovl_dentry_real(dentry);
	realinode = realdentry->d_inode;

	if (WARN_ON(!realinode->i_op->follow_link))
		return ERR_PTR(-EPERM);

	if (realinode->i_op->put_link) {
		data = kmalloc(sizeof(struct ovl_link_data), GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		data->realdentry = realdentry;
	}

	old_cred = ovl_override_creds(dentry->d_sb);
	ret = realinode->i_op->follow_link(realdentry, nd);
	revert_creds(old_cred);
	if (IS_ERR(ret)) {
		kfree(data);
		return ret;
	}

	if (data)
		data->cookie = ret;

	return data;
}

static void ovl_put_link(struct dentry *dentry, struct nameidata *nd, void *c)
{
	struct inode *realinode;
	struct ovl_link_data *data = c;

	if (!data)
		return;

	realinode = data->realdentry->d_inode;
	realinode->i_op->put_link(data->realdentry, nd, data->cookie);
	kfree(data);
}

bool ovl_is_private_xattr(const char *name)
{
	return strncmp(name, OVL_XATTR_PREFIX,
		       sizeof(OVL_XATTR_PREFIX) - 1) == 0;
}

int ovl_xattr_set(struct dentry *dentry, struct inode *inode, const char *name,
		  const void *value, size_t size, int flags)
{
	int err;
	struct dentry *upperdentry = ovl_i_dentry_upper(inode);
	struct dentry *realdentry = upperdentry ?: ovl_dentry_lower(dentry);
	const struct cred *old_cred;

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	if (!value && !upperdentry) {
		err = vfs_getxattr(realdentry, name, NULL, 0);
		if (err < 0)
			goto out_drop_write;
	}

	if (!upperdentry) {
		err = ovl_copy_up(dentry);
		if (err)
			goto out_drop_write;

		realdentry = ovl_dentry_upper(dentry);
	}

	old_cred = ovl_override_creds(dentry->d_sb);
	if (value)
		err = vfs_setxattr(realdentry, name, value, size, flags);
	else {
		WARN_ON(flags != XATTR_REPLACE);
		err = vfs_removexattr(realdentry, name);
	}
	revert_creds(old_cred);

out_drop_write:
	ovl_drop_write(dentry);
out:
	return err;
}

int ovl_xattr_get(struct dentry *dentry, struct inode *inode, const char *name,
		  void *value, size_t size)
{
	ssize_t res;
	const struct cred *old_cred;
	struct dentry *realdentry =
		ovl_i_dentry_upper(inode) ?: ovl_dentry_lower(dentry);

	old_cred = ovl_override_creds(dentry->d_sb);
	res = vfs_getxattr(realdentry, name, value, size);
	revert_creds(old_cred);
	return res;
}

static bool ovl_can_list(const char *s)
{
	/* List all non-trusted xatts */
	if (strncmp(s, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN) != 0)
		return true;

	/* Never list trusted.overlay, list other trusted for superuser only */
	return !ovl_is_private_xattr(s) && capable(CAP_SYS_ADMIN);
}

ssize_t ovl_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct dentry *realdentry = ovl_dentry_real(dentry);
	ssize_t res;
	size_t len;
	char *s;
	const struct cred *old_cred;

	old_cred = ovl_override_creds(dentry->d_sb);
	res = vfs_listxattr(realdentry, list, size);
	revert_creds(old_cred);
	if (res <= 0 || size == 0)
		return res;

	/* filter out private xattrs */
	for (s = list, len = res; len;) {
		size_t slen = strnlen(s, len) + 1;

		/* underlying fs providing us with an broken xattr list? */
		if (WARN_ON(slen > len))
			return -EIO;

		len -= slen;
		if (!ovl_can_list(s)) {
			res -= slen;
			memmove(s, s + slen, len);
		} else {
			s += slen;
		}
	}

	return res;
}

struct posix_acl *ovl_get_acl(struct inode *inode, int type)
{
	struct inode *realinode = ovl_inode_real(inode);
	const struct cred *old_cred;
	struct posix_acl *acl;

	if (!IS_ENABLED(CONFIG_FS_POSIX_ACL) || !IS_POSIXACL(realinode))
		return NULL;

	old_cred = ovl_override_creds(inode->i_sb);
	acl = get_acl(realinode, type);
	revert_creds(old_cred);

	return acl;
}

static bool ovl_open_need_copy_up(struct dentry *dentry, int flags)
{
	/* Copy up of disconnected dentry does not set upper alias */
	if (ovl_dentry_upper(dentry) &&
	    (ovl_dentry_has_upper_alias(dentry) ||
	     (dentry->d_flags & DCACHE_DISCONNECTED)))
		return false;

	if (special_file(d_inode(dentry)->i_mode))
		return false;

	if (!(OPEN_FMODE(flags) & FMODE_WRITE) && !(flags & O_TRUNC))
		return false;

	return true;
}

int ovl_open_maybe_copy_up(struct dentry *dentry, unsigned int file_flags)
{
	int err = 0;

	if (ovl_open_need_copy_up(dentry, file_flags)) {
		err = ovl_want_write(dentry);
		if (!err) {
			err = ovl_copy_up_flags(dentry, file_flags);
			ovl_drop_write(dentry);
		}
	}

	return err;
}

int ovl_update_time(struct inode *inode, struct timespec *ts, int flags)
{
	if (flags & S_ATIME) {
		struct ovl_fs *ofs = inode->i_sb->s_fs_info;
		struct path upperpath = {
			.mnt = ofs->upper_mnt,
			.dentry = ovl_upperdentry_dereference(OVL_I(inode)),
		};

		if (upperpath.dentry) {
			touch_atime(&upperpath);
			inode->i_atime = d_inode(upperpath.dentry)->i_atime;
		}
	}
	return 0;
}

static const struct inode_operations_wrapper ovl_file_inode_operations = {
	.ops = {
	.setattr	= ovl_setattr,
	.permission	= ovl_permission,
	.getattr	= ovl_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ovl_listxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= ovl_get_acl,
	.update_time	= ovl_update_time,
	},
};

static const struct inode_operations ovl_symlink_inode_operations = {
	.setattr	= ovl_setattr,
	.follow_link	= ovl_follow_link,
	.put_link	= ovl_put_link,
	.readlink	= generic_readlink,
	.getattr	= ovl_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ovl_listxattr,
	.removexattr	= generic_removexattr,
	.update_time	= ovl_update_time,
};

/*
 * It is possible to stack overlayfs instance on top of another
 * overlayfs instance as lower layer. We need to annonate the
 * stackable i_mutex locks according to stack level of the super
 * block instance. An overlayfs instance can never be in stack
 * depth 0 (there is always a real fs below it).  An overlayfs
 * inode lock will use the lockdep annotaion ovl_i_mutex_key[depth].
 *
 * For example, here is a snip from /proc/lockdep_chains after
 * dir_iterate of nested overlayfs:
 *
 * [...] &ovl_i_mutex_dir_key[depth]   (stack_depth=2)
 * [...] &ovl_i_mutex_dir_key[depth]#2 (stack_depth=1)
 * [...] &type->i_mutex_dir_key        (stack_depth=0)
 */
#define OVL_MAX_NESTING FILESYSTEM_MAX_STACK_DEPTH

static inline void ovl_lockdep_annotate_inode_mutex_key(struct inode *inode)
{
#ifdef CONFIG_LOCKDEP
	static struct lock_class_key ovl_i_mutex_key[OVL_MAX_NESTING];
	static struct lock_class_key ovl_i_mutex_dir_key[OVL_MAX_NESTING];
	static struct lock_class_key ovl_i_lock_key[OVL_MAX_NESTING];

	int depth = *get_s_stack_depth(inode->i_sb) - 1;

	if (WARN_ON_ONCE(depth < 0 || depth >= OVL_MAX_NESTING))
		depth = 0;

	if (S_ISDIR(inode->i_mode))
		lockdep_set_class(&inode->i_mutex, &ovl_i_mutex_dir_key[depth]);
	else
		lockdep_set_class(&inode->i_mutex, &ovl_i_mutex_key[depth]);

	lockdep_set_class(&OVL_I(inode)->lock, &ovl_i_lock_key[depth]);
#endif
}

static void ovl_fill_inode(struct inode *inode, umode_t mode, dev_t rdev,
			   unsigned long ino, int fsid)
{
	int xinobits = ovl_xino_bits(inode->i_sb);

	/*
	 * When NFS export is enabled and d_ino is consistent with st_ino
	 * (samefs or i_ino has enough bits to encode layer), set the same
	 * value used for d_ino to i_ino, because nfsd readdirplus compares
	 * d_ino values to i_ino values of child entries. When called from
	 * ovl_new_inode(), ino arg is 0, so i_ino will be updated to real
	 * upper inode i_ino on ovl_inode_init() or ovl_inode_update().
	 */
	if (inode->i_sb->s_export_op &&
	    (ovl_same_sb(inode->i_sb) || xinobits)) {
		inode->i_ino = ino;
		if (xinobits && fsid && !(ino >> (64 - xinobits)))
			inode->i_ino |= (unsigned long)fsid << (64 - xinobits);
	} else {
		inode->i_ino = get_next_ino();
	}
	inode->i_mode = mode;
	inode->i_flags |= S_NOCMTIME;

	ovl_lockdep_annotate_inode_mutex_key(inode);

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &ovl_file_inode_operations.ops;
		inode->i_flags |= S_IOPS_WRAPPER;
		break;

	case S_IFDIR:
		inode->i_op = &ovl_dir_inode_operations.ops;
		inode->i_fop = &ovl_dir_operations;
		inode->i_flags |= S_IOPS_WRAPPER;
		break;

	case S_IFLNK:
		inode->i_op = &ovl_symlink_inode_operations;
		break;

	default:
		inode->i_op = &ovl_file_inode_operations.ops;
		inode->i_flags |= S_IOPS_WRAPPER;
		init_special_inode(inode, mode, rdev);
		break;
	}
}

/*
 * With inodes index enabled, an overlay inode nlink counts the union of upper
 * hardlinks and non-covered lower hardlinks. During the lifetime of a non-pure
 * upper inode, the following nlink modifying operations can happen:
 *
 * 1. Lower hardlink copy up
 * 2. Upper hardlink created, unlinked or renamed over
 * 3. Lower hardlink whiteout or renamed over
 *
 * For the first, copy up case, the union nlink does not change, whether the
 * operation succeeds or fails, but the upper inode nlink may change.
 * Therefore, before copy up, we store the union nlink value relative to the
 * lower inode nlink in the index inode xattr trusted.overlay.nlink.
 *
 * For the second, upper hardlink case, the union nlink should be incremented
 * or decremented IFF the operation succeeds, aligned with nlink change of the
 * upper inode. Therefore, before link/unlink/rename, we store the union nlink
 * value relative to the upper inode nlink in the index inode.
 *
 * For the last, lower cover up case, we simplify things by preceding the
 * whiteout or cover up with copy up. This makes sure that there is an index
 * upper inode where the nlink xattr can be stored before the copied up upper
 * entry is unlink.
 */
#define OVL_NLINK_ADD_UPPER	(1 << 0)

/*
 * On-disk format for indexed nlink:
 *
 * nlink relative to the upper inode - "U[+-]NUM"
 * nlink relative to the lower inode - "L[+-]NUM"
 */

static int ovl_set_nlink_common(struct dentry *dentry,
				struct dentry *realdentry, const char *format)
{
	struct inode *inode = d_inode(dentry);
	struct inode *realinode = d_inode(realdentry);
	char buf[13];
	int len;

	len = snprintf(buf, sizeof(buf), format,
		       (int) (inode->i_nlink - realinode->i_nlink));

	if (WARN_ON(len >= sizeof(buf)))
		return -EIO;

	return ovl_do_setxattr(ovl_dentry_upper(dentry),
			       OVL_XATTR_NLINK, buf, len, 0);
}

int ovl_set_nlink_upper(struct dentry *dentry)
{
	return ovl_set_nlink_common(dentry, ovl_dentry_upper(dentry), "U%+i");
}

int ovl_set_nlink_lower(struct dentry *dentry)
{
	return ovl_set_nlink_common(dentry, ovl_dentry_lower(dentry), "L%+i");
}

unsigned int ovl_get_nlink(struct dentry *lowerdentry,
			   struct dentry *upperdentry,
			   unsigned int fallback)
{
	int nlink_diff;
	int nlink;
	char buf[13];
	int err;

	if (!lowerdentry || !upperdentry || d_inode(lowerdentry)->i_nlink == 1)
		return fallback;

	err = vfs_getxattr(upperdentry, OVL_XATTR_NLINK, &buf, sizeof(buf) - 1);
	if (err < 0)
		goto fail;

	buf[err] = '\0';
	if ((buf[0] != 'L' && buf[0] != 'U') ||
	    (buf[1] != '+' && buf[1] != '-'))
		goto fail;

	err = kstrtoint(buf + 1, 10, &nlink_diff);
	if (err < 0)
		goto fail;

	nlink = d_inode(buf[0] == 'L' ? lowerdentry : upperdentry)->i_nlink;
	nlink += nlink_diff;

	if (nlink <= 0)
		goto fail;

	return nlink;

fail:
	pr_warn_ratelimited("overlayfs: failed to get index nlink (%pd2, err=%i)\n",
			    upperdentry, err);
	return fallback;
}

struct inode *ovl_new_inode(struct super_block *sb, umode_t mode, dev_t rdev)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (inode)
		ovl_fill_inode(inode, mode, rdev, 0, 0);

	return inode;
}

static int ovl_inode_test(struct inode *inode, void *data)
{
	return inode->i_private == data;
}

static int ovl_inode_set(struct inode *inode, void *data)
{
	inode->i_private = data;
	return 0;
}

static bool ovl_verify_inode(struct inode *inode, struct dentry *lowerdentry,
			     struct dentry *upperdentry, bool strict)
{
	/*
	 * For directories, @strict verify from lookup path performs consistency
	 * checks, so NULL lower/upper in dentry must match NULL lower/upper in
	 * inode. Non @strict verify from NFS handle decode path passes NULL for
	 * 'unknown' lower/upper.
	 */
	if (S_ISDIR(inode->i_mode) && strict) {
		/* Real lower dir moved to upper layer under us? */
		if (!lowerdentry && ovl_inode_lower(inode))
			return false;

		/* Lookup of an uncovered redirect origin? */
		if (!upperdentry && ovl_inode_upper(inode))
			return false;
	}

	/*
	 * Allow non-NULL lower inode in ovl_inode even if lowerdentry is NULL.
	 * This happens when finding a copied up overlay inode for a renamed
	 * or hardlinked overlay dentry and lower dentry cannot be followed
	 * by origin because lower fs does not support file handles.
	 */
	if (lowerdentry && ovl_inode_lower(inode) != d_inode(lowerdentry))
		return false;

	/*
	 * Allow non-NULL __upperdentry in inode even if upperdentry is NULL.
	 * This happens when finding a lower alias for a copied up hard link.
	 */
	if (upperdentry && ovl_inode_upper(inode) != d_inode(upperdentry))
		return false;

	return true;
}

struct inode *ovl_lookup_inode(struct super_block *sb, struct dentry *real,
			       bool is_upper)
{
	struct inode *inode, *key = d_inode(real);

	inode = ilookup5(sb, (unsigned long) key, ovl_inode_test, key);
	if (!inode)
		return NULL;

	if (!ovl_verify_inode(inode, is_upper ? NULL : real,
			      is_upper ? real : NULL, false)) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

/*
 * Does overlay inode need to be hashed by lower inode?
 */
static bool ovl_hash_bylower(struct super_block *sb, struct dentry *upper,
			     struct dentry *lower, struct dentry *index)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	/* No, if pure upper */
	if (!lower)
		return false;

	/* Yes, if already indexed */
	if (index)
		return true;

	/* Yes, if won't be copied up */
	if (!ofs->upper_mnt)
		return true;

	/* No, if lower hardlink is or will be broken on copy up */
	if ((upper || !ovl_indexdir(sb)) &&
	    !d_is_dir(lower) && d_inode(lower)->i_nlink > 1)
		return false;

	/* No, if non-indexed upper with NFS export */
	if (sb->s_export_op && upper)
		return false;

	/* Otherwise, hash by lower inode for fsnotify */
	return true;
}

static struct inode *ovl_iget5(struct super_block *sb, struct inode *newinode,
			       struct inode *key)
{
	return newinode ? inode_insert5(newinode, (unsigned long) key,
					 ovl_inode_test, ovl_inode_set, key) :
			  iget5_locked(sb, (unsigned long) key,
				       ovl_inode_test, ovl_inode_set, key);
}

struct inode *ovl_get_inode(struct super_block *sb,
			    struct ovl_inode_params *oip)
{
	struct dentry *upperdentry = oip->upperdentry;
	struct ovl_path *lowerpath = oip->lowerpath;
	struct inode *realinode = upperdentry ? d_inode(upperdentry) : NULL;
	struct inode *inode;
	struct dentry *lowerdentry = lowerpath ? lowerpath->dentry : NULL;
	bool bylower = ovl_hash_bylower(sb, upperdentry, lowerdentry,
					oip->index);
	int fsid = bylower ? oip->lowerpath->layer->fsid : 0;
	bool is_dir;
	unsigned long ino = 0;

	if (!realinode)
		realinode = d_inode(lowerdentry);

	/*
	 * Copy up origin (lower) may exist for non-indexed upper, but we must
	 * not use lower as hash key if this is a broken hardlink.
	 */
	is_dir = S_ISDIR(realinode->i_mode);
	if (upperdentry || bylower) {
		struct inode *key = d_inode(bylower ? lowerdentry :
						      upperdentry);
		unsigned int nlink = is_dir ? 1 : realinode->i_nlink;

		inode = ovl_iget5(sb, oip->newinode, key);
		if (!inode)
			goto out_nomem;
		if (!(inode->i_state & I_NEW)) {
			/*
			 * Verify that the underlying files stored in the inode
			 * match those in the dentry.
			 */
			if (!ovl_verify_inode(inode, lowerdentry, upperdentry,
					      true)) {
				iput(inode);
				inode = ERR_PTR(-ESTALE);
				goto out;
			}

			dput(upperdentry);
			goto out;
		}

		/* Recalculate nlink for non-dir due to indexing */
		if (!is_dir)
			nlink = ovl_get_nlink(lowerdentry, upperdentry, nlink);
		set_nlink(inode, nlink);
		ino = key->i_ino;
	} else {
		/* Lower hardlink that will be broken on copy up */
		inode = new_inode(sb);
		if (!inode)
			goto out_nomem;
	}
	ovl_fill_inode(inode, realinode->i_mode, realinode->i_rdev, ino, fsid);
	ovl_inode_init(inode, upperdentry, lowerdentry);

	if (upperdentry && ovl_is_impuredir(upperdentry))
		ovl_set_flag(OVL_IMPURE, inode);

	if (oip->index)
		ovl_set_flag(OVL_INDEX, inode);

	/* Check for non-merge dir that may have whiteouts */
	if (is_dir) {
		if (((upperdentry && lowerdentry) || oip->numlower > 1) ||
		    ovl_check_origin_xattr(upperdentry ?: lowerdentry)) {
			ovl_set_flag(OVL_WHITEOUTS, inode);
		}
	}

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
out:
	return inode;

out_nomem:
	inode = ERR_PTR(-ENOMEM);
	goto out;
}
