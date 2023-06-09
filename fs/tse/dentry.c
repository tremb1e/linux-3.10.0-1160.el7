/**
 * Tse: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include "tse_kernel.h"

/**
 * tse_d_revalidate - revalidate an tse dentry
 * @dentry: The tse dentry
 * @flags: lookup flags
 *
 * Called when the VFS needs to revalidate a dentry. This
 * is called whenever a name lookup finds a dentry in the
 * dcache. Most filesystems leave this as NULL, because all their
 * dentries in the dcache are valid.
 *
 * Returns 1 if valid, 0 otherwise.
 *
 */
static int tse_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *lower_dentry;
	int rc = 1;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	lower_dentry = tse_dentry_to_lower(dentry);
	if (!lower_dentry->d_op || !lower_dentry->d_op->d_revalidate)
		goto out;
	rc = lower_dentry->d_op->d_revalidate(lower_dentry, flags);
	if (dentry->d_inode) {
		struct inode *lower_inode =
			tse_inode_to_lower(dentry->d_inode);

		fsstack_copy_attr_all(dentry->d_inode, lower_inode);
	}
out:
	return rc;
}

struct kmem_cache *tse_dentry_info_cache;

/**
 * tse_d_release
 * @dentry: The tse dentry
 *
 * Called when a dentry is really deallocated.
 */
static void tse_d_release(struct dentry *dentry)
{
	if (tse_dentry_to_private(dentry)) {
		if (tse_dentry_to_lower(dentry)) {
			dput(tse_dentry_to_lower(dentry));
			mntput(tse_dentry_to_lower_mnt(dentry));
		}
		kmem_cache_free(tse_dentry_info_cache,
				tse_dentry_to_private(dentry));
	}
	return;
}

const struct dentry_operations tse_dops = {
	.d_revalidate = tse_d_revalidate,
	.d_release = tse_d_release,
};
