/**
 * Tse: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *              Tyler Hicks <tyhicks@ou.edu>
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
#include <linux/file.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/skbuff.h>
#include <linux/crypto.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/parser.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include "tse_kernel.h"

/**
 * Module parameter that defines the tse_verbosity level.
 */
int tse_verbosity = 0;

module_param(tse_verbosity, int, 0);
MODULE_PARM_DESC(tse_verbosity,
		 "Initial verbosity level (0 or 1; defaults to "
		 "0, which is Quiet)");

/**
 * Module parameter that defines the number of message buffer elements
 */
unsigned int tse_message_buf_len = TSE_DEFAULT_MSG_CTX_ELEMS;

module_param(tse_message_buf_len, uint, 0);
MODULE_PARM_DESC(tse_message_buf_len,
		 "Number of message buffer elements");

/**
 * Module parameter that defines the maximum guaranteed amount of time to wait
 * for a response from tsed.  The actual sleep time will be, more than
 * likely, a small amount greater than this specified value, but only less if
 * the message successfully arrives.
 */
signed long tse_message_wait_timeout = TSE_MAX_MSG_CTX_TTL / HZ;

module_param(tse_message_wait_timeout, long, 0);
MODULE_PARM_DESC(tse_message_wait_timeout,
		 "Maximum number of seconds that an operation will "
		 "sleep while waiting for a message response from "
		 "userspace");

/**
 * Module parameter that is an estimate of the maximum number of users
 * that will be concurrently using Tse. Set this to the right
 * value to balance performance and memory use.
 */
unsigned int tse_number_of_users = TSE_DEFAULT_NUM_USERS;

module_param(tse_number_of_users, uint, 0);
MODULE_PARM_DESC(tse_number_of_users, "An estimate of the number of "
		 "concurrent users of Tse");

void __tse_printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (fmt[1] == '7') { /* KERN_DEBUG */
		if (tse_verbosity >= 1)
			vprintk(fmt, args);
	} else
		vprintk(fmt, args);
	va_end(args);
}

/**
 * tse_init_lower_file
 * @tse_dentry: Fully initialized Tse dentry object, with
 *                   the lower dentry and the lower mount set
 *
 * Tse only ever keeps a single open file for every lower
 * inode. All I/O operations to the lower inode occur through that
 * file. When the first Tse dentry that interposes with the first
 * lower dentry for that inode is created, this function creates the
 * lower file struct and associates it with the Tse
 * inode. When all Tse files associated with the inode are released, the
 * file is closed.
 *
 * The lower file will be opened with read/write permissions, if
 * possible. Otherwise, it is opened read-only.
 *
 * This function does nothing if a lower file is already
 * associated with the Tse inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int tse_init_lower_file(struct dentry *dentry,
				    struct file **lower_file)
{
	const struct cred *cred = current_cred();
	struct dentry *lower_dentry = tse_dentry_to_lower(dentry);
	struct vfsmount *lower_mnt = tse_dentry_to_lower_mnt(dentry);
	int rc;

	rc = tse_privileged_open(lower_file, lower_dentry, lower_mnt,
				      cred);
	if (rc) {
		printk(KERN_ERR "Error opening lower file "
		       "for lower_dentry [0x%p] and lower_mnt [0x%p]; "
		       "rc = [%d]\n", lower_dentry, lower_mnt, rc);
		(*lower_file) = NULL;
	}
	return rc;
}

int tse_get_lower_file(struct dentry *dentry, struct inode *inode)
{
	struct tse_inode_info *inode_info;
	int count, rc = 0;

	inode_info = tse_inode_to_private(inode);
	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_inc_return(&inode_info->lower_file_count);
	if (WARN_ON_ONCE(count < 1))
		rc = -EINVAL;
	else if (count == 1) {
		rc = tse_init_lower_file(dentry,
					      &inode_info->lower_file);
		if (rc)
			atomic_set(&inode_info->lower_file_count, 0);
	}
	mutex_unlock(&inode_info->lower_file_mutex);
	return rc;
}

void tse_put_lower_file(struct inode *inode)
{
	struct tse_inode_info *inode_info;

	inode_info = tse_inode_to_private(inode);
	if (atomic_dec_and_mutex_lock(&inode_info->lower_file_count,
				      &inode_info->lower_file_mutex)) {
		filemap_write_and_wait(inode->i_mapping);
		fput(inode_info->lower_file);
		inode_info->lower_file = NULL;
		mutex_unlock(&inode_info->lower_file_mutex);
	}
}

enum { tse_opt_sig, tse_opt_tse_sig,
       tse_opt_cipher, tse_opt_tse_cipher,
       tse_opt_tse_key_bytes,
       tse_opt_passthrough, tse_opt_xattr_metadata,
       tse_opt_encrypted_view, tse_opt_fnek_sig,
       tse_opt_fn_cipher, tse_opt_fn_cipher_key_bytes,
       tse_opt_unlink_sigs, tse_opt_mount_auth_tok_only,
       tse_opt_check_dev_ruid,
       tse_opt_err };

static const match_table_t tokens = {
	{tse_opt_sig, "sig=%s"},
	{tse_opt_tse_sig, "tse_sig=%s"},
	{tse_opt_cipher, "cipher=%s"},
	{tse_opt_tse_cipher, "tse_cipher=%s"},
	{tse_opt_tse_key_bytes, "tse_key_bytes=%u"},
	{tse_opt_passthrough, "tse_passthrough"},
	{tse_opt_xattr_metadata, "tse_xattr_metadata"},
	{tse_opt_encrypted_view, "tse_encrypted_view"},
	{tse_opt_fnek_sig, "tse_fnek_sig=%s"},
	{tse_opt_fn_cipher, "tse_fn_cipher=%s"},
	{tse_opt_fn_cipher_key_bytes, "tse_fn_key_bytes=%u"},
	{tse_opt_unlink_sigs, "tse_unlink_sigs"},
	{tse_opt_mount_auth_tok_only, "tse_mount_auth_tok_only"},
	{tse_opt_check_dev_ruid, "tse_check_dev_ruid"},
	{tse_opt_err, NULL}
};

static int tse_init_global_auth_toks(
	struct tse_mount_crypt_stat *mount_crypt_stat)
{
	struct tse_global_auth_tok *global_auth_tok;
	struct ecryptfs_auth_tok *auth_tok;
	int rc = 0;

	list_for_each_entry(global_auth_tok,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		rc = tse_keyring_auth_tok_for_sig(
			&global_auth_tok->global_auth_tok_key, &auth_tok,
			global_auth_tok->sig);
		if (rc) {
			printk(KERN_ERR "Could not find valid key in user "
			       "session keyring for sig specified in mount "
			       "option: [%s]\n", global_auth_tok->sig);
			global_auth_tok->flags |= TSE_AUTH_TOK_INVALID;
			goto out;
		} else {
			global_auth_tok->flags &= ~TSE_AUTH_TOK_INVALID;
			up_write(&(global_auth_tok->global_auth_tok_key)->sem);
		}
	}
out:
	return rc;
}

static void tse_init_mount_crypt_stat(
	struct tse_mount_crypt_stat *mount_crypt_stat)
{
	memset((void *)mount_crypt_stat, 0,
	       sizeof(struct tse_mount_crypt_stat));
	INIT_LIST_HEAD(&mount_crypt_stat->global_auth_tok_list);
	mutex_init(&mount_crypt_stat->global_auth_tok_list_mutex);
	mount_crypt_stat->flags |= TSE_MOUNT_CRYPT_STAT_INITIALIZED;
}

/**
 * tse_parse_options
 * @sb: The tse super block
 * @options: The options passed to the kernel
 * @check_ruid: set to 1 if device uid should be checked against the ruid
 *
 * Parse mount options:
 * debug=N 	   - tse_verbosity level for debug output
 * sig=XXX	   - description(signature) of the key to use
 *
 * Returns the dentry object of the lower-level (lower/interposed)
 * directory; We want to mount our stackable file system on top of
 * that lower directory.
 *
 * The signature of the key to use must be the description of a key
 * already in the keyring. Mounting will fail if the key can not be
 * found.
 *
 * Returns zero on success; non-zero on error
 */
static int tse_parse_options(struct tse_sb_info *sbi, char *options,
				  uid_t *check_ruid)
{
	char *p;
	int rc = 0;
	int sig_set = 0;
	int cipher_name_set = 0;
	int fn_cipher_name_set = 0;
	int cipher_key_bytes;
	int cipher_key_bytes_set = 0;
	int fn_cipher_key_bytes;
	int fn_cipher_key_bytes_set = 0;
	struct tse_mount_crypt_stat *mount_crypt_stat =
		&sbi->mount_crypt_stat;
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *sig_src;
	char *cipher_name_dst;
	char *cipher_name_src;
	char *fn_cipher_name_dst;
	char *fn_cipher_name_src;
	char *fnek_dst;
	char *fnek_src;
	char *cipher_key_bytes_src;
	char *fn_cipher_key_bytes_src;
	u8 cipher_code;

	*check_ruid = 0;

	if (!options) {
		rc = -EINVAL;
		goto out;
	}
	tse_init_mount_crypt_stat(mount_crypt_stat);
	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case tse_opt_sig:
		case tse_opt_tse_sig:
			sig_src = args[0].from;
			rc = tse_add_global_auth_tok(mount_crypt_stat,
							  sig_src, 0);
			if (rc) {
				printk(KERN_ERR "Error attempting to register "
				       "global sig; rc = [%d]\n", rc);
				goto out;
			}
			sig_set = 1;
			break;
		case tse_opt_cipher:
		case tse_opt_tse_cipher:
			cipher_name_src = args[0].from;
			cipher_name_dst =
				mount_crypt_stat->
				global_default_cipher_name;
			strncpy(cipher_name_dst, cipher_name_src,
				TSE_MAX_CIPHER_NAME_SIZE);
			cipher_name_dst[TSE_MAX_CIPHER_NAME_SIZE] = '\0';
			cipher_name_set = 1;
			break;
		case tse_opt_tse_key_bytes:
			cipher_key_bytes_src = args[0].from;
			cipher_key_bytes =
				(int)simple_strtol(cipher_key_bytes_src,
						   &cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_cipher_key_size =
				cipher_key_bytes;
			cipher_key_bytes_set = 1;
			break;
		case tse_opt_passthrough:
			mount_crypt_stat->flags |=
				TSE_PLAINTEXT_PASSTHROUGH_ENABLED;
			break;
		case tse_opt_xattr_metadata:
			mount_crypt_stat->flags |=
				TSE_XATTR_METADATA_ENABLED;
			break;
		case tse_opt_encrypted_view:
			mount_crypt_stat->flags |=
				TSE_XATTR_METADATA_ENABLED;
			mount_crypt_stat->flags |=
				TSE_ENCRYPTED_VIEW_ENABLED;
			break;
		case tse_opt_fnek_sig:
			fnek_src = args[0].from;
			fnek_dst =
				mount_crypt_stat->global_default_fnek_sig;
			strncpy(fnek_dst, fnek_src, ECRYPTFS_SIG_SIZE_HEX);
			mount_crypt_stat->global_default_fnek_sig[
				ECRYPTFS_SIG_SIZE_HEX] = '\0';
			rc = tse_add_global_auth_tok(
				mount_crypt_stat,
				mount_crypt_stat->global_default_fnek_sig,
				TSE_AUTH_TOK_FNEK);
			if (rc) {
				printk(KERN_ERR "Error attempting to register "
				       "global fnek sig [%s]; rc = [%d]\n",
				       mount_crypt_stat->global_default_fnek_sig,
				       rc);
				goto out;
			}
			mount_crypt_stat->flags |=
				(TSE_GLOBAL_ENCRYPT_FILENAMES
				 | TSE_GLOBAL_ENCFN_USE_MOUNT_FNEK);
			break;
		case tse_opt_fn_cipher:
			fn_cipher_name_src = args[0].from;
			fn_cipher_name_dst =
				mount_crypt_stat->global_default_fn_cipher_name;
			strncpy(fn_cipher_name_dst, fn_cipher_name_src,
				TSE_MAX_CIPHER_NAME_SIZE);
			mount_crypt_stat->global_default_fn_cipher_name[
				TSE_MAX_CIPHER_NAME_SIZE] = '\0';
			fn_cipher_name_set = 1;
			break;
		case tse_opt_fn_cipher_key_bytes:
			fn_cipher_key_bytes_src = args[0].from;
			fn_cipher_key_bytes =
				(int)simple_strtol(fn_cipher_key_bytes_src,
						   &fn_cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_fn_cipher_key_bytes =
				fn_cipher_key_bytes;
			fn_cipher_key_bytes_set = 1;
			break;
		case tse_opt_unlink_sigs:
			mount_crypt_stat->flags |= TSE_UNLINK_SIGS;
			break;
		case tse_opt_mount_auth_tok_only:
			mount_crypt_stat->flags |=
				TSE_GLOBAL_MOUNT_AUTH_TOK_ONLY;
			break;
		case tse_opt_check_dev_ruid:
			*check_ruid = 1;
			break;
		case tse_opt_err:
		default:
			printk(KERN_WARNING
			       "%s: Tse: unrecognized option [%s]\n",
			       __func__, p);
		}
	}
	if (!sig_set) {
		rc = -EINVAL;
		tse_printk(KERN_ERR, "You must supply at least one valid "
				"auth tok signature as a mount "
				"parameter; see the Tse README\n");
		goto out;
	}
	if (!cipher_name_set) {
		int cipher_name_len = strlen(TSE_DEFAULT_CIPHER);

		BUG_ON(cipher_name_len >= TSE_MAX_CIPHER_NAME_SIZE);
		strcpy(mount_crypt_stat->global_default_cipher_name,
		       TSE_DEFAULT_CIPHER);
	}
	if ((mount_crypt_stat->flags & TSE_GLOBAL_ENCRYPT_FILENAMES)
	    && !fn_cipher_name_set)
		strcpy(mount_crypt_stat->global_default_fn_cipher_name,
		       mount_crypt_stat->global_default_cipher_name);
	if (!cipher_key_bytes_set)
		mount_crypt_stat->global_default_cipher_key_size = 0;
	if ((mount_crypt_stat->flags & TSE_GLOBAL_ENCRYPT_FILENAMES)
	    && !fn_cipher_key_bytes_set)
		mount_crypt_stat->global_default_fn_cipher_key_bytes =
			mount_crypt_stat->global_default_cipher_key_size;

	cipher_code = tse_code_for_cipher_string(
		mount_crypt_stat->global_default_cipher_name,
		mount_crypt_stat->global_default_cipher_key_size);
	if (!cipher_code) {
		tse_printk(KERN_ERR,
				"Tse doesn't support cipher: %s",
				mount_crypt_stat->global_default_cipher_name);
		rc = -EINVAL;
		goto out;
	}

	mutex_lock(&key_tfm_list_mutex);
	if (!tse_tfm_exists(mount_crypt_stat->global_default_cipher_name,
				 NULL)) {
		rc = tse_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_cipher_name,
			mount_crypt_stat->global_default_cipher_key_size);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_cipher_name,
			       mount_crypt_stat->global_default_cipher_key_size,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	if ((mount_crypt_stat->flags & TSE_GLOBAL_ENCRYPT_FILENAMES)
	    && !tse_tfm_exists(
		    mount_crypt_stat->global_default_fn_cipher_name, NULL)) {
		rc = tse_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_fn_cipher_name,
			mount_crypt_stat->global_default_fn_cipher_key_bytes);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_fn_cipher_name,
			       mount_crypt_stat->global_default_fn_cipher_key_bytes,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	mutex_unlock(&key_tfm_list_mutex);
	rc = tse_init_global_auth_toks(mount_crypt_stat);
	if (rc)
		printk(KERN_WARNING "One or more global auth toks could not "
		       "properly register; rc = [%d]\n", rc);
out:
	return rc;
}

struct kmem_cache *tse_sb_info_cache;
static struct file_system_type tse_fs_type;

/**
 * tse_get_sb
 * @fs_type
 * @flags
 * @dev_name: The path to mount over
 * @raw_data: The options passed into the kernel
 */
static struct dentry *tse_mount(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *raw_data)
{
	int *s_stack_depth;	//Compile success after modification
	struct super_block *s;
	struct tse_sb_info *sbi;
	struct tse_dentry_info *root_info;
	const char *err = "Getting sb failed";
	struct inode *inode;
	struct path path;
	uid_t check_ruid;
	int rc;

	sbi = kmem_cache_zalloc(tse_sb_info_cache, GFP_KERNEL);
	if (!sbi) {
		rc = -ENOMEM;
		goto out;
	}

	rc = tse_parse_options(sbi, raw_data, &check_ruid);
	if (rc) {
		err = "Error parsing options";
		goto out;
	}

	s = sget(fs_type, NULL, set_anon_super, flags, NULL);
	if (IS_ERR(s)) {
		rc = PTR_ERR(s);
		goto out;
	}

	rc = bdi_setup_and_register(&sbi->bdi, "tse", BDI_CAP_MAP_COPY);
	if (rc)
		goto out1;

	tse_set_superblock_private(s, sbi);
	s->s_bdi = &sbi->bdi;

	/* ->kill_sb() will take care of sbi after that point */
	sbi = NULL;
	s->s_op = &tse_sops;
	s->s_d_op = &tse_dops;

	err = "Reading sb failed";
	rc = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (rc) {
		tse_printk(KERN_WARNING, "kern_path() failed\n");
		goto out1;
	}
	if (path.dentry->d_sb->s_type == &tse_fs_type) {
		rc = -EINVAL;
		printk(KERN_ERR "Mount on filesystem of type "
			"Tse explicitly disallowed due to "
			"known incompatibilities\n");
		goto out_free;
	}

	if (check_ruid && !uid_eq(path.dentry->d_inode->i_uid, current_uid())) {
		rc = -EPERM;
		printk(KERN_ERR "Mount of device (uid: %d) not owned by "
		       "requested user (uid: %d)\n",
			i_uid_read(path.dentry->d_inode),
			from_kuid(&init_user_ns, current_uid()));
		goto out_free;
	}

	tse_set_superblock_lower(s, path.dentry->d_sb);

	/**
	 * Set the POSIX ACL flag based on whether they're enabled in the lower
	 * mount. Force a read-only Tse mount if the lower mount is ro.
	 * Allow a ro Tse mount even when the lower mount is rw.
	 */
	s->s_flags = flags & ~MS_POSIXACL;
	s->s_flags |= path.dentry->d_sb->s_flags & (MS_RDONLY | MS_POSIXACL);

	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
	s->s_blocksize = path.dentry->d_sb->s_blocksize;
	s->s_magic = ECRYPTFS_SUPER_MAGIC;
	//s->s_stack_depth = path.dentry->d_sb->s_stack_depth + 1;
	s_stack_depth = get_s_stack_depth(path.dentry->d_sb);	//Compile success after modification

	rc = -EINVAL;
	//if (s->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
	if ( *s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {	//Compile success after modification
		pr_err("Tse: maximum fs stacking depth exceeded\n");
		goto out_free;
	}

	inode = tse_get_inode(path.dentry->d_inode, s);
	rc = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_free;

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		rc = -ENOMEM;
		goto out_free;
	}

	rc = -ENOMEM;
	root_info = kmem_cache_zalloc(tse_dentry_info_cache, GFP_KERNEL);
	if (!root_info)
		goto out_free;

	/* ->kill_sb() will take care of root_info */
	tse_set_dentry_private(s->s_root, root_info);
	tse_set_dentry_lower(s->s_root, path.dentry);
	tse_set_dentry_lower_mnt(s->s_root, path.mnt);

	s->s_flags |= MS_ACTIVE;
	return dget(s->s_root);

out_free:
	path_put(&path);
out1:
	deactivate_locked_super(s);
out:
	if (sbi) {
		tse_destroy_mount_crypt_stat(&sbi->mount_crypt_stat);
		kmem_cache_free(tse_sb_info_cache, sbi);
	}
	printk(KERN_ERR "%s; rc = [%d]\n", err, rc);
	return ERR_PTR(rc);
}

/**
 * tse_kill_block_super
 * @sb: The tse super block
 *
 * Used to bring the superblock down and free the private data.
 */
static void tse_kill_block_super(struct super_block *sb)
{
	struct tse_sb_info *sb_info = tse_superblock_to_private(sb);
	kill_anon_super(sb);
	if (!sb_info)
		return;
	tse_destroy_mount_crypt_stat(&sb_info->mount_crypt_stat);
	bdi_destroy(&sb_info->bdi);
	kmem_cache_free(tse_sb_info_cache, sb_info);
}

static struct file_system_type tse_fs_type = {
	.owner = THIS_MODULE,
	.name = "tse",
	.mount = tse_mount,
	.kill_sb = tse_kill_block_super,
	.fs_flags = 0
};
MODULE_ALIAS_FS("tse");

/**
 * inode_info_init_once
 *
 * Initializes the tse_inode_info_cache when it is created
 */
static void
inode_info_init_once(void *vptr)
{
	struct tse_inode_info *ei = (struct tse_inode_info *)vptr;

	inode_init_once(&ei->vfs_inode);
}

static struct tse_cache_info {
	struct kmem_cache **cache;
	const char *name;
	size_t size;
	unsigned long flags;
	void (*ctor)(void *obj);
} tse_cache_infos[] = {
	{
		.cache = &tse_auth_tok_list_item_cache,
		.name = "tse_auth_tok_list_item",
		.size = sizeof(struct tse_auth_tok_list_item),
	},
	{
		.cache = &tse_file_info_cache,
		.name = "tse_file_cache",
		.size = sizeof(struct tse_file_info),
	},
	{
		.cache = &tse_dentry_info_cache,
		.name = "tse_dentry_info_cache",
		.size = sizeof(struct tse_dentry_info),
	},
	{
		.cache = &tse_inode_info_cache,
		.name = "tse_inode_cache",
		.size = sizeof(struct tse_inode_info),
		.flags = SLAB_ACCOUNT,
		.ctor = inode_info_init_once,
	},
	{
		.cache = &tse_sb_info_cache,
		.name = "tse_sb_cache",
		.size = sizeof(struct tse_sb_info),
	},
	{
		.cache = &tse_header_cache,
		.name = "tse_headers",
		.size = PAGE_CACHE_SIZE,
	},
	{
		.cache = &tse_xattr_cache,
		.name = "tse_xattr_cache",
		.size = PAGE_CACHE_SIZE,
	},
	{
		.cache = &tse_key_record_cache,
		.name = "tse_key_record_cache",
		.size = sizeof(struct tse_key_record),
	},
	{
		.cache = &tse_key_sig_cache,
		.name = "tse_key_sig_cache",
		.size = sizeof(struct tse_key_sig),
	},
	{
		.cache = &tse_global_auth_tok_cache,
		.name = "tse_global_auth_tok_cache",
		.size = sizeof(struct tse_global_auth_tok),
	},
	{
		.cache = &tse_key_tfm_cache,
		.name = "tse_key_tfm_cache",
		.size = sizeof(struct tse_key_tfm),
	},
};

static void tse_free_kmem_caches(void)
{
	int i;

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	for (i = 0; i < ARRAY_SIZE(tse_cache_infos); i++) {
		struct tse_cache_info *info;

		info = &tse_cache_infos[i];
		if (*(info->cache))
			kmem_cache_destroy(*(info->cache));
	}
}

/**
 * tse_init_kmem_caches
 *
 * Returns zero on success; non-zero otherwise
 */
static int tse_init_kmem_caches(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tse_cache_infos); i++) {
		struct tse_cache_info *info;

		info = &tse_cache_infos[i];
		*(info->cache) = kmem_cache_create(info->name, info->size, 0,
				SLAB_HWCACHE_ALIGN | info->flags, info->ctor);
		if (!*(info->cache)) {
			tse_free_kmem_caches();
			tse_printk(KERN_WARNING, "%s: "
					"kmem_cache_create failed\n",
					info->name);
			return -ENOMEM;
		}
	}
	return 0;
}

static struct kobject *tse_kobj;

static ssize_t version_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	return snprintf(buff, PAGE_SIZE, "%d\n", TSE_VERSIONING_MASK);
}

static struct kobj_attribute version_attr = __ATTR_RO(version);

static struct attribute *attributes[] = {
	&version_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attributes,
};

static int do_sysfs_registration(void)
{
	int rc;

	tse_kobj = kobject_create_and_add("tse", fs_kobj);
	if (!tse_kobj) {
		printk(KERN_ERR "Unable to create tse kset\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = sysfs_create_group(tse_kobj, &attr_group);
	if (rc) {
		printk(KERN_ERR
		       "Unable to create tse version attributes\n");
		kobject_put(tse_kobj);
	}
out:
	return rc;
}

static void do_sysfs_unregistration(void)
{
	sysfs_remove_group(tse_kobj, &attr_group);
	kobject_put(tse_kobj);
}

static int __init tse_init(void)
{
	int rc;

	if (TSE_DEFAULT_EXTENT_SIZE > PAGE_CACHE_SIZE) {
		rc = -EINVAL;
		tse_printk(KERN_ERR, "The Tse extent size is "
				"larger than the host's page size, and so "
				"Tse cannot run on this system. The "
				"default Tse extent size is [%u] bytes; "
				"the page size is [%lu] bytes.\n",
				TSE_DEFAULT_EXTENT_SIZE,
				(unsigned long)PAGE_CACHE_SIZE);
		goto out;
	}
	rc = tse_init_kmem_caches();
	if (rc) {
		printk(KERN_ERR
		       "Failed to allocate one or more kmem_cache objects\n");
		goto out;
	}
	rc = do_sysfs_registration();
	if (rc) {
		printk(KERN_ERR "sysfs registration failed\n");
		goto out_free_kmem_caches;
	}
	rc = tse_init_kthread();
	if (rc) {
		printk(KERN_ERR "%s: kthread initialization failed; "
		       "rc = [%d]\n", __func__, rc);
		goto out_do_sysfs_unregistration;
	}
	rc = tse_init_messaging();
	if (rc) {
		printk(KERN_ERR "Failure occurred while attempting to "
				"initialize the communications channel to "
				"tsed\n");
		goto out_destroy_kthread;
	}
	rc = tse_init_crypto();
	if (rc) {
		printk(KERN_ERR "Failure whilst attempting to init crypto; "
		       "rc = [%d]\n", rc);
		goto out_release_messaging;
	}
	rc = register_filesystem(&tse_fs_type);
	if (rc) {
		printk(KERN_ERR "Failed to register filesystem\n");
		goto out_destroy_crypto;
	}
	if (tse_verbosity > 0)
		printk(KERN_CRIT "Tse verbosity set to %d. Secret values "
			"will be written to the syslog!\n", tse_verbosity);

	goto out;
out_destroy_crypto:
	tse_destroy_crypto();
out_release_messaging:
	tse_release_messaging();
out_destroy_kthread:
	tse_destroy_kthread();
out_do_sysfs_unregistration:
	do_sysfs_unregistration();
out_free_kmem_caches:
	tse_free_kmem_caches();
out:
	return rc;
}

static void __exit tse_exit(void)
{
	int rc;

	rc = tse_destroy_crypto();
	if (rc)
		printk(KERN_ERR "Failure whilst attempting to destroy crypto; "
		       "rc = [%d]\n", rc);
	tse_release_messaging();
	tse_destroy_kthread();
	do_sysfs_unregistration();
	unregister_filesystem(&tse_fs_type);
	tse_free_kmem_caches();
}

MODULE_AUTHOR("Michael A. Halcrow <mhalcrow@us.ibm.com>");
MODULE_DESCRIPTION("Tse");

MODULE_LICENSE("GPL");

module_init(tse_init)
module_exit(tse_exit)
