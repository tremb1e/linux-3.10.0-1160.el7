/**
 * Tse: Linux filesystem encryption layer
 * Kernel declarations.
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Trevor S. Highland <trevor.highland@gmail.com>
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

#ifndef TSE_KERNEL_H
#define TSE_KERNEL_H

#include <keys/user-type.h>
#include <keys/encrypted-type.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/scatterlist.h>
#include <linux/hash.h>
#include <linux/nsproxy.h>
#include <linux/backing-dev.h>
#include <linux/ecryptfs.h>
#include <linux/crypto.h>

#define TSE_DEFAULT_IV_BYTES 16
#define TSE_DEFAULT_EXTENT_SIZE 4096
#define TSE_MINIMUM_HEADER_EXTENT_SIZE 8192	//tremb1e 
#define TSE_DEFAULT_MSG_CTX_ELEMS 32
#define TSE_DEFAULT_SEND_TIMEOUT HZ
#define TSE_MAX_MSG_CTX_TTL (HZ*3)
#define TSE_DEFAULT_NUM_USERS 4
#define TSE_MAX_NUM_USERS 32768
#define TSE_XATTR_NAME "user.tse"

void tse_dump_auth_tok(struct ecryptfs_auth_tok *auth_tok);
extern void tse_to_hex(char *dst, char *src, size_t src_size);
extern void tse_from_hex(char *dst, char *src, int dst_size);

struct tse_key_record {
	unsigned char type;
	size_t enc_key_size;
	unsigned char sig[ECRYPTFS_SIG_SIZE];
	unsigned char enc_key[ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES];
};

struct tse_auth_tok_list {
	struct ecryptfs_auth_tok *auth_tok;
	struct list_head list;
};

struct tse_crypt_stat;
struct tse_mount_crypt_stat;

struct tse_page_crypt_context {
	struct page *page;
#define TSE_PREPARE_COMMIT_MODE 0
#define TSE_WRITEPAGE_MODE      1
	unsigned int mode;
	union {
		struct file *lower_file;
		struct writeback_control *wbc;
	} param;
};

#if defined(CONFIG_ENCRYPTED_KEYS) || defined(CONFIG_ENCRYPTED_KEYS_MODULE)
static inline struct ecryptfs_auth_tok *
tse_get_encrypted_key_payload_data(struct key *key)
{
	if (key->type == &key_type_encrypted)
		return (struct ecryptfs_auth_tok *)
			(&((struct encrypted_key_payload *)key->payload.data)->payload_data);
	else
		return NULL;
}

static inline struct key *tse_get_encrypted_key(char *sig)
{
	return request_key(&key_type_encrypted, sig, NULL);
}

#else
static inline struct ecryptfs_auth_tok *
tse_get_encrypted_key_payload_data(struct key *key)
{
	return NULL;
}

static inline struct key *tse_get_encrypted_key(char *sig)
{
	return ERR_PTR(-ENOKEY);
}

#endif /* CONFIG_ENCRYPTED_KEYS */

static inline struct ecryptfs_auth_tok *
tse_get_key_payload_data(struct key *key)
{
	struct ecryptfs_auth_tok *auth_tok;

	auth_tok = tse_get_encrypted_key_payload_data(key);
	if (!auth_tok)
		return (struct ecryptfs_auth_tok *)user_key_payload_locked(key)->data;
	else
		return auth_tok;
}

#define TSE_MAX_KEYSET_SIZE 1024
#define TSE_MAX_CIPHER_NAME_SIZE 32
#define TSE_MAX_NUM_ENC_KEYS 64
#define TSE_MAX_IV_BYTES 16	/* 128 bits */
#define TSE_SALT_BYTES 2
#define MAGIC_TSE_MARKER 0x3c81b7f5
#define MAGIC_TSE_MARKER_SIZE_BYTES 8	/* 4*2 */
#define TSE_FILE_SIZE_BYTES (sizeof(u64))
#define TSE_SIZE_AND_MARKER_BYTES (TSE_FILE_SIZE_BYTES \
					+ MAGIC_TSE_MARKER_SIZE_BYTES)
#define TSE_DEFAULT_CIPHER "aes"
#define TSE_DEFAULT_KEY_BYTES 16
#define TSE_DEFAULT_HASH "md5"
#define TSE_TAG_70_DIGEST TSE_DEFAULT_HASH
#define TSE_TAG_1_PACKET_TYPE 0x01
#define TSE_TAG_3_PACKET_TYPE 0x8C
#define TSE_TAG_11_PACKET_TYPE 0xED
#define TSE_TAG_64_PACKET_TYPE 0x40
#define TSE_TAG_65_PACKET_TYPE 0x41
#define TSE_TAG_66_PACKET_TYPE 0x42
#define TSE_TAG_67_PACKET_TYPE 0x43
#define TSE_TAG_70_PACKET_TYPE 0x46 /* FNEK-encrypted filename
					  * as dentry name */
#define TSE_TAG_71_PACKET_TYPE 0x47 /* FNEK-encrypted filename in
					  * metadata */
#define TSE_TAG_72_PACKET_TYPE 0x48 /* FEK-encrypted filename as
					  * dentry name */
#define TSE_TAG_73_PACKET_TYPE 0x49 /* FEK-encrypted filename as
					  * metadata */
#define TSE_MIN_PKT_LEN_SIZE 1 /* Min size to specify packet length */
#define TSE_MAX_PKT_LEN_SIZE 2 /* Pass at least this many bytes to
				     * tse_parse_packet_length() and
				     * tse_write_packet_length()
				     */
/* Constraint: TSE_FILENAME_MIN_RANDOM_PREPEND_BYTES >=
 * TSE_MAX_IV_BYTES */
#define TSE_FILENAME_MIN_RANDOM_PREPEND_BYTES 16
#define TSE_NON_NULL 0x42 /* A reasonable substitute for NULL */
#define MD5_DIGEST_SIZE 16
#define TSE_TAG_70_DIGEST_SIZE MD5_DIGEST_SIZE
#define TSE_TAG_70_MIN_METADATA_SIZE (1 + TSE_MIN_PKT_LEN_SIZE \
					   + ECRYPTFS_SIG_SIZE + 1 + 1)
#define TSE_TAG_70_MAX_METADATA_SIZE (1 + TSE_MAX_PKT_LEN_SIZE \
					   + ECRYPTFS_SIG_SIZE + 1 + 1)
#define TSE_FEK_ENCRYPTED_FILENAME_PREFIX "TSE_FEK_ENCRYPTED."
#define TSE_FEK_ENCRYPTED_FILENAME_PREFIX_SIZE 23
#define TSE_FNEK_ENCRYPTED_FILENAME_PREFIX "TSE_FNEK_ENCRYPTED."
#define TSE_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE 24
#define TSE_ENCRYPTED_DENTRY_NAME_LEN (18 + 1 + 4 + 1 + 32)

#ifdef CONFIG_T_SE_MESSAGING
# define TSE_VERSIONING_MASK_MESSAGING (ECRYPTFS_VERSIONING_DEVMISC \
					     | ECRYPTFS_VERSIONING_PUBKEY)
#else
# define TSE_VERSIONING_MASK_MESSAGING 0
#endif

#define TSE_VERSIONING_MASK (ECRYPTFS_VERSIONING_PASSPHRASE \
				  | ECRYPTFS_VERSIONING_PLAINTEXT_PASSTHROUGH \
				  | ECRYPTFS_VERSIONING_XATTR \
				  | ECRYPTFS_VERSIONING_MULTKEY \
				  | TSE_VERSIONING_MASK_MESSAGING \
				  | ECRYPTFS_VERSIONING_FILENAME_ENCRYPTION)
struct tse_key_sig {
	struct list_head crypt_stat_list;
	char keysig[ECRYPTFS_SIG_SIZE_HEX + 1];
};

struct tse_filename {
	struct list_head crypt_stat_list;
#define TSE_FILENAME_CONTAINS_DECRYPTED 0x00000001
	u32 flags;
	u32 seq_no;
	char *filename;
	char *encrypted_filename;
	size_t filename_size;
	size_t encrypted_filename_size;
	char fnek_sig[ECRYPTFS_SIG_SIZE_HEX];
	char dentry_name[TSE_ENCRYPTED_DENTRY_NAME_LEN + 1];
};

/**
 * This is the primary struct associated with each encrypted file.
 *
 * TODO: cache align/pack?
 */
struct tse_crypt_stat {
#define TSE_STRUCT_INITIALIZED   0x00000001
#define TSE_POLICY_APPLIED       0x00000002
#define TSE_ENCRYPTED            0x00000004
#define TSE_SECURITY_WARNING     0x00000008
#define TSE_ENABLE_HMAC          0x00000010
#define TSE_ENCRYPT_IV_PAGES     0x00000020
#define TSE_KEY_VALID            0x00000040
#define TSE_METADATA_IN_XATTR    0x00000080
#define TSE_VIEW_AS_ENCRYPTED    0x00000100
#define TSE_KEY_SET              0x00000200
#define TSE_ENCRYPT_FILENAMES    0x00000400
#define TSE_ENCFN_USE_MOUNT_FNEK 0x00000800
#define TSE_ENCFN_USE_FEK        0x00001000
#define TSE_UNLINK_SIGS          0x00002000
#define TSE_I_SIZE_INITIALIZED   0x00004000
	u32 flags;
	unsigned int file_version;
	size_t iv_bytes;
	size_t metadata_size;
	size_t extent_size; /* Data extent size; default is 4096 */
	size_t key_size;
	size_t extent_shift;
	unsigned int extent_mask;
	struct tse_mount_crypt_stat *mount_crypt_stat;
	struct crypto_ablkcipher *tfm;
	struct crypto_hash *hash_tfm; /* Crypto context for generating
				       * the initialization vectors */
	unsigned char cipher[TSE_MAX_CIPHER_NAME_SIZE];
	unsigned char key[ECRYPTFS_MAX_KEY_BYTES];
	unsigned char root_iv[TSE_MAX_IV_BYTES];
	struct list_head keysig_list;
	struct mutex keysig_list_mutex;
	struct mutex cs_tfm_mutex;
	struct mutex cs_hash_tfm_mutex;
	struct mutex cs_mutex;
};

/* inode private data. */
struct tse_inode_info {
	struct inode vfs_inode;
	struct inode *wii_inode;
	struct mutex lower_file_mutex;
	atomic_t lower_file_count;
	struct file *lower_file;
	struct tse_crypt_stat crypt_stat;
};

/* dentry private data. Each dentry must keep track of a lower
 * vfsmount too. */
struct tse_dentry_info {
	struct path lower_path;
	struct tse_crypt_stat *crypt_stat;
};

/**
 * tse_global_auth_tok - A key used to encrypt all new files under the mountpoint
 * @flags: Status flags
 * @mount_crypt_stat_list: These auth_toks hang off the mount-wide
 *                         cryptographic context. Every time a new
 *                         inode comes into existence, Tse copies
 *                         the auth_toks on that list to the set of
 *                         auth_toks on the inode's crypt_stat
 * @global_auth_tok_key: The key from the user's keyring for the sig
 * @global_auth_tok: The key contents
 * @sig: The key identifier
 *
 * tse_global_auth_tok structs refer to authentication token keys
 * in the user keyring that apply to newly created files. A list of
 * these objects hangs off of the mount_crypt_stat struct for any
 * given Tse mount. This struct maintains a reference to both the
 * key contents and the key itself so that the key can be put on
 * unmount.
 */
struct tse_global_auth_tok {
#define TSE_AUTH_TOK_INVALID 0x00000001
#define TSE_AUTH_TOK_FNEK    0x00000002
	u32 flags;
	struct list_head mount_crypt_stat_list;
	struct key *global_auth_tok_key;
	unsigned char sig[ECRYPTFS_SIG_SIZE_HEX + 1];
};

/**
 * tse_key_tfm - Persistent key tfm
 * @key_tfm: crypto API handle to the key
 * @key_size: Key size in bytes
 * @key_tfm_mutex: Mutex to ensure only one operation in Tse is
 *                 using the persistent TFM at any point in time
 * @key_tfm_list: Handle to hang this off the module-wide TFM list
 * @cipher_name: String name for the cipher for this TFM
 *
 * Typically, Tse will use the same ciphers repeatedly throughout
 * the course of its operations. In order to avoid unnecessarily
 * destroying and initializing the same cipher repeatedly, Tse
 * keeps a list of crypto API contexts around to use when needed.
 */
struct tse_key_tfm {
	struct crypto_blkcipher *key_tfm;
	size_t key_size;
	struct mutex key_tfm_mutex;
	struct list_head key_tfm_list;
	unsigned char cipher_name[TSE_MAX_CIPHER_NAME_SIZE + 1];
};

extern struct mutex key_tfm_list_mutex;

/**
 * This struct is to enable a mount-wide passphrase/salt combo. This
 * is more or less a stopgap to provide similar functionality to other
 * crypto filesystems like EncFS or CFS until full policy support is
 * implemented in Tse.
 */
struct tse_mount_crypt_stat {
	/* Pointers to memory we do not own, do not free these */
#define TSE_PLAINTEXT_PASSTHROUGH_ENABLED 0x00000001
#define TSE_XATTR_METADATA_ENABLED        0x00000002
#define TSE_ENCRYPTED_VIEW_ENABLED        0x00000004
#define TSE_MOUNT_CRYPT_STAT_INITIALIZED  0x00000008
#define TSE_GLOBAL_ENCRYPT_FILENAMES      0x00000010
#define TSE_GLOBAL_ENCFN_USE_MOUNT_FNEK   0x00000020
#define TSE_GLOBAL_ENCFN_USE_FEK          0x00000040
#define TSE_GLOBAL_MOUNT_AUTH_TOK_ONLY    0x00000080
	u32 flags;
	struct list_head global_auth_tok_list;
	struct mutex global_auth_tok_list_mutex;
	size_t global_default_cipher_key_size;
	size_t global_default_fn_cipher_key_bytes;
	unsigned char global_default_cipher_name[TSE_MAX_CIPHER_NAME_SIZE
						 + 1];
	unsigned char global_default_fn_cipher_name[
		TSE_MAX_CIPHER_NAME_SIZE + 1];
	char global_default_fnek_sig[ECRYPTFS_SIG_SIZE_HEX + 1];
};

/* superblock private data. */
struct tse_sb_info {
	struct super_block *wsi_sb;
	struct tse_mount_crypt_stat mount_crypt_stat;
	struct backing_dev_info bdi;
};

/* file private data. */
struct tse_file_info {
	struct file *wfi_file;
	struct tse_crypt_stat *crypt_stat;
};

/* auth_tok <=> encrypted_session_key mappings */
struct tse_auth_tok_list_item {
	unsigned char encrypted_session_key[ECRYPTFS_MAX_KEY_BYTES];
	struct list_head list;
	struct ecryptfs_auth_tok auth_tok;
};

struct tse_message {
	/* Can never be greater than tse_message_buf_len */
	/* Used to find the parent msg_ctx */
	/* Inherits from msg_ctx->index */
	u32 index;
	u32 data_len;
	u8 data[];
};

struct tse_msg_ctx {
#define TSE_MSG_CTX_STATE_FREE     0x01
#define TSE_MSG_CTX_STATE_PENDING  0x02
#define TSE_MSG_CTX_STATE_DONE     0x03
#define TSE_MSG_CTX_STATE_NO_REPLY 0x04
	u8 state;
#define TSE_MSG_HELO 100
#define TSE_MSG_QUIT 101
#define TSE_MSG_REQUEST 102
#define TSE_MSG_RESPONSE 103
//tremb1e:新添加两种tse_msg
#define TSE_MSG_REQUEST_FEK 104
#define TSE_MSG_RESPONSE_FEK 105

	u8 type;
	u32 index;
	/* Counter converts to a sequence number. Each message sent
	 * out for which we expect a response has an associated
	 * sequence number. The response must have the same sequence
	 * number as the counter for the msg_stc for the message to be
	 * valid. */
	u32 counter;
	size_t msg_size;
	struct tse_message *msg;
	struct task_struct *task;
	struct list_head node;
	struct list_head daemon_out_list;
	struct mutex mux;
};

struct tse_daemon {
#define TSE_DAEMON_IN_READ      0x00000001
#define TSE_DAEMON_IN_POLL      0x00000002
#define TSE_DAEMON_ZOMBIE       0x00000004
#define TSE_DAEMON_MISCDEV_OPEN 0x00000008
	u32 flags;
	u32 num_queued_msg_ctx;
	struct file *file;
	struct mutex mux;
	struct list_head msg_ctx_out_queue;
	wait_queue_head_t wait;
	struct hlist_node euid_chain;
};

#ifdef CONFIG_T_SE_MESSAGING
extern struct mutex tse_daemon_hash_mux;
#endif

static inline size_t
tse_lower_header_size(struct tse_crypt_stat *crypt_stat)
{
	if (crypt_stat->flags & TSE_METADATA_IN_XATTR)
		return 0;
	return crypt_stat->metadata_size;
}

static inline struct tse_file_info *
tse_file_to_private(struct file *file)
{
	return file->private_data;
}

static inline void
tse_set_file_private(struct file *file,
			  struct tse_file_info *file_info)
{
	file->private_data = file_info;
}

static inline struct file *tse_file_to_lower(struct file *file)
{
	return ((struct tse_file_info *)file->private_data)->wfi_file;
}

static inline void
tse_set_file_lower(struct file *file, struct file *lower_file)
{
	((struct tse_file_info *)file->private_data)->wfi_file =
		lower_file;
}

static inline struct tse_inode_info *
tse_inode_to_private(struct inode *inode)
{
	return container_of(inode, struct tse_inode_info, vfs_inode);
}

static inline struct inode *tse_inode_to_lower(struct inode *inode)
{
	return tse_inode_to_private(inode)->wii_inode;
}

static inline void
tse_set_inode_lower(struct inode *inode, struct inode *lower_inode)
{
	tse_inode_to_private(inode)->wii_inode = lower_inode;
}

static inline struct tse_sb_info *
tse_superblock_to_private(struct super_block *sb)
{
	return (struct tse_sb_info *)sb->s_fs_info;
}

static inline void
tse_set_superblock_private(struct super_block *sb,
				struct tse_sb_info *sb_info)
{
	sb->s_fs_info = sb_info;
}

static inline struct super_block *
tse_superblock_to_lower(struct super_block *sb)
{
	return ((struct tse_sb_info *)sb->s_fs_info)->wsi_sb;
}

static inline void
tse_set_superblock_lower(struct super_block *sb,
			      struct super_block *lower_sb)
{
	((struct tse_sb_info *)sb->s_fs_info)->wsi_sb = lower_sb;
}

static inline struct tse_dentry_info *
tse_dentry_to_private(struct dentry *dentry)
{
	return (struct tse_dentry_info *)dentry->d_fsdata;
}

static inline void
tse_set_dentry_private(struct dentry *dentry,
			    struct tse_dentry_info *dentry_info)
{
	dentry->d_fsdata = dentry_info;
}

static inline struct dentry *
tse_dentry_to_lower(struct dentry *dentry)
{
	return ((struct tse_dentry_info *)dentry->d_fsdata)->lower_path.dentry;
}

static inline void
tse_set_dentry_lower(struct dentry *dentry, struct dentry *lower_dentry)
{
	((struct tse_dentry_info *)dentry->d_fsdata)->lower_path.dentry =
		lower_dentry;
}

static inline struct vfsmount *
tse_dentry_to_lower_mnt(struct dentry *dentry)
{
	return ((struct tse_dentry_info *)dentry->d_fsdata)->lower_path.mnt;
}

static inline struct path *
tse_dentry_to_lower_path(struct dentry *dentry)
{
	return &((struct tse_dentry_info *)dentry->d_fsdata)->lower_path;
}

static inline void
tse_set_dentry_lower_mnt(struct dentry *dentry, struct vfsmount *lower_mnt)
{
	((struct tse_dentry_info *)dentry->d_fsdata)->lower_path.mnt =
		lower_mnt;
}

#define tse_printk(type, fmt, arg...) \
        __tse_printk(type "%s: " fmt, __func__, ## arg);
__printf(1, 2)
void __tse_printk(const char *fmt, ...);

extern const struct file_operations tse_main_fops;
extern const struct file_operations tse_dir_fops;
extern const struct inode_operations tse_main_iops;
extern const struct inode_operations tse_dir_iops;
extern const struct inode_operations tse_symlink_iops;
extern const struct super_operations tse_sops;
extern const struct dentry_operations tse_dops;
extern const struct address_space_operations tse_aops;
extern int tse_verbosity;
extern unsigned int tse_message_buf_len;
extern signed long tse_message_wait_timeout;
extern unsigned int tse_number_of_users;

extern struct kmem_cache *tse_auth_tok_list_item_cache;
extern struct kmem_cache *tse_file_info_cache;
extern struct kmem_cache *tse_dentry_info_cache;
extern struct kmem_cache *tse_inode_info_cache;
extern struct kmem_cache *tse_sb_info_cache;
extern struct kmem_cache *tse_header_cache;
extern struct kmem_cache *tse_xattr_cache;
extern struct kmem_cache *tse_key_record_cache;
extern struct kmem_cache *tse_key_sig_cache;
extern struct kmem_cache *tse_global_auth_tok_cache;
extern struct kmem_cache *tse_key_tfm_cache;

struct inode *tse_get_inode(struct inode *lower_inode,
				 struct super_block *sb);
void tse_i_size_init(const char *page_virt, struct inode *inode);
int tse_initialize_file(struct dentry *tse_dentry,
			     struct inode *tse_inode);
int tse_decode_and_decrypt_filename(char **decrypted_name,
					 size_t *decrypted_name_size,
					 struct dentry *tse_dentry,
					 const char *name, size_t name_size);
int tse_fill_zeros(struct file *file, loff_t new_length);
int tse_encrypt_and_encode_filename(
	char **encoded_name,
	size_t *encoded_name_size,
	struct tse_crypt_stat *crypt_stat,
	struct tse_mount_crypt_stat *mount_crypt_stat,
	const char *name, size_t name_size);
struct dentry *tse_lower_dentry(struct dentry *this_dentry);
void tse_dump_hex(char *data, int bytes);
int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
			int sg_size);
int tse_compute_root_iv(struct tse_crypt_stat *crypt_stat);
void tse_rotate_iv(unsigned char *iv);
void tse_init_crypt_stat(struct tse_crypt_stat *crypt_stat);
void tse_destroy_crypt_stat(struct tse_crypt_stat *crypt_stat);
void tse_destroy_mount_crypt_stat(
	struct tse_mount_crypt_stat *mount_crypt_stat);
int tse_init_crypt_ctx(struct tse_crypt_stat *crypt_stat);
int tse_write_inode_size_to_metadata(struct inode *tse_inode);
int tse_encrypt_page(struct page *page);
int tse_decrypt_page(struct page *page);
int tse_write_metadata(struct dentry *tse_dentry,
			    struct inode *tse_inode);
int tse_read_metadata(struct dentry *tse_dentry);
int tse_new_file_context(struct inode *tse_inode);
void tse_write_crypt_stat_flags(char *page_virt,
				     struct tse_crypt_stat *crypt_stat,
				     size_t *written);
int tse_read_and_validate_header_region(struct inode *inode);
int tse_read_and_validate_xattr_region(struct dentry *dentry,
					    struct inode *inode);
u8 tse_code_for_cipher_string(char *cipher_name, size_t key_bytes);
int tse_cipher_code_to_string(char *str, u8 cipher_code);
void tse_set_default_sizes(struct tse_crypt_stat *crypt_stat);
int tse_generate_key_packet_set(char *dest_base,
				     struct tse_crypt_stat *crypt_stat,
				     struct dentry *tse_dentry,
				     size_t *len, size_t max);
int
tse_parse_packet_set(struct tse_crypt_stat *crypt_stat,
			  unsigned char *src, struct dentry *tse_dentry);
int tse_truncate(struct dentry *dentry, loff_t new_length);
ssize_t
tse_getxattr_lower(struct dentry *lower_dentry, const char *name,
			void *value, size_t size);
int
tse_setxattr(struct dentry *dentry, const char *name, const void *value,
		  size_t size, int flags);
int tse_read_xattr_region(char *page_virt, struct inode *tse_inode);
#ifdef CONFIG_T_SE_MESSAGING
int tse_process_response(struct tse_daemon *daemon,
			      struct tse_message *msg, u32 seq);
int tse_send_message(char *data, int data_len,
			  struct tse_msg_ctx **msg_ctx);
int tse_wait_for_response(struct tse_msg_ctx *msg_ctx,
			       struct tse_message **emsg);
int tse_init_messaging(void);
void tse_release_messaging(void);
#else
static inline int tse_init_messaging(void)
{
	return 0;
}
static inline void tse_release_messaging(void)
{ }
static inline int tse_send_message(char *data, int data_len,
					struct tse_msg_ctx **msg_ctx)
{
	return -ENOTCONN;
}
static inline int tse_wait_for_response(struct tse_msg_ctx *msg_ctx,
					     struct tse_message **emsg)
{
	return -ENOMSG;
}
#endif

void
tse_write_header_metadata(char *virt,
			       struct tse_crypt_stat *crypt_stat,
			       size_t *written);
int tse_add_keysig(struct tse_crypt_stat *crypt_stat, char *sig);
int
tse_add_global_auth_tok(struct tse_mount_crypt_stat *mount_crypt_stat,
			   char *sig, u32 global_auth_tok_flags);
int tse_get_global_auth_tok_for_sig(
	struct tse_global_auth_tok **global_auth_tok,
	struct tse_mount_crypt_stat *mount_crypt_stat, char *sig);
int
tse_add_new_key_tfm(struct tse_key_tfm **key_tfm, char *cipher_name,
			 size_t key_size);
int tse_init_crypto(void);
int tse_destroy_crypto(void);
int tse_tfm_exists(char *cipher_name, struct tse_key_tfm **key_tfm);
int tse_get_tfm_and_mutex_for_cipher_name(struct crypto_blkcipher **tfm,
					       struct mutex **tfm_mutex,
					       char *cipher_name);
int tse_keyring_auth_tok_for_sig(struct key **auth_tok_key,
				      struct ecryptfs_auth_tok **auth_tok,
				      char *sig);
int tse_write_lower(struct inode *tse_inode, char *data,
			 loff_t offset, size_t size);
int tse_write_lower_page_segment(struct inode *tse_inode,
				      struct page *page_for_lower,
				      size_t offset_in_page, size_t size);
int tse_write(struct inode *inode, char *data, loff_t offset, size_t size);
int tse_read_lower(char *data, loff_t offset, size_t size,
			struct inode *tse_inode);
int tse_read_lower_page_segment(struct page *page_for_tse,
				     pgoff_t page_index,
				     size_t offset_in_page, size_t size,
				     struct inode *tse_inode);
struct page *tse_get_locked_page(struct inode *inode, loff_t index);
int tse_parse_packet_length(unsigned char *data, size_t *size,
				 size_t *length_size);
int tse_write_packet_length(char *dest, size_t size,
				 size_t *packet_size_length);
#ifdef CONFIG_T_SE_MESSAGING
int tse_init_tse_miscdev(void);
void tse_destroy_tse_miscdev(void);
int tse_send_miscdev(char *data, size_t data_size,
			  struct tse_msg_ctx *msg_ctx, u8 msg_type,
			  u16 msg_flags, struct tse_daemon *daemon);
void tse_msg_ctx_alloc_to_free(struct tse_msg_ctx *msg_ctx);
int
tse_spawn_daemon(struct tse_daemon **daemon, struct file *file);
int tse_exorcise_daemon(struct tse_daemon *daemon);
int tse_find_daemon_by_euid(struct tse_daemon **daemon);
#endif
int tse_init_kthread(void);
void tse_destroy_kthread(void);
int tse_privileged_open(struct file **lower_file,
			     struct dentry *lower_dentry,
			     struct vfsmount *lower_mnt,
			     const struct cred *cred);
int tse_get_lower_file(struct dentry *dentry, struct inode *inode);
void tse_put_lower_file(struct inode *inode);
int
tse_write_tag_70_packet(char *dest, size_t *remaining_bytes,
			     size_t *packet_size,
			     struct tse_mount_crypt_stat *mount_crypt_stat,
			     char *filename, size_t filename_size);
int
tse_parse_tag_70_packet(char **filename, size_t *filename_size,
			     size_t *packet_size,
			     struct tse_mount_crypt_stat *mount_crypt_stat,
			     char *data, size_t max_packet_size);
int tse_set_f_namelen(long *namelen, long lower_namelen,
			   struct tse_mount_crypt_stat *mount_crypt_stat);
int tse_derive_iv(char *iv, struct tse_crypt_stat *crypt_stat,
		       loff_t offset);

//tremb1e
void get_fek_from_userspace(void *buf,int nbytes);

int tse_request_fek(char *data, int data_len,
			  struct tse_msg_ctx **msg_ctx);

#endif /* #ifndef TSE_KERNEL_H */
