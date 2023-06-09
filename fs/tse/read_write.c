/**
 * Tse: Linux filesystem encryption layer
 *
 * Copyright (C) 2007 International Business Machines Corp.
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

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "tse_kernel.h"

/**
 * tse_write_lower
 * @tse_inode: The Tse inode
 * @data: Data to write
 * @offset: Byte offset in the lower file to which to write the data
 * @size: Number of bytes from @data to write at @offset in the lower
 *        file
 *
 * Write data to the lower file.
 *
 * Returns bytes written on success; less than zero on error
 */
int tse_write_lower(struct inode *tse_inode, char *data,
			 loff_t offset, size_t size)
{
	struct file *lower_file;
	ssize_t rc;

	lower_file = tse_inode_to_private(tse_inode)->lower_file;
	if (!lower_file)
		return -EIO;
	rc = kernel_write(lower_file, data, size, offset);
	mark_inode_dirty_sync(tse_inode);
	return rc;
}

/**
 * tse_write_lower_page_segment
 * @tse_inode: The Tse inode
 * @page_for_lower: The page containing the data to be written to the
 *                  lower file
 * @offset_in_page: The offset in the @page_for_lower from which to
 *                  start writing the data
 * @size: The amount of data from @page_for_lower to write to the
 *        lower file
 *
 * Determines the byte offset in the file for the given page and
 * offset within the page, maps the page, and makes the call to write
 * the contents of @page_for_lower to the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int tse_write_lower_page_segment(struct inode *tse_inode,
				      struct page *page_for_lower,
				      size_t offset_in_page, size_t size)
{
	char *virt;
	loff_t offset;
	int rc;

	offset = ((((loff_t)page_for_lower->index) << PAGE_CACHE_SHIFT)
		  + offset_in_page);
	virt = kmap(page_for_lower);
	rc = tse_write_lower(tse_inode, virt, offset, size);
	if (rc > 0)
		rc = 0;
	kunmap(page_for_lower);
	return rc;
}

/**
 * tse_write
 * @tse_inode: The Tse file into which to write
 * @data: Virtual address where data to write is located
 * @offset: Offset in the Tse file at which to begin writing the
 *          data from @data
 * @size: The number of bytes to write from @data
 *
 * Write an arbitrary amount of data to an arbitrary location in the
 * Tse inode page cache. This is done on a page-by-page, and then
 * by an extent-by-extent, basis; individual extents are encrypted and
 * written to the lower page cache (via VFS writes). This function
 * takes care of all the address translation to locations in the lower
 * filesystem; it also handles truncate events, writing out zeros
 * where necessary.
 *
 * Returns zero on success; non-zero otherwise
 */
int tse_write(struct inode *tse_inode, char *data, loff_t offset,
		   size_t size)
{
	struct page *tse_page;
	struct tse_crypt_stat *crypt_stat;
	char *tse_page_virt;
	loff_t tse_file_size = i_size_read(tse_inode);
	loff_t data_offset = 0;
	loff_t pos;
	int rc = 0;

	crypt_stat = &tse_inode_to_private(tse_inode)->crypt_stat;
	/*
	 * if we are writing beyond current size, then start pos
	 * at the current size - we'll fill in zeros from there.
	 */
	if (offset > tse_file_size)
		pos = tse_file_size;
	else
		pos = offset;
	while (pos < (offset + size)) {
		pgoff_t tse_page_idx = (pos >> PAGE_CACHE_SHIFT);
		size_t start_offset_in_page = (pos & ~PAGE_CACHE_MASK);
		size_t num_bytes = (PAGE_CACHE_SIZE - start_offset_in_page);
		loff_t total_remaining_bytes = ((offset + size) - pos);

		if (fatal_signal_pending(current)) {
			rc = -EINTR;
			break;
		}

		if (num_bytes > total_remaining_bytes)
			num_bytes = total_remaining_bytes;
		if (pos < offset) {
			/* remaining zeros to write, up to destination offset */
			loff_t total_remaining_zeros = (offset - pos);

			if (num_bytes > total_remaining_zeros)
				num_bytes = total_remaining_zeros;
		}
		tse_page = tse_get_locked_page(tse_inode,
							 tse_page_idx);
		if (IS_ERR(tse_page)) {
			rc = PTR_ERR(tse_page);
			printk(KERN_ERR "%s: Error getting page at "
			       "index [%ld] from Tse inode "
			       "mapping; rc = [%d]\n", __func__,
			       tse_page_idx, rc);
			goto out;
		}
		tse_page_virt = kmap_atomic(tse_page);

		/*
		 * pos: where we're now writing, offset: where the request was
		 * If current pos is before request, we are filling zeros
		 * If we are at or beyond request, we are writing the *data*
		 * If we're in a fresh page beyond eof, zero it in either case
		 */
		if (pos < offset || !start_offset_in_page) {
			/* We are extending past the previous end of the file.
			 * Fill in zero values to the end of the page */
			memset(((char *)tse_page_virt
				+ start_offset_in_page), 0,
				PAGE_CACHE_SIZE - start_offset_in_page);
		}

		/* pos >= offset, we are now writing the data request */
		if (pos >= offset) {
			memcpy(((char *)tse_page_virt
				+ start_offset_in_page),
			       (data + data_offset), num_bytes);
			data_offset += num_bytes;
		}
		kunmap_atomic(tse_page_virt);
		flush_dcache_page(tse_page);
		SetPageUptodate(tse_page);
		unlock_page(tse_page);
		if (crypt_stat->flags & TSE_ENCRYPTED)
			rc = tse_encrypt_page(tse_page);
		else
			rc = tse_write_lower_page_segment(tse_inode,
						tse_page,
						start_offset_in_page,
						data_offset);
		page_cache_release(tse_page);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting "
			       "page; rc = [%d]\n", __func__, rc);
			goto out;
		}
		pos += num_bytes;
	}
	if (pos > tse_file_size) {
		i_size_write(tse_inode, pos);
		if (crypt_stat->flags & TSE_ENCRYPTED) {
			int rc2;

			rc2 = tse_write_inode_size_to_metadata(
								tse_inode);
			if (rc2) {
				printk(KERN_ERR	"Problem with "
				       "tse_write_inode_size_to_metadata; "
				       "rc = [%d]\n", rc2);
				if (!rc)
					rc = rc2;
				goto out;
			}
		}
	}
out:
	return rc;
}

/**
 * tse_read_lower
 * @data: The read data is stored here by this function
 * @offset: Byte offset in the lower file from which to read the data
 * @size: Number of bytes to read from @offset of the lower file and
 *        store into @data
 * @tse_inode: The Tse inode
 *
 * Read @size bytes of data at byte offset @offset from the lower
 * inode into memory location @data.
 *
 * Returns bytes read on success; 0 on EOF; less than zero on error
 */
int tse_read_lower(char *data, loff_t offset, size_t size,
			struct inode *tse_inode)
{
	struct file *lower_file;
	lower_file = tse_inode_to_private(tse_inode)->lower_file;
	if (!lower_file)
		return -EIO;
	return kernel_read(lower_file, offset, data, size);
}

/**
 * tse_read_lower_page_segment
 * @page_for_tse: The page into which data for Tse will be
 *                     written
 * @offset_in_page: Offset in @page_for_tse from which to start
 *                  writing
 * @size: The number of bytes to write into @page_for_tse
 * @tse_inode: The Tse inode
 *
 * Determines the byte offset in the file for the given page and
 * offset within the page, maps the page, and makes the call to read
 * the contents of @page_for_tse from the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int tse_read_lower_page_segment(struct page *page_for_tse,
				     pgoff_t page_index,
				     size_t offset_in_page, size_t size,
				     struct inode *tse_inode)
{
	char *virt;
	loff_t offset;
	int rc;

	offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
	virt = kmap(page_for_tse);
	rc = tse_read_lower(virt, offset, size, tse_inode);
	if (rc > 0)
		rc = 0;
	kunmap(page_for_tse);
	flush_dcache_page(page_for_tse);
	return rc;
}
