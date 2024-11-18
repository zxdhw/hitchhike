// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ioctl.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/falloc.h>
#include <linux/sched/signal.h>
#include <linux/fiemap.h>
#include <linux/mount.h>
#include <linux/fscrypt.h>
#include <linux/fileattr.h>

#include "internal.h"

#include <asm/ioctls.h>

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS	(UINT_MAX / sizeof(struct fiemap_extent))

/**
 * vfs_ioctl - call filesystem specific ioctl methods
 * @filp:	open file to invoke ioctl method on
 * @cmd:	ioctl command to execute
 * @arg:	command-specific argument for ioctl
 *
 * Invokes filesystem specific ->unlocked_ioctl, if one exists; otherwise
 * returns -ENOTTY.
 *
 * Returns 0 on success, -errno on error.
 */
long vfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int error = -ENOTTY;

	if (!filp->f_op->unlocked_ioctl)
		goto out;

	error = filp->f_op->unlocked_ioctl(filp, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;
 out:
	return error;
}
EXPORT_SYMBOL(vfs_ioctl);

static int ioctl_fibmap(struct file *filp, int __user *p)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	int error, ur_block;
	sector_t block;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	error = get_user(ur_block, p);
	if (error)
		return error;

	if (ur_block < 0)
		return -EINVAL;

	block = ur_block;
	error = bmap(inode, &block);

	if (block > INT_MAX) {
		error = -ERANGE;
		pr_warn_ratelimited("[%s/%d] FS: %s File: %pD4 would truncate fibmap result\n",
				    current->comm, task_pid_nr(current),
				    sb->s_id, filp);
	}

	if (error)
		ur_block = 0;
	else
		ur_block = block;

	if (put_user(ur_block, p))
		error = -EFAULT;

	return error;
}

/**
 * fiemap_fill_next_extent - Fiemap helper function
 * @fieinfo:	Fiemap context passed into ->fiemap
 * @logical:	Extent logical start offset, in bytes
 * @phys:	Extent physical start offset, in bytes
 * @len:	Extent length, in bytes
 * @flags:	FIEMAP_EXTENT flags that describe this extent
 *
 * Called from file system ->fiemap callback. Will populate extent
 * info as passed in via arguments and copy to user memory. On
 * success, extent count on fieinfo is incremented.
 *
 * Returns 0 on success, -errno on error, 1 if this was the last
 * extent that will fit in user array.
 */
#define SET_UNKNOWN_FLAGS	(FIEMAP_EXTENT_DELALLOC)
#define SET_NO_UNMOUNTED_IO_FLAGS	(FIEMAP_EXTENT_DATA_ENCRYPTED)
#define SET_NOT_ALIGNED_FLAGS	(FIEMAP_EXTENT_DATA_TAIL|FIEMAP_EXTENT_DATA_INLINE)
int fiemap_fill_next_extent(struct fiemap_extent_info *fieinfo, u64 logical,
			    u64 phys, u64 len, u32 flags)
{
	struct fiemap_extent extent;
	struct fiemap_extent __user *dest = fieinfo->fi_extents_start;

	/* only count the extents */
	if (fieinfo->fi_extents_max == 0) {
		fieinfo->fi_extents_mapped++;
		return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
	}

	if (fieinfo->fi_extents_mapped >= fieinfo->fi_extents_max)
		return 1;

	if (flags & SET_UNKNOWN_FLAGS)
		flags |= FIEMAP_EXTENT_UNKNOWN;
	if (flags & SET_NO_UNMOUNTED_IO_FLAGS)
		flags |= FIEMAP_EXTENT_ENCODED;
	if (flags & SET_NOT_ALIGNED_FLAGS)
		flags |= FIEMAP_EXTENT_NOT_ALIGNED;

	memset(&extent, 0, sizeof(extent));
	extent.fe_logical = logical;
	extent.fe_physical = phys;
	extent.fe_length = len;
	extent.fe_flags = flags;

	dest += fieinfo->fi_extents_mapped;
	if (copy_to_user(dest, &extent, sizeof(extent)))
		return -EFAULT;

	fieinfo->fi_extents_mapped++;
	if (fieinfo->fi_extents_mapped == fieinfo->fi_extents_max)
		return 1;
	return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
}
EXPORT_SYMBOL(fiemap_fill_next_extent);

/**
 * fiemap_prep - check validity of requested flags for fiemap
 * @inode:	Inode to operate on
 * @fieinfo:	Fiemap context passed into ->fiemap
 * @start:	Start of the mapped range
 * @len:	Length of the mapped range, can be truncated by this function.
 * @supported_flags:	Set of fiemap flags that the file system understands
 *
 * This function must be called from each ->fiemap instance to validate the
 * fiemap request against the file system parameters.
 *
 * Returns 0 on success, or a negative error on failure.
 */
int fiemap_prep(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 *len, u32 supported_flags)
{
	u64 maxbytes = inode->i_sb->s_maxbytes;
	u32 incompat_flags;
	int ret = 0;

	if (*len == 0)
		return -EINVAL;
	if (start >= maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (*len > maxbytes || (maxbytes - *len) < start)
		*len = maxbytes - start;

	supported_flags |= FIEMAP_FLAG_SYNC;
	supported_flags &= FIEMAP_FLAGS_COMPAT;
	incompat_flags = fieinfo->fi_flags & ~supported_flags;
	if (incompat_flags) {
		fieinfo->fi_flags = incompat_flags;
		return -EBADR;
	}

	if (fieinfo->fi_flags & FIEMAP_FLAG_SYNC)
		ret = filemap_write_and_wait(inode->i_mapping);
	return ret;
}
EXPORT_SYMBOL(fiemap_prep);

static int ioctl_fiemap(struct file *filp, struct fiemap __user *ufiemap)
{
	struct fiemap fiemap;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	int error;

	if (!inode->i_op->fiemap)
		return -EOPNOTSUPP;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	error = inode->i_op->fiemap(inode, &fieinfo, fiemap.fm_start,
			fiemap.fm_length);

	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

static long ioctl_file_clone(struct file *dst_file, unsigned long srcfd,
			     u64 off, u64 olen, u64 destoff)
{
	struct fd src_file = fdget(srcfd);
	loff_t cloned;
	int ret;

	if (!src_file.file)
		return -EBADF;
	cloned = vfs_clone_file_range(src_file.file, off, dst_file, destoff,
				      olen, 0);
	if (cloned < 0)
		ret = cloned;
	else if (olen && cloned != olen)
		ret = -EINVAL;
	else
		ret = 0;
	fdput(src_file);
	return ret;
}

static long ioctl_file_clone_range(struct file *file,
				   struct file_clone_range __user *argp)
{
	struct file_clone_range args;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	return ioctl_file_clone(file, args.src_fd, args.src_offset,
				args.src_length, args.dest_offset);
}

/*
 * This provides compatibility with legacy XFS pre-allocation ioctls
 * which predate the fallocate syscall.
 *
 * Only the l_start, l_len and l_whence fields of the 'struct space_resv'
 * are used here, rest are ignored.
 */
static int ioctl_preallocate(struct file *filp, int mode, void __user *argp)
{
	struct inode *inode = file_inode(filp);
	struct space_resv sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += filp->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(filp, mode | FALLOC_FL_KEEP_SIZE, sr.l_start,
			sr.l_len);
}

/* on ia32 l_start is on a 32-bit boundary */
#if defined CONFIG_COMPAT && defined(CONFIG_X86_64)
/* just account for different alignment */
static int compat_ioctl_preallocate(struct file *file, int mode,
				    struct space_resv_32 __user *argp)
{
	struct inode *inode = file_inode(file);
	struct space_resv_32 sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += file->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(file, mode | FALLOC_FL_KEEP_SIZE, sr.l_start, sr.l_len);
}
#endif

static int file_ioctl(struct file *filp, unsigned int cmd, int __user *p)
{
	switch (cmd) {
	case FIBMAP:
		return ioctl_fibmap(filp, p);
	case FS_IOC_RESVSP:
	case FS_IOC_RESVSP64:
		return ioctl_preallocate(filp, 0, p);
	case FS_IOC_UNRESVSP:
	case FS_IOC_UNRESVSP64:
		return ioctl_preallocate(filp, FALLOC_FL_PUNCH_HOLE, p);
	case FS_IOC_ZERO_RANGE:
		return ioctl_preallocate(filp, FALLOC_FL_ZERO_RANGE, p);
	}

	return -ENOIOCTLCMD;
}

static int ioctl_fionbio(struct file *filp, int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = O_NONBLOCK;
#ifdef __sparc__
	/* SunOS compatibility item. */
	if (O_NONBLOCK != O_NDELAY)
		flag |= O_NDELAY;
#endif
	spin_lock(&filp->f_lock);
	if (on)
		filp->f_flags |= flag;
	else
		filp->f_flags &= ~flag;
	spin_unlock(&filp->f_lock);
	return error;
}

static int ioctl_fioasync(unsigned int fd, struct file *filp,
			  int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = on ? FASYNC : 0;

	/* Did FASYNC state change ? */
	if ((flag ^ filp->f_flags) & FASYNC) {
		if (filp->f_op->fasync)
			/* fasync() adjusts filp->f_flags */
			error = filp->f_op->fasync(fd, filp, on);
		else
			error = -ENOTTY;
	}
	return error < 0 ? error : 0;
}

static int ioctl_fsfreeze(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!ns_capable(sb->s_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/* If filesystem doesn't support freeze feature, return. */
	if (sb->s_op->freeze_fs == NULL && sb->s_op->freeze_super == NULL)
		return -EOPNOTSUPP;

	/* Freeze */
	if (sb->s_op->freeze_super)
		return sb->s_op->freeze_super(sb);
	return freeze_super(sb);
}

static int ioctl_fsthaw(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!ns_capable(sb->s_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/* Thaw */
	if (sb->s_op->thaw_super)
		return sb->s_op->thaw_super(sb);
	return thaw_super(sb);
}

static int ioctl_file_dedupe_range(struct file *file,
				   struct file_dedupe_range __user *argp)
{
	struct file_dedupe_range *same = NULL;
	int ret;
	unsigned long size;
	u16 count;

	if (get_user(count, &argp->dest_count)) {
		ret = -EFAULT;
		goto out;
	}

	size = offsetof(struct file_dedupe_range, info[count]);
	if (size > PAGE_SIZE) {
		ret = -ENOMEM;
		goto out;
	}

	same = memdup_user(argp, size);
	if (IS_ERR(same)) {
		ret = PTR_ERR(same);
		same = NULL;
		goto out;
	}

	same->dest_count = count;
	ret = vfs_dedupe_file_range(file, same);
	if (ret)
		goto out;

	ret = copy_to_user(argp, same, size);
	if (ret)
		ret = -EFAULT;

out:
	kfree(same);
	return ret;
}

/**
 * fileattr_fill_xflags - initialize fileattr with xflags
 * @fa:		fileattr pointer
 * @xflags:	FS_XFLAG_* flags
 *
 * Set ->fsx_xflags, ->fsx_valid and ->flags (translated xflags).  All
 * other fields are zeroed.
 */
void fileattr_fill_xflags(struct fileattr *fa, u32 xflags)
{
	memset(fa, 0, sizeof(*fa));
	fa->fsx_valid = true;
	fa->fsx_xflags = xflags;
	if (fa->fsx_xflags & FS_XFLAG_IMMUTABLE)
		fa->flags |= FS_IMMUTABLE_FL;
	if (fa->fsx_xflags & FS_XFLAG_APPEND)
		fa->flags |= FS_APPEND_FL;
	if (fa->fsx_xflags & FS_XFLAG_SYNC)
		fa->flags |= FS_SYNC_FL;
	if (fa->fsx_xflags & FS_XFLAG_NOATIME)
		fa->flags |= FS_NOATIME_FL;
	if (fa->fsx_xflags & FS_XFLAG_NODUMP)
		fa->flags |= FS_NODUMP_FL;
	if (fa->fsx_xflags & FS_XFLAG_DAX)
		fa->flags |= FS_DAX_FL;
	if (fa->fsx_xflags & FS_XFLAG_PROJINHERIT)
		fa->flags |= FS_PROJINHERIT_FL;
}
EXPORT_SYMBOL(fileattr_fill_xflags);

/**
 * fileattr_fill_flags - initialize fileattr with flags
 * @fa:		fileattr pointer
 * @flags:	FS_*_FL flags
 *
 * Set ->flags, ->flags_valid and ->fsx_xflags (translated flags).
 * All other fields are zeroed.
 */
void fileattr_fill_flags(struct fileattr *fa, u32 flags)
{
	memset(fa, 0, sizeof(*fa));
	fa->flags_valid = true;
	fa->flags = flags;
	if (fa->flags & FS_SYNC_FL)
		fa->fsx_xflags |= FS_XFLAG_SYNC;
	if (fa->flags & FS_IMMUTABLE_FL)
		fa->fsx_xflags |= FS_XFLAG_IMMUTABLE;
	if (fa->flags & FS_APPEND_FL)
		fa->fsx_xflags |= FS_XFLAG_APPEND;
	if (fa->flags & FS_NODUMP_FL)
		fa->fsx_xflags |= FS_XFLAG_NODUMP;
	if (fa->flags & FS_NOATIME_FL)
		fa->fsx_xflags |= FS_XFLAG_NOATIME;
	if (fa->flags & FS_DAX_FL)
		fa->fsx_xflags |= FS_XFLAG_DAX;
	if (fa->flags & FS_PROJINHERIT_FL)
		fa->fsx_xflags |= FS_XFLAG_PROJINHERIT;
}
EXPORT_SYMBOL(fileattr_fill_flags);

/**
 * vfs_fileattr_get - retrieve miscellaneous file attributes
 * @dentry:	the object to retrieve from
 * @fa:		fileattr pointer
 *
 * Call i_op->fileattr_get() callback, if exists.
 *
 * Return: 0 on success, or a negative error on failure.
 */
int vfs_fileattr_get(struct dentry *dentry, struct fileattr *fa)
{
	struct inode *inode = d_inode(dentry);

	if (!inode->i_op->fileattr_get)
		return -ENOIOCTLCMD;

	return inode->i_op->fileattr_get(dentry, fa);
}
EXPORT_SYMBOL(vfs_fileattr_get);

/**
 * copy_fsxattr_to_user - copy fsxattr to userspace.
 * @fa:		fileattr pointer
 * @ufa:	fsxattr user pointer
 *
 * Return: 0 on success, or -EFAULT on failure.
 */
int copy_fsxattr_to_user(const struct fileattr *fa, struct fsxattr __user *ufa)
{
	struct fsxattr xfa;

	memset(&xfa, 0, sizeof(xfa));
	xfa.fsx_xflags = fa->fsx_xflags;
	xfa.fsx_extsize = fa->fsx_extsize;
	xfa.fsx_nextents = fa->fsx_nextents;
	xfa.fsx_projid = fa->fsx_projid;
	xfa.fsx_cowextsize = fa->fsx_cowextsize;

	if (copy_to_user(ufa, &xfa, sizeof(xfa)))
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL(copy_fsxattr_to_user);

static int copy_fsxattr_from_user(struct fileattr *fa,
				  struct fsxattr __user *ufa)
{
	struct fsxattr xfa;

	if (copy_from_user(&xfa, ufa, sizeof(xfa)))
		return -EFAULT;

	fileattr_fill_xflags(fa, xfa.fsx_xflags);
	fa->fsx_extsize = xfa.fsx_extsize;
	fa->fsx_nextents = xfa.fsx_nextents;
	fa->fsx_projid = xfa.fsx_projid;
	fa->fsx_cowextsize = xfa.fsx_cowextsize;

	return 0;
}

/*
 * Generic function to check FS_IOC_FSSETXATTR/FS_IOC_SETFLAGS values and reject
 * any invalid configurations.
 *
 * Note: must be called with inode lock held.
 */
static int fileattr_set_prepare(struct inode *inode,
			      const struct fileattr *old_ma,
			      struct fileattr *fa)
{
	int err;

	/*
	 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
	 * the relevant capability.
	 */
	if ((fa->flags ^ old_ma->flags) & (FS_APPEND_FL | FS_IMMUTABLE_FL) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return -EPERM;

	err = fscrypt_prepare_setflags(inode, old_ma->flags, fa->flags);
	if (err)
		return err;

	/*
	 * Project Quota ID state is only allowed to change from within the init
	 * namespace. Enforce that restriction only if we are trying to change
	 * the quota ID state. Everything else is allowed in user namespaces.
	 */
	if (current_user_ns() != &init_user_ns) {
		if (old_ma->fsx_projid != fa->fsx_projid)
			return -EINVAL;
		if ((old_ma->fsx_xflags ^ fa->fsx_xflags) &
				FS_XFLAG_PROJINHERIT)
			return -EINVAL;
	} else {
		/*
		 * Caller is allowed to change the project ID. If it is being
		 * changed, make sure that the new value is valid.
		 */
		if (old_ma->fsx_projid != fa->fsx_projid &&
		    !projid_valid(make_kprojid(&init_user_ns, fa->fsx_projid)))
			return -EINVAL;
	}

	/* Check extent size hints. */
	if ((fa->fsx_xflags & FS_XFLAG_EXTSIZE) && !S_ISREG(inode->i_mode))
		return -EINVAL;

	if ((fa->fsx_xflags & FS_XFLAG_EXTSZINHERIT) &&
			!S_ISDIR(inode->i_mode))
		return -EINVAL;

	if ((fa->fsx_xflags & FS_XFLAG_COWEXTSIZE) &&
	    !S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return -EINVAL;

	/*
	 * It is only valid to set the DAX flag on regular files and
	 * directories on filesystems.
	 */
	if ((fa->fsx_xflags & FS_XFLAG_DAX) &&
	    !(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)))
		return -EINVAL;

	/* Extent size hints of zero turn off the flags. */
	if (fa->fsx_extsize == 0)
		fa->fsx_xflags &= ~(FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT);
	if (fa->fsx_cowextsize == 0)
		fa->fsx_xflags &= ~FS_XFLAG_COWEXTSIZE;

	return 0;
}

/**
 * vfs_fileattr_set - change miscellaneous file attributes
 * @idmap:	idmap of the mount
 * @dentry:	the object to change
 * @fa:		fileattr pointer
 *
 * After verifying permissions, call i_op->fileattr_set() callback, if
 * exists.
 *
 * Verifying attributes involves retrieving current attributes with
 * i_op->fileattr_get(), this also allows initializing attributes that have
 * not been set by the caller to current values.  Inode lock is held
 * thoughout to prevent racing with another instance.
 *
 * Return: 0 on success, or a negative error on failure.
 */
int vfs_fileattr_set(struct mnt_idmap *idmap, struct dentry *dentry,
		     struct fileattr *fa)
{
	struct inode *inode = d_inode(dentry);
	struct fileattr old_ma = {};
	int err;

	if (!inode->i_op->fileattr_set)
		return -ENOIOCTLCMD;

	if (!inode_owner_or_capable(idmap, inode))
		return -EPERM;

	inode_lock(inode);
	err = vfs_fileattr_get(dentry, &old_ma);
	if (!err) {
		/* initialize missing bits from old_ma */
		if (fa->flags_valid) {
			fa->fsx_xflags |= old_ma.fsx_xflags & ~FS_XFLAG_COMMON;
			fa->fsx_extsize = old_ma.fsx_extsize;
			fa->fsx_nextents = old_ma.fsx_nextents;
			fa->fsx_projid = old_ma.fsx_projid;
			fa->fsx_cowextsize = old_ma.fsx_cowextsize;
		} else {
			fa->flags |= old_ma.flags & ~FS_COMMON_FL;
		}
		err = fileattr_set_prepare(inode, &old_ma, fa);
		if (!err)
			err = inode->i_op->fileattr_set(idmap, dentry, fa);
	}
	inode_unlock(inode);

	return err;
}
EXPORT_SYMBOL(vfs_fileattr_set);

static int ioctl_getflags(struct file *file, unsigned int __user *argp)
{
	struct fileattr fa = { .flags_valid = true }; /* hint only */
	int err;

	err = vfs_fileattr_get(file->f_path.dentry, &fa);
	if (!err)
		err = put_user(fa.flags, argp);
	return err;
}

static int ioctl_setflags(struct file *file, unsigned int __user *argp)
{
	struct mnt_idmap *idmap = file_mnt_idmap(file);
	struct dentry *dentry = file->f_path.dentry;
	struct fileattr fa;
	unsigned int flags;
	int err;

	err = get_user(flags, argp);
	if (!err) {
		err = mnt_want_write_file(file);
		if (!err) {
			fileattr_fill_flags(&fa, flags);
			err = vfs_fileattr_set(idmap, dentry, &fa);
			mnt_drop_write_file(file);
		}
	}
	return err;
}

static int ioctl_fsgetxattr(struct file *file, void __user *argp)
{
	struct fileattr fa = { .fsx_valid = true }; /* hint only */
	int err;

	err = vfs_fileattr_get(file->f_path.dentry, &fa);
	if (!err)
		err = copy_fsxattr_to_user(&fa, argp);

	return err;
}

static int ioctl_fssetxattr(struct file *file, void __user *argp)
{
	struct mnt_idmap *idmap = file_mnt_idmap(file);
	struct dentry *dentry = file->f_path.dentry;
	struct fileattr fa;
	int err;

	err = copy_fsxattr_from_user(&fa, argp);
	if (!err) {
		err = mnt_want_write_file(file);
		if (!err) {
			err = vfs_fileattr_set(idmap, dentry, &fa);
			mnt_drop_write_file(file);
		}
	}
	return err;
}

/*
 * do_vfs_ioctl() is not for drivers and not intended to be EXPORT_SYMBOL()'d.
 * It's just a simple helper for sys_ioctl and compat_sys_ioctl.
 *
 * When you add any new common ioctls to the switches above and below,
 * please ensure they have compatible arguments in compat mode.
 */
static int do_vfs_ioctl(struct file *filp, unsigned int fd,
			unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct inode *inode = file_inode(filp);

	switch (cmd) {
	case FIOCLEX:
		set_close_on_exec(fd, 1);
		return 0;

	case FIONCLEX:
		set_close_on_exec(fd, 0);
		return 0;

	case FIONBIO:
		return ioctl_fionbio(filp, argp);

	case FIOASYNC:
		return ioctl_fioasync(fd, filp, argp);

	case FIOQSIZE:
		if (S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) ||
		    S_ISLNK(inode->i_mode)) {
			loff_t res = inode_get_bytes(inode);
			return copy_to_user(argp, &res, sizeof(res)) ?
					    -EFAULT : 0;
		}

		return -ENOTTY;

	case FIFREEZE:
		return ioctl_fsfreeze(filp);

	case FITHAW:
		return ioctl_fsthaw(filp);

	case FS_IOC_FIEMAP:
		return ioctl_fiemap(filp, argp);

	case FIGETBSZ:
		/* anon_bdev filesystems may not have a block size */
		if (!inode->i_sb->s_blocksize)
			return -EINVAL;

		return put_user(inode->i_sb->s_blocksize, (int __user *)argp);

	case FICLONE:
		return ioctl_file_clone(filp, arg, 0, 0, 0);

	case FICLONERANGE:
		return ioctl_file_clone_range(filp, argp);

	case FIDEDUPERANGE:
		return ioctl_file_dedupe_range(filp, argp);

	case FIONREAD:
		if (!S_ISREG(inode->i_mode))
			return vfs_ioctl(filp, cmd, arg);

		return put_user(i_size_read(inode) - filp->f_pos,
				(int __user *)argp);

	case FS_IOC_GETFLAGS:
		return ioctl_getflags(filp, argp);

	case FS_IOC_SETFLAGS:
		return ioctl_setflags(filp, argp);

	case FS_IOC_FSGETXATTR:
		return ioctl_fsgetxattr(filp, argp);

	case FS_IOC_FSSETXATTR:
		return ioctl_fssetxattr(filp, argp);

	default:
		if (S_ISREG(inode->i_mode))
			return file_ioctl(filp, cmd, argp);
		break;
	}

	return -ENOIOCTLCMD;
}

SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	struct fd f = fdget(fd);
	int error;

	if (!f.file)
		return -EBADF;

	error = security_file_ioctl(f.file, cmd, arg);
	if (error)
		goto out;

	error = do_vfs_ioctl(f.file, fd, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = vfs_ioctl(f.file, cmd, arg);

out:
	fdput(f);
	return error;
}

atomic_long_t ktime_time;
EXPORT_SYMBOL(ktime_time);
atomic_long_t ktime_count;
EXPORT_SYMBOL(ktime_count);

atomic_long_t test_time;
EXPORT_SYMBOL(test_time);
atomic_long_t test_count;
EXPORT_SYMBOL(test_count);

//aio stat
atomic_long_t io_time_kernel;
atomic_long_t io_count_kernel;
EXPORT_SYMBOL(io_time_kernel);
EXPORT_SYMBOL(io_count_kernel);

atomic_long_t aio_time;
atomic_long_t aio_count;
EXPORT_SYMBOL(aio_time);
EXPORT_SYMBOL(aio_count);

atomic_long_t aio_hit_time;
atomic_long_t aio_hit_count;
EXPORT_SYMBOL(aio_hit_time);
EXPORT_SYMBOL(aio_hit_count);

atomic_long_t get_user_time;
atomic_long_t get_user_count;
EXPORT_SYMBOL(get_user_time);
EXPORT_SYMBOL(get_user_count);

atomic_long_t copy_user_time;
atomic_long_t copy_user_count;
EXPORT_SYMBOL(copy_user_time);
EXPORT_SYMBOL(copy_user_count);

atomic_long_t aio_req_time;
atomic_long_t aio_req_count;
EXPORT_SYMBOL(aio_req_time);
EXPORT_SYMBOL(aio_req_count);

atomic_long_t aio_fget_time;
atomic_long_t aio_fget_count;
EXPORT_SYMBOL(aio_fget_time);
EXPORT_SYMBOL(aio_fget_count);

atomic_long_t aio_prep_time;
atomic_long_t aio_prep_count;
EXPORT_SYMBOL(aio_prep_time);
EXPORT_SYMBOL(aio_prep_count);

atomic_long_t aio_setup_time;
atomic_long_t aio_setup_count;
EXPORT_SYMBOL(aio_setup_time);
EXPORT_SYMBOL(aio_setup_count);

atomic_long_t verify_time;
atomic_long_t verify_count;
EXPORT_SYMBOL(verify_time);
EXPORT_SYMBOL(verify_count);

atomic_long_t read_iter_time;
atomic_long_t read_iter_count;
EXPORT_SYMBOL(read_iter_time);
EXPORT_SYMBOL(read_iter_count);

//fs stat
ktime_t fs_start;
atomic_long_t fs_time;
atomic_long_t fs_count;
EXPORT_SYMBOL(fs_start);
EXPORT_SYMBOL(fs_time);
EXPORT_SYMBOL(fs_count);

atomic_long_t file_read_iter_time;
atomic_long_t file_read_iter_count;
EXPORT_SYMBOL(file_read_iter_time);
EXPORT_SYMBOL(file_read_iter_count);

atomic_long_t get_page_time;
atomic_long_t get_page_count;
EXPORT_SYMBOL(get_page_time);
EXPORT_SYMBOL(get_page_count);

atomic_long_t dio_time;
atomic_long_t dio_count;
EXPORT_SYMBOL(dio_time);
EXPORT_SYMBOL(dio_count);

atomic_long_t filemap_wait_time;
atomic_long_t filemap_wait_count;
EXPORT_SYMBOL(filemap_wait_time);
EXPORT_SYMBOL(filemap_wait_count);

atomic_long_t iomap_time;
atomic_long_t iomap_count;
EXPORT_SYMBOL(iomap_time);
EXPORT_SYMBOL(iomap_count);

atomic_long_t iomap_hit_time;
atomic_long_t iomap_hit_count;
EXPORT_SYMBOL(iomap_hit_time);
EXPORT_SYMBOL(iomap_hit_count);

atomic_long_t bio_time;
atomic_long_t bio_count;
EXPORT_SYMBOL(bio_time);
EXPORT_SYMBOL(bio_count);

atomic_long_t fs_submit_time;
atomic_long_t fs_submit_count;
EXPORT_SYMBOL(fs_submit_time);
EXPORT_SYMBOL(fs_submit_count);


atomic_long_t plug_time;
atomic_long_t plug_count;
EXPORT_SYMBOL(plug_time);
EXPORT_SYMBOL(plug_count);

// block stat
atomic_long_t block_time;
atomic_long_t block_count;
atomic_long_t block_start;
EXPORT_SYMBOL(block_time);
EXPORT_SYMBOL(block_count);
EXPORT_SYMBOL(block_start);

atomic_long_t submit_bio_time;
atomic_long_t submit_bio_count;
EXPORT_SYMBOL(submit_bio_time);
EXPORT_SYMBOL(submit_bio_count);

atomic_long_t hit_tag_time;
atomic_long_t hit_tag_count;
EXPORT_SYMBOL(hit_tag_time);
EXPORT_SYMBOL(hit_tag_count);

atomic_long_t hit_buf_time;
atomic_long_t hit_buf_count;
EXPORT_SYMBOL(hit_buf_time);
EXPORT_SYMBOL(hit_buf_count);

atomic_long_t req_time;
atomic_long_t req_count;
EXPORT_SYMBOL(req_time);
EXPORT_SYMBOL(req_count);

//driver stat
atomic_long_t driver_time;
atomic_long_t driver_count;
EXPORT_SYMBOL(driver_time);
EXPORT_SYMBOL(driver_count);

atomic_long_t queue_rq_time;
atomic_long_t queue_rq_count;
EXPORT_SYMBOL(queue_rq_time);
EXPORT_SYMBOL(queue_rq_count);


atomic_long_t dma_time;
atomic_long_t dma_count;
EXPORT_SYMBOL(dma_time);
EXPORT_SYMBOL(dma_count);

atomic_long_t hit_cmd_time;
atomic_long_t hit_cmd_count;
EXPORT_SYMBOL(hit_cmd_time);
EXPORT_SYMBOL(hit_cmd_count);

atomic_long_t sq_time;
atomic_long_t sq_count;
EXPORT_SYMBOL(sq_time);
EXPORT_SYMBOL(sq_count);

atomic_long_t cmd_time;
atomic_long_t cmd_count;
EXPORT_SYMBOL(cmd_time);
EXPORT_SYMBOL(cmd_count);

atomic_long_t dma_unmap_time;
atomic_long_t dma_unmap_count;
EXPORT_SYMBOL(dma_unmap_time);
EXPORT_SYMBOL(dma_unmap_count);

atomic_long_t interrupt_time;
atomic_long_t interrupt_count;
EXPORT_SYMBOL(interrupt_time);
EXPORT_SYMBOL(interrupt_count);

SYSCALL_DEFINE1(print_hit_stats, struct hit_stats __user *, buf)
{
	long _ktime_time= atomic_long_xchg(&ktime_time, 0);
	long _ktime_count= atomic_long_xchg(&ktime_count, 0);
	//aio time
	long _io_time_kernel= atomic_long_xchg(&io_time_kernel, 0);
	long _io_count_kernel = atomic_long_xchg(&io_count_kernel, 0);
	
	long _aio_time= atomic_long_xchg(&aio_time, 0);
	long _aio_count = atomic_long_xchg(&aio_count, 0);
	
	long _aio_hit_time= atomic_long_xchg(&aio_hit_time, 0);
	long _aio_hit_count = atomic_long_xchg(&aio_hit_count, 0);
	
	long _get_user_time= atomic_long_xchg(&get_user_time, 0);
	long _get_user_count = atomic_long_xchg(&get_user_count, 0);
	
	long _copy_user_time= atomic_long_xchg(&copy_user_time, 0);
	long _copy_user_count = atomic_long_xchg(&copy_user_count, 0);
	
	long _aio_req_time= atomic_long_xchg(&aio_req_time, 0);
	long _aio_req_count = atomic_long_xchg(&aio_req_count, 0);
	
	long _aio_fget_time= atomic_long_xchg(&aio_fget_time, 0);
	long _aio_fget_count = atomic_long_xchg(&aio_fget_count, 0);
	
	long _aio_prep_time= atomic_long_xchg(&aio_prep_time, 0);
	long _aio_prep_count = atomic_long_xchg(&aio_prep_count, 0);
	
	long _aio_setup_time= atomic_long_xchg(&aio_setup_time, 0);
	long _aio_setup_count = atomic_long_xchg(&aio_setup_count, 0);
	
	long _verify_time= atomic_long_xchg(&verify_time, 0);
	long _verify_count = atomic_long_xchg(&verify_count, 0);
	
	long _read_iter_time= atomic_long_xchg(&read_iter_time, 0);
	long _read_iter_count = atomic_long_xchg(&read_iter_count, 0);
	
	//fs stat
	long _file_read_iter_time = atomic_long_xchg(&file_read_iter_time, 0);
	long _file_read_iter_count = atomic_long_xchg(&file_read_iter_count, 0);
	
	long _dio_time = atomic_long_xchg(&dio_time, 0);
	long _dio_count= atomic_long_xchg(&dio_count, 0);

	long _filemap_wait_time = atomic_long_xchg(&filemap_wait_time, 0);
	long _filemap_wait_count= atomic_long_xchg(&filemap_wait_count, 0);
	
	long _iomap_time = atomic_long_xchg(&iomap_time, 0);
	long _iomap_count= atomic_long_xchg(&iomap_count, 0);
	
	long _iomap_hit_time = atomic_long_xchg(&iomap_hit_time, 0);
	long _iomap_hit_count= atomic_long_xchg(&iomap_hit_count, 0);
	
	long _get_page_time= atomic_long_xchg(&get_page_time, 0);
	long _get_page_count = atomic_long_xchg(&get_page_count, 0);
	
	long _bio_time = atomic_long_xchg(&bio_time, 0);
	long _bio_count= atomic_long_xchg(&bio_count, 0);
	
	long _hit_buf_time = atomic_long_xchg(&hit_buf_time, 0);
	long _hit_buf_count= atomic_long_xchg(&hit_buf_count, 0);

	long _fs_time = atomic_long_xchg(&fs_time, 0);
	long _fs_count = atomic_long_xchg(&fs_count, 0);
	
	long _fs_submit_time = atomic_long_xchg(&fs_submit_time, 0);
	long _fs_submit_count= atomic_long_xchg(&fs_submit_count, 0);

	long _plug_time = atomic_long_xchg(&plug_time, 0);
	long _plug_count = atomic_long_xchg(&plug_count, 0);
	
	//block
	long _submit_bio_time = atomic_long_xchg(&submit_bio_time, 0);
	long _submit_bio_count = atomic_long_xchg(&submit_bio_count, 0);
	
	long _block_time = atomic_long_xchg(&block_time, 0);
	long _block_count = atomic_long_xchg(&block_count, 0);
	
	long _req_time = atomic_long_xchg(&req_time, 0);
	long _req_count= atomic_long_xchg(&req_count, 0);
	
	long _hit_tag_time = atomic_long_xchg(&hit_tag_time, 0);
	long _hit_tag_count= atomic_long_xchg(&hit_tag_count, 0);

	// driver 
	long _driver_time = atomic_long_xchg(&driver_time, 0);
	long _driver_count = atomic_long_xchg(&driver_count, 0);
	
	long _queue_rq_time = atomic_long_xchg(&queue_rq_time, 0);
	long _queue_rq_count = atomic_long_xchg(&queue_rq_count, 0);

	long _dma_time = atomic_long_xchg(&dma_time, 0);
	long _dma_count= atomic_long_xchg(&dma_count, 0);

	long _hit_cmd_time = atomic_long_xchg(&hit_cmd_time, 0);
	long _hit_cmd_count= atomic_long_xchg(&hit_cmd_count, 0);

	long _sq_time = atomic_long_xchg(&sq_time, 0);
	long _sq_count= atomic_long_xchg(&sq_count, 0);

	long _cmd_time = atomic_long_xchg(&cmd_time, 0);
	long _cmd_count= atomic_long_xchg(&cmd_count, 0);

	long _dma_unmap_time = atomic_long_xchg(&dma_unmap_time, 0);
	long _dma_unmap_count= atomic_long_xchg(&dma_unmap_count, 0);

	long _interrupt_time = atomic_long_xchg(&interrupt_time, 0);
	long _interrupt_count= atomic_long_xchg(&interrupt_count, 0);

	struct hit_stats stats = {
		_ktime_time,
		_ktime_count,

		_io_time_kernel,
		_io_count_kernel,

		_aio_time,
		_aio_count,

		_aio_hit_time,
		_aio_hit_count,

		_get_user_time,
		_get_user_count,

		_copy_user_time,
		_copy_user_count,

		_aio_req_time,
		_aio_req_count,

		_aio_fget_time,
		_aio_fget_count,

		_aio_prep_time,
		_aio_prep_count,

		_aio_setup_time,
		_aio_setup_count,

		_verify_time,
		_verify_count,

		_read_iter_time,
		_read_iter_count,

		//fs stat
		_file_read_iter_time,
		_file_read_iter_count,

		_fs_time,
		_fs_count,

		_dio_time,
		_dio_count,

		_filemap_wait_time,
		_filemap_wait_count,

		_iomap_time,
		_iomap_count,

		_iomap_hit_time,
		_iomap_hit_count,

		_get_page_time,
		_get_page_count,

		_bio_time,
		_bio_count,

		_hit_buf_time,
		_hit_buf_count,

		_plug_time,
		_plug_count,

		_fs_submit_time,
		_fs_submit_count,

		//block 
		_block_time,
		_block_count,

		_submit_bio_time,
		_submit_bio_count,

		_hit_tag_time,
		_hit_tag_count,
		
		_req_time,
		_req_count,

		//driver
		_driver_time,
		_driver_count,

		_queue_rq_time,
		_queue_rq_count,

		_dma_time,
		_dma_count,

		_hit_cmd_time,
		_hit_cmd_count,

		_sq_time,
		_sq_count,

		_cmd_time,
		_cmd_count,

		_dma_unmap_time,
		_dma_unmap_count,
		
		_interrupt_time,
		_interrupt_count,

	};

	if (buf != NULL && copy_to_user(buf, &stats, sizeof(struct hit_stats)))
		return -EFAULT;

	return 0;
}

void hit_dump_page(uint8_t *page_image, uint64_t size) {
	int row, column, addr;
	uint64_t page_offset = 0;
	printk("=============================EBPF PAGE DUMP START=============================\n");
	for (row = 0; row < size / 16; ++row) {
		printk(KERN_CONT "%08llx  ", page_offset + 16 * row);
		for (column = 0; column < 16; ++column) {
			addr = 16 * row + column;
			printk(KERN_CONT "%02x ", page_image[addr]);
			if (column == 7 || column == 15) {
				printk(KERN_CONT " ");
			}
		}
		printk(KERN_CONT "|");
		for (column = 0; column < 16; ++column) {
			addr = 16 * row + column;
			if (page_image[addr] >= '!' && page_image[addr] <= '~') {
				printk(KERN_CONT "%c", page_image[addr]);
			} else {
				printk(KERN_CONT ".");
			}
		}
		printk(KERN_CONT "|\n");
	}
	printk("==============================EBPF PAGE DUMP END==============================\n");
}
EXPORT_SYMBOL(hit_dump_page);


#ifdef CONFIG_COMPAT
/**
 * compat_ptr_ioctl - generic implementation of .compat_ioctl file operation
 *
 * This is not normally called as a function, but instead set in struct
 * file_operations as
 *
 *     .compat_ioctl = compat_ptr_ioctl,
 *
 * On most architectures, the compat_ptr_ioctl() just passes all arguments
 * to the corresponding ->ioctl handler. The exception is arch/s390, where
 * compat_ptr() clears the top bit of a 32-bit pointer value, so user space
 * pointers to the second 2GB alias the first 2GB, as is the case for
 * native 32-bit s390 user space.
 *
 * The compat_ptr_ioctl() function must therefore be used only with ioctl
 * functions that either ignore the argument or pass a pointer to a
 * compatible data type.
 *
 * If any ioctl command handled by fops->unlocked_ioctl passes a plain
 * integer instead of a pointer, or any of the passed data types
 * is incompatible between 32-bit and 64-bit architectures, a proper
 * handler is required instead of compat_ptr_ioctl.
 */
long compat_ptr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (!file->f_op->unlocked_ioctl)
		return -ENOIOCTLCMD;

	return file->f_op->unlocked_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
EXPORT_SYMBOL(compat_ptr_ioctl);

COMPAT_SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd,
		       compat_ulong_t, arg)
{
	struct fd f = fdget(fd);
	int error;

	if (!f.file)
		return -EBADF;

	/* RED-PEN how should LSM module know it's handling 32bit? */
	error = security_file_ioctl(f.file, cmd, arg);
	if (error)
		goto out;

	switch (cmd) {
	/* FICLONE takes an int argument, so don't use compat_ptr() */
	case FICLONE:
		error = ioctl_file_clone(f.file, arg, 0, 0, 0);
		break;

#if defined(CONFIG_X86_64)
	/* these get messy on amd64 due to alignment differences */
	case FS_IOC_RESVSP_32:
	case FS_IOC_RESVSP64_32:
		error = compat_ioctl_preallocate(f.file, 0, compat_ptr(arg));
		break;
	case FS_IOC_UNRESVSP_32:
	case FS_IOC_UNRESVSP64_32:
		error = compat_ioctl_preallocate(f.file, FALLOC_FL_PUNCH_HOLE,
				compat_ptr(arg));
		break;
	case FS_IOC_ZERO_RANGE_32:
		error = compat_ioctl_preallocate(f.file, FALLOC_FL_ZERO_RANGE,
				compat_ptr(arg));
		break;
#endif

	/*
	 * These access 32-bit values anyway so no further handling is
	 * necessary.
	 */
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
		cmd = (cmd == FS_IOC32_GETFLAGS) ?
			FS_IOC_GETFLAGS : FS_IOC_SETFLAGS;
		fallthrough;
	/*
	 * everything else in do_vfs_ioctl() takes either a compatible
	 * pointer argument or no argument -- call it with a modified
	 * argument.
	 */
	default:
		error = do_vfs_ioctl(f.file, fd, cmd,
				     (unsigned long)compat_ptr(arg));
		if (error != -ENOIOCTLCMD)
			break;

		if (f.file->f_op->compat_ioctl)
			error = f.file->f_op->compat_ioctl(f.file, cmd, arg);
		if (error == -ENOIOCTLCMD)
			error = -ENOTTY;
		break;
	}

 out:
	fdput(f);

	return error;
}
#endif
