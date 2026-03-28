#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/sched/signal.h>
#include <uapi/linux/io_acacia.h>

struct io_sq_ring {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 flags;
	u32 dropped;
	u32 array[];
};

struct io_cq_ring {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 overflow;
	struct io_acacia_cqe cqes[];
};

struct io_ring_ctx {
	struct io_sq_ring *sq_ring;
	struct io_cq_ring *cq_ring;
	struct io_acacia_sqe *sqes;
	
	size_t sq_ring_sz;
	size_t cq_ring_sz;
	size_t sqes_sz;
	
	u32 sq_entries;
	u32 cq_entries;
	
	spinlock_t cq_lock;
	wait_queue_head_t wait;
	
	u32 cached_sq_head;
	u32 cached_cq_tail;
};

struct io_acacia_work {
	struct work_struct work;
	struct io_ring_ctx *ctx;
	struct io_acacia_sqe sqe;
};

static void *io_mem_alloc(size_t size)
{
	return (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(size));
}

static void io_mem_free(void *ptr, size_t size)
{
	if (ptr)
		free_pages((unsigned long)ptr, get_order(size));
}

static int io_acacia_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct io_ring_ctx *ctx = file->private_data;
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	void *ptr;
	unsigned long pfn;

	if (offset == IORING_OFF_SQ_RING) {
		ptr = ctx->sq_ring;
		if (size > ctx->sq_ring_sz) return -EINVAL;
	} else if (offset == IORING_OFF_CQ_RING) {
		ptr = ctx->cq_ring;
		if (size > ctx->cq_ring_sz) return -EINVAL;
	} else if (offset == IORING_OFF_SQES) {
		ptr = ctx->sqes;
		if (size > ctx->sqes_sz) return -EINVAL;
	} else {
		return -EINVAL;
	}

	pfn = virt_to_phys(ptr) >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static int io_acacia_release(struct inode *inode, struct file *file)
{
	struct io_ring_ctx *ctx = file->private_data;
	
	io_mem_free(ctx->sq_ring, ctx->sq_ring_sz);
	io_mem_free(ctx->cq_ring, ctx->cq_ring_sz);
	io_mem_free(ctx->sqes, ctx->sqes_sz);
	kfree(ctx);
	
	return 0;
}

static const struct file_operations io_acacia_fops = {
	.mmap = io_acacia_mmap,
	.release = io_acacia_release,
};

static void io_acacia_cqring_fill_event(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 flags)
{
	struct io_cq_ring *ring = ctx->cq_ring;
	u32 tail, mask = ctx->cq_entries - 1;
	struct io_acacia_cqe *cqe;

	spin_lock(&ctx->cq_lock);
	tail = ctx->cached_cq_tail;
	
	cqe = &ring->cqes[tail & mask];
	cqe->user_data = user_data;
	cqe->res = res;
	cqe->flags = flags;
	
	ctx->cached_cq_tail++;
	/* ensure cqe is written before tail update */
	smp_store_release(&ring->tail, ctx->cached_cq_tail);
	spin_unlock(&ctx->cq_lock);
	
	wake_up_all(&ctx->wait);
}

static ssize_t io_acacia_read_write(struct io_acacia_sqe *sqe, int is_write)
{
	struct fd f = fdget(sqe->fd);
	struct file *file = f.file;
	ssize_t ret = -EBADF;
	void __user *buf = (void __user *)(unsigned long)sqe->addr;
	size_t len = sqe->len;
	loff_t pos = sqe->off;

	if (!file)
		return ret;

	if (is_write) {
		if (file->f_op->write)
			ret = file->f_op->write(file, buf, len, &pos);
		else if (file->f_op->write_iter) {
			struct iovec iov = { .iov_base = buf, .iov_len = len };
			struct iov_iter iter;
			struct kiocb kiocb;
			
			init_sync_kiocb(&kiocb, file);
			kiocb.ki_pos = pos;
			iov_iter_init(&iter, WRITE, &iov, 1, len);
			ret = file->f_op->write_iter(&kiocb, &iter);
		} else
			ret = -EINVAL;
	} else {
		if (file->f_op->read)
			ret = file->f_op->read(file, buf, len, &pos);
		else if (file->f_op->read_iter) {
			struct iovec iov = { .iov_base = buf, .iov_len = len };
			struct iov_iter iter;
			struct kiocb kiocb;
			
			init_sync_kiocb(&kiocb, file);
			kiocb.ki_pos = pos;
			iov_iter_init(&iter, READ, &iov, 1, len);
			ret = file->f_op->read_iter(&kiocb, &iter);
		} else
			ret = -EINVAL;
	}

	fdput(f);
	return ret;
}

static void io_acacia_worker(struct work_struct *work)
{
	struct io_acacia_work *iow = container_of(work, struct io_acacia_work, work);
	struct io_ring_ctx *ctx = iow->ctx;
	struct io_acacia_sqe *sqe = &iow->sqe;
	s32 res = -EINVAL;

	switch (sqe->opcode) {
	case IORING_OP_NOP:
		res = 0;
		break;
	case IORING_OP_READV:
	case IORING_OP_READ:
		res = io_acacia_read_write(sqe, 0);
		break;
	case IORING_OP_WRITEV:
	case IORING_OP_WRITE:
		res = io_acacia_read_write(sqe, 1);
		break;
	}

	io_acacia_cqring_fill_event(ctx, sqe->user_data, res, 0);
	kfree(iow);
}

SYSCALL_DEFINE2(io_acacia_setup, u32, entries,
		struct io_acacia_params __user *, params)
{
	struct io_acacia_params p;
	struct io_ring_ctx *ctx;
	int fd, ret;
	
	if (!entries || entries > 4096)
		return -EINVAL;
		
	if (copy_from_user(&p, params, sizeof(p)))
		return -EFAULT;
		
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
		
	ctx->sq_entries = entries;
	ctx->cq_entries = entries * 2; /* CQ is typically double SQ */
	
	spin_lock_init(&ctx->cq_lock);
	init_waitqueue_head(&ctx->wait);
	
	ctx->sq_ring_sz = PAGE_ALIGN(sizeof(struct io_sq_ring) + ctx->sq_entries * sizeof(u32));
	ctx->cq_ring_sz = PAGE_ALIGN(sizeof(struct io_cq_ring) + ctx->cq_entries * sizeof(struct io_acacia_cqe));
	ctx->sqes_sz = PAGE_ALIGN(ctx->sq_entries * sizeof(struct io_acacia_sqe));
	
	ctx->sq_ring = io_mem_alloc(ctx->sq_ring_sz);
	ctx->cq_ring = io_mem_alloc(ctx->cq_ring_sz);
	ctx->sqes = io_mem_alloc(ctx->sqes_sz);
	
	if (!ctx->sq_ring || !ctx->cq_ring || !ctx->sqes) {
		ret = -ENOMEM;
		goto err;
	}
	
	ctx->sq_ring->ring_mask = ctx->sq_entries - 1;
	ctx->sq_ring->ring_entries = ctx->sq_entries;
	ctx->cq_ring->ring_mask = ctx->cq_entries - 1;
	ctx->cq_ring->ring_entries = ctx->cq_entries;
	
	memset(&p, 0, sizeof(p));
	p.sq_entries = ctx->sq_entries;
	p.cq_entries = ctx->cq_entries;
	
	p.sq_off.head = offsetof(struct io_sq_ring, head);
	p.sq_off.tail = offsetof(struct io_sq_ring, tail);
	p.sq_off.ring_mask = offsetof(struct io_sq_ring, ring_mask);
	p.sq_off.ring_entries = offsetof(struct io_sq_ring, ring_entries);
	p.sq_off.flags = offsetof(struct io_sq_ring, flags);
	p.sq_off.dropped = offsetof(struct io_sq_ring, dropped);
	p.sq_off.array = offsetof(struct io_sq_ring, array);

	p.cq_off.head = offsetof(struct io_cq_ring, head);
	p.cq_off.tail = offsetof(struct io_cq_ring, tail);
	p.cq_off.ring_mask = offsetof(struct io_cq_ring, ring_mask);
	p.cq_off.ring_entries = offsetof(struct io_cq_ring, ring_entries);
	p.cq_off.overflow = offsetof(struct io_cq_ring, overflow);
	p.cq_off.cqes = offsetof(struct io_cq_ring, cqes);
	
	p.features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP;
	
	if (copy_to_user(params, &p, sizeof(p))) {
		ret = -EFAULT;
		goto err;
	}
	
	fd = anon_inode_getfd("[io_acacia]", &io_acacia_fops, ctx, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err;
	}
	
	return fd;

err:
	io_mem_free(ctx->sq_ring, ctx->sq_ring_sz);
	io_mem_free(ctx->cq_ring, ctx->cq_ring_sz);
	io_mem_free(ctx->sqes, ctx->sqes_sz);
	kfree(ctx);
	return ret;
}

SYSCALL_DEFINE6(io_acacia_enter, unsigned int, fd, u32, to_submit,
		u32, min_complete, u32, flags, const sigset_t __user *, sig,
		size_t, sigsz)
{
	struct fd f;
	struct io_ring_ctx *ctx;
	int submitted = 0;
	u32 head, tail, mask;
	
	f = fdget(fd);
	if (!f.file)
		return -EBADF;
		
	if (f.file->f_op != &io_acacia_fops) {
		fdput(f);
		return -EOPNOTSUPP;
	}
	
	ctx = f.file->private_data;
	
	mask = ctx->sq_entries - 1;
	
	/* read sq ring tail with smp_load_acquire */
	tail = smp_load_acquire(&ctx->sq_ring->tail);
	head = ctx->cached_sq_head;
	
	while (to_submit && head != tail) {
		u32 index = ctx->sq_ring->array[head & mask];
		struct io_acacia_sqe *sqe;
		struct io_acacia_work *iow;
		
		if (index >= ctx->sq_entries) {
			head++;
			continue;
		}
		
		sqe = &ctx->sqes[index];
		
		iow = kmalloc(sizeof(*iow), GFP_KERNEL);
		if (!iow) {
			io_acacia_cqring_fill_event(ctx, sqe->user_data, -ENOMEM, 0);
			head++;
			to_submit--;
			continue;
		}
		iow->ctx = ctx;
		memcpy(&iow->sqe, sqe, sizeof(struct io_acacia_sqe));
		INIT_WORK(&iow->work, io_acacia_worker);
		schedule_work(&iow->work);
		submitted++;

		head++;
		to_submit--;
	}
	
	if (submitted) {
		ctx->cached_sq_head = head;
		smp_store_release(&ctx->sq_ring->head, head);
	}
	
	if (min_complete) {
		wait_event_interruptible(ctx->wait, 
			(ctx->cached_cq_tail - smp_load_acquire(&ctx->cq_ring->head)) >= min_complete);
	}
	
	fdput(f);
	return submitted;
}

SYSCALL_DEFINE4(io_acacia_register, unsigned int, fd, unsigned int, opcode,
		void __user *, arg, u32, nr_args)
{
	return -ENOSYS;
}
