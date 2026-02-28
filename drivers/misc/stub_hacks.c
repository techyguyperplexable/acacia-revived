#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/platform_device.h>

static unsigned int dummy_sched_busy_hyst_ns = 0;
static unsigned int dummy_sched_boost = 0;
static unsigned int dummy_sched_upmigrate = 0;
static unsigned int dummy_sched_downmigrate = 0;
static unsigned int dummy_sched_group_upmigrate = 0;
static unsigned int dummy_sched_group_downmigrate = 0;
static unsigned int dummy_sched_min_task_util_for_boost = 0;
static unsigned int dummy_sched_min_task_util_for_colocation = 0;

static struct class *dummy_input_booster_class;
static struct device *dummy_touch_dev;

static ssize_t dummy_show(struct device *dev, struct device_attribute *attr, char *buf) { return sprintf(buf, "0\n"); }
static ssize_t dummy_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) { return count; }
static DEVICE_ATTR(head, 0644, dummy_show, dummy_store);

static struct ctl_table dummy_kern_table[] = {
       {
               .procname       = "sched_busy_hyst_ns",
               .data           = &dummy_sched_busy_hyst_ns,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       {
               .procname       = "sched_boost",
               .data           = &dummy_sched_boost,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       {
               .procname       = "sched_upmigrate",
               .data           = &dummy_sched_upmigrate,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       {
               .procname       = "sched_downmigrate",
               .data           = &dummy_sched_downmigrate,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       {
               .procname       = "sched_group_upmigrate",
               .data           = &dummy_sched_group_upmigrate,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       {
               .procname       = "sched_group_downmigrate",
               .data           = &dummy_sched_group_downmigrate,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       {
               .procname       = "sched_min_task_util_for_boost",
               .data           = &dummy_sched_min_task_util_for_boost,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       {
               .procname       = "sched_min_task_util_for_colocation",
               .data           = &dummy_sched_min_task_util_for_colocation,
               .maxlen         = sizeof(unsigned int),
               .mode           = 0644,
               .proc_handler   = proc_dointvec,
       },
       { }
};

static struct ctl_table dummy_root_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= dummy_kern_table,
	},
	{ }
};

static struct ctl_table_header *dummy_sysctl_header;

static int __init stub_hacks_init(void)
{
       pr_info("Loading stub hacks for sched variables and input_booster\n");
       dummy_sysctl_header = register_sysctl_table(dummy_root_table);

       dummy_input_booster_class = class_create(THIS_MODULE, "input_booster");
       if (!IS_ERR(dummy_input_booster_class)) {
           dummy_touch_dev = device_create(dummy_input_booster_class, NULL, 0, NULL, "touch");
           if (!IS_ERR(dummy_touch_dev)) {
               device_create_file(dummy_touch_dev, &dev_attr_head);
           }
       }

       return 0;
}

static void __exit stub_hacks_exit(void)
{
       if (dummy_touch_dev && !IS_ERR(dummy_touch_dev)) {
               device_remove_file(dummy_touch_dev, &dev_attr_head);
               device_destroy(dummy_input_booster_class, 0);
       }
       if (dummy_input_booster_class && !IS_ERR(dummy_input_booster_class)) {
               class_destroy(dummy_input_booster_class);
       }
       if (dummy_sysctl_header)
               unregister_sysctl_table(dummy_sysctl_header);
}
module_init(stub_hacks_init);
module_exit(stub_hacks_exit);
MODULE_LICENSE("GPL");
