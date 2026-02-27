#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/platform_device.h>
#include <linux/devfreq.h>

#include <linux/pm_opp.h>

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
static DEVICE_ATTR(min_freq, 0644, dummy_show, dummy_store);
static DEVICE_ATTR(max_freq, 0644, dummy_show, dummy_store);

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

static int stub_target(struct device *dev, unsigned long *freq, u32 flags)
{
	return 0;
}

static int stub_get_dev_status(struct device *dev, struct devfreq_dev_status *stat)
{
	stat->current_frequency = 0;
	stat->busy_time = 0;
	stat->total_time = 100;
	return 0;
}

static struct devfreq_dev_profile dummy_profile = {
	.initial_freq = 0,
	.polling_ms = 0,
	.target = stub_target,
	.get_dev_status = stub_get_dev_status,
};

static struct platform_device *pdev_cpu0;
static struct platform_device *pdev_cpu4;
static struct platform_device *pdev_cpu6;
static struct platform_device *pdev_cpu7;

static struct devfreq *df_cpu0;
static struct devfreq *df_cpu4;
static struct devfreq *df_cpu6;
static struct devfreq *df_cpu7;

static struct platform_device *pdev_l3_0;
static struct platform_device *pdev_l3_4;
static struct platform_device *pdev_l3_6;
static struct platform_device *pdev_l3_7;
static struct devfreq *df_l3_0;
static struct devfreq *df_l3_4;
static struct devfreq *df_l3_6;
static struct devfreq *df_l3_7;

static struct platform_device *pdev_llcc_0;
static struct platform_device *pdev_llcc_4;
static struct platform_device *pdev_llcc_6;
static struct platform_device *pdev_llcc_7;
static struct devfreq *df_llcc_0;
static struct devfreq *df_llcc_4;
static struct devfreq *df_llcc_6;
static struct devfreq *df_llcc_7;

static struct devfreq *register_dummy_devfreq(const char *name, struct platform_device **pdev_out)
{
       struct platform_device *pdev;
       struct devfreq *df;

       pdev = platform_device_register_simple(name, -1, NULL, 0);
       if (IS_ERR(pdev))
               return ERR_CAST(pdev);

       dev_pm_opp_add(&pdev->dev, 0, 0);
       dev_pm_opp_add(&pdev->dev, 1000000, 0);

       df = devfreq_add_device(&pdev->dev, &dummy_profile, "performance", NULL);
       if (IS_ERR(df)) {
               platform_device_unregister(pdev);
               return df;
       }
       
       device_create_file(&df->dev, &dev_attr_min_freq);
       device_create_file(&df->dev, &dev_attr_max_freq);

       *pdev_out = pdev;
       return df;
}

static int __init stub_hacks_init(void)
{
       pr_info("Loading stub hacks for sched_busy_hyst_ns and cpu-ddr-latfloor\n");
       dummy_sysctl_header = register_sysctl_table(dummy_root_table);

       dummy_input_booster_class = class_create(THIS_MODULE, "input_booster");
       if (!IS_ERR(dummy_input_booster_class)) {
           dummy_touch_dev = device_create(dummy_input_booster_class, NULL, 0, NULL, "touch");
           if (!IS_ERR(dummy_touch_dev)) {
               device_create_file(dummy_touch_dev, &dev_attr_head);
           }
       }

       df_cpu0 = register_dummy_devfreq("soc:qcom,cpu0-cpu-ddr-latfloor", &pdev_cpu0);
       df_cpu4 = register_dummy_devfreq("soc:qcom,cpu4-cpu-ddr-latfloor", &pdev_cpu4);
       df_cpu6 = register_dummy_devfreq("soc:qcom,cpu6-cpu-ddr-latfloor", &pdev_cpu6);
       df_cpu7 = register_dummy_devfreq("soc:qcom,cpu7-cpu-ddr-latfloor", &pdev_cpu7);

       df_l3_0 = register_dummy_devfreq("soc:qcom,cpu0-cpu-l3-lat", &pdev_l3_0);
       df_l3_4 = register_dummy_devfreq("soc:qcom,cpu4-cpu-l3-lat", &pdev_l3_4);
       df_l3_6 = register_dummy_devfreq("soc:qcom,cpu6-cpu-l3-lat", &pdev_l3_6);
       df_l3_7 = register_dummy_devfreq("soc:qcom,cpu7-cpu-l3-lat", &pdev_l3_7);

       df_llcc_0 = register_dummy_devfreq("soc:qcom,cpu0-llcc-lat", &pdev_llcc_0);
       df_llcc_4 = register_dummy_devfreq("soc:qcom,cpu4-llcc-lat", &pdev_llcc_4);
       df_llcc_6 = register_dummy_devfreq("soc:qcom,cpu6-llcc-lat", &pdev_llcc_6);
       df_llcc_7 = register_dummy_devfreq("soc:qcom,cpu7-llcc-lat", &pdev_llcc_7);

       return 0;
}

static void __exit stub_hacks_exit(void)
{
       if (df_llcc_7 && !IS_ERR(df_llcc_7)) devfreq_remove_device(df_llcc_7);
       if (pdev_llcc_7 && !IS_ERR(pdev_llcc_7)) platform_device_unregister(pdev_llcc_7);
       if (df_llcc_6 && !IS_ERR(df_llcc_6)) devfreq_remove_device(df_llcc_6);
       if (pdev_llcc_6 && !IS_ERR(pdev_llcc_6)) platform_device_unregister(pdev_llcc_6);
       if (df_llcc_4 && !IS_ERR(df_llcc_4)) devfreq_remove_device(df_llcc_4);
       if (pdev_llcc_4 && !IS_ERR(pdev_llcc_4)) platform_device_unregister(pdev_llcc_4);
       if (df_llcc_0 && !IS_ERR(df_llcc_0)) devfreq_remove_device(df_llcc_0);
       if (pdev_llcc_0 && !IS_ERR(pdev_llcc_0)) platform_device_unregister(pdev_llcc_0);

       if (df_l3_7 && !IS_ERR(df_l3_7)) devfreq_remove_device(df_l3_7);
       if (pdev_l3_7 && !IS_ERR(pdev_l3_7)) platform_device_unregister(pdev_l3_7);
       if (df_l3_6 && !IS_ERR(df_l3_6)) devfreq_remove_device(df_l3_6);
       if (pdev_l3_6 && !IS_ERR(pdev_l3_6)) platform_device_unregister(pdev_l3_6);
       if (df_l3_4 && !IS_ERR(df_l3_4)) devfreq_remove_device(df_l3_4);
       if (pdev_l3_4 && !IS_ERR(pdev_l3_4)) platform_device_unregister(pdev_l3_4);
       if (df_l3_0 && !IS_ERR(df_l3_0)) devfreq_remove_device(df_l3_0);
       if (pdev_l3_0 && !IS_ERR(pdev_l3_0)) platform_device_unregister(pdev_l3_0);

       if (df_cpu7 && !IS_ERR(df_cpu7)) devfreq_remove_device(df_cpu7);
       if (pdev_cpu7 && !IS_ERR(pdev_cpu7)) platform_device_unregister(pdev_cpu7);
       if (df_cpu6 && !IS_ERR(df_cpu6)) devfreq_remove_device(df_cpu6);
       if (pdev_cpu6 && !IS_ERR(pdev_cpu6)) platform_device_unregister(pdev_cpu6);
       if (df_cpu4 && !IS_ERR(df_cpu4)) devfreq_remove_device(df_cpu4);
       if (pdev_cpu4 && !IS_ERR(pdev_cpu4)) platform_device_unregister(pdev_cpu4);
       if (df_cpu0 && !IS_ERR(df_cpu0)) devfreq_remove_device(df_cpu0);
       if (pdev_cpu0 && !IS_ERR(pdev_cpu0)) platform_device_unregister(pdev_cpu0);

       if (dummy_sysctl_header)
               unregister_sysctl_table(dummy_sysctl_header);
}
module_init(stub_hacks_init);
module_exit(stub_hacks_exit);
MODULE_LICENSE("GPL");
