#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/platform_device.h>
#include <linux/devfreq.h>

static unsigned int dummy_sched_busy_hyst_ns = 0;

static struct ctl_table dummy_kern_table[] = {
	{
		.procname	= "sched_busy_hyst_ns",
		.data		= &dummy_sched_busy_hyst_ns,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
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

static int __init stub_hacks_init(void)
{
	pr_info("Loading stub hacks for sched_busy_hyst_ns and cpu-ddr-latfloor
");
	dummy_sysctl_header = register_sysctl_table(dummy_root_table);

	pdev_cpu0 = platform_device_register_simple("soc:qcom,cpu0-cpu-ddr-latfloor", -1, NULL, 0);
	if (!IS_ERR(pdev_cpu0))
		df_cpu0 = devfreq_add_device(&pdev_cpu0->dev, &dummy_profile, "performance", NULL);

	pdev_cpu4 = platform_device_register_simple("soc:qcom,cpu4-cpu-ddr-latfloor", -1, NULL, 0);
	if (!IS_ERR(pdev_cpu4))
		df_cpu4 = devfreq_add_device(&pdev_cpu4->dev, &dummy_profile, "performance", NULL);

	pdev_cpu6 = platform_device_register_simple("soc:qcom,cpu6-cpu-ddr-latfloor", -1, NULL, 0);
	if (!IS_ERR(pdev_cpu6))
		df_cpu6 = devfreq_add_device(&pdev_cpu6->dev, &dummy_profile, "performance", NULL);

	pdev_cpu7 = platform_device_register_simple("soc:qcom,cpu7-cpu-ddr-latfloor", -1, NULL, 0);
	if (!IS_ERR(pdev_cpu7))
		df_cpu7 = devfreq_add_device(&pdev_cpu7->dev, &dummy_profile, "performance", NULL);

	return 0;
}

static void __exit stub_hacks_exit(void)
{
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
