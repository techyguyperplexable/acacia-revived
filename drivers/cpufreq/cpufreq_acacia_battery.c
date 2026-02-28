// SPDX-License-Identifier: GPL-2.0
/*
 * CPUFreq governor: acacia-battery
 *
 * Locks CPU frequency to the policy minimum with cached frequency
 * tracking to avoid redundant driver calls.
 *
 * Copyright (C) 2024 techyguyperplexable
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

struct acacia_battery_data {
	unsigned int cached_min;
};

static int cpufreq_gov_acacia_battery_init(struct cpufreq_policy *policy)
{
	struct acacia_battery_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->cached_min = policy->min;
	policy->governor_data = data;

	return 0;
}

static void cpufreq_gov_acacia_battery_exit(struct cpufreq_policy *policy)
{
	kfree(policy->governor_data);
	policy->governor_data = NULL;
}

static int cpufreq_gov_acacia_battery_start(struct cpufreq_policy *policy)
{
	struct acacia_battery_data *data = policy->governor_data;

	data->cached_min = policy->min;

	pr_debug("setting policy%u to %u kHz\n", policy->cpu, policy->min);
	__cpufreq_driver_target(policy, policy->min, CPUFREQ_RELATION_L);
	return 0;
}

static void cpufreq_gov_acacia_battery_limits(struct cpufreq_policy *policy)
{
	struct acacia_battery_data *data = policy->governor_data;
	unsigned int target = policy->min;

	if (likely(target == data->cached_min && policy->cur == target))
		return;

	data->cached_min = target;

	pr_debug("updating policy%u to %u kHz\n", policy->cpu, target);
	__cpufreq_driver_target(policy, target, CPUFREQ_RELATION_L);
}

static struct cpufreq_governor cpufreq_gov_acacia_battery = {
	.name		= "acacia-battery",
	.init		= cpufreq_gov_acacia_battery_init,
	.exit		= cpufreq_gov_acacia_battery_exit,
	.start		= cpufreq_gov_acacia_battery_start,
	.limits		= cpufreq_gov_acacia_battery_limits,
	.owner		= THIS_MODULE,
};

static int __init cpufreq_gov_acacia_battery_register(void)
{
	return cpufreq_register_governor(&cpufreq_gov_acacia_battery);
}

static void __exit cpufreq_gov_acacia_battery_unregister(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_acacia_battery);
}

MODULE_AUTHOR("techyguyperplexable <objecting@objecting.org>");
MODULE_DESCRIPTION("Acacia Battery Governor - Minimum frequency for maximum battery life");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ACACIA_BATTERY
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return &cpufreq_gov_acacia_battery;
}
#endif

core_initcall(cpufreq_gov_acacia_battery_register);
module_exit(cpufreq_gov_acacia_battery_unregister);
