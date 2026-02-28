// SPDX-License-Identifier: GPL-2.0
/*
 * CPUFreq governor: acacia-perf
 *
 * Locks CPU frequency to the policy maximum with cached frequency
 * tracking to avoid redundant driver calls.
 *
 * Copyright (C) 2024 techyguyperplexable
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

struct acacia_perf_data {
	unsigned int cached_max;
};

static int cpufreq_gov_acacia_perf_init(struct cpufreq_policy *policy)
{
	struct acacia_perf_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->cached_max = policy->max;
	policy->governor_data = data;

	return 0;
}

static void cpufreq_gov_acacia_perf_exit(struct cpufreq_policy *policy)
{
	kfree(policy->governor_data);
	policy->governor_data = NULL;
}

static int cpufreq_gov_acacia_perf_start(struct cpufreq_policy *policy)
{
	struct acacia_perf_data *data = policy->governor_data;

	data->cached_max = policy->max;

	pr_debug("setting policy%u to %u kHz\n", policy->cpu, policy->max);
	__cpufreq_driver_target(policy, policy->max, CPUFREQ_RELATION_H);
	return 0;
}

static void cpufreq_gov_acacia_perf_limits(struct cpufreq_policy *policy)
{
	struct acacia_perf_data *data = policy->governor_data;
	unsigned int target = policy->max;

	if (likely(target == data->cached_max && policy->cur == target))
		return;

	data->cached_max = target;

	pr_debug("updating policy%u to %u kHz\n", policy->cpu, target);
	__cpufreq_driver_target(policy, target, CPUFREQ_RELATION_H);
}

static struct cpufreq_governor cpufreq_gov_acacia_perf = {
	.name		= "acacia-perf",
	.init		= cpufreq_gov_acacia_perf_init,
	.exit		= cpufreq_gov_acacia_perf_exit,
	.start		= cpufreq_gov_acacia_perf_start,
	.limits		= cpufreq_gov_acacia_perf_limits,
	.owner		= THIS_MODULE,
};

static int __init cpufreq_gov_acacia_perf_register(void)
{
	return cpufreq_register_governor(&cpufreq_gov_acacia_perf);
}

static void __exit cpufreq_gov_acacia_perf_unregister(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_acacia_perf);
}

MODULE_AUTHOR("techyguyperplexable <objecting@objecting.org>");
MODULE_DESCRIPTION("Acacia Performance Governor - Maximum frequency with minimal overhead");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ACACIA_PERF
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return &cpufreq_gov_acacia_perf;
}
#endif

core_initcall(cpufreq_gov_acacia_perf_register);
module_exit(cpufreq_gov_acacia_perf_unregister);
