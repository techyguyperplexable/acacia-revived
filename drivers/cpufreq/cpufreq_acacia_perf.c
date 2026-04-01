// SPDX-License-Identifier: GPL-2.0
/*
 * CPUFreq governor: acacia-perf
 *
 * Locks CPU frequency to the policy maximum.
 *
 * Copyright (C) 2024 techyguyperplexable
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/module.h>

static int cpufreq_gov_acacia_perf_start(struct cpufreq_policy *policy)
{
	pr_debug("setting policy%u to %u kHz\n", policy->cpu, policy->max);
	__cpufreq_driver_target(policy, policy->max, CPUFREQ_RELATION_H);
	return 0;
}

static void cpufreq_gov_acacia_perf_limits(struct cpufreq_policy *policy)
{
	pr_debug("updating policy%u to %u kHz\n", policy->cpu, policy->max);
	__cpufreq_driver_target(policy, policy->max, CPUFREQ_RELATION_H);
}

static struct cpufreq_governor cpufreq_gov_acacia_perf = {
	.name		= "acacia-perf",
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
