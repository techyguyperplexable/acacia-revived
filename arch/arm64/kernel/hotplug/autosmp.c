/*
 * arch/arm/kernel/autosmp.c
 *
 * automatically hotplug/unplug multiple cpu cores
 * based on cpu load and suspend state
 *
 * based on the msm_mpdecision code by
 * Copyright (c) 2012-2013, Dennis Rassmann <showp1984@gmail.com>
 *
 * Copyright (C) 2013-2014, Rauf Gungor, http://github.com/mrg666
 * rewrite to simplify and optimize, Jul. 2013, http://goo.gl/cdGw6x
 * optimize more, generalize for n cores, Sep. 2013, http://goo.gl/448qBz
 * generalize for all arch, rename as autosmp, Dec. 2013, http://goo.gl/x5oyhy
 *
 * Copyright (C) 2018, Ryan Andri (Rainforce279) <ryanandri@linuxmail.org>
 *       Adaptation for Octa core processor.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. For more details, see the GNU
 * General Public License included with the Linux kernel or available
 * at www.gnu.org/licenses
 */

#include <linux/moduleparam.h>
#include <linux/cpufreq.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/hrtimer.h>
#include <linux/notifier.h>
#include <linux/fb.h>

#define ASMP_TAG "AutoSMP: "

struct asmp_load_data {
    u64 prev_cpu_idle;
    u64 prev_cpu_wall;
};
static DEFINE_PER_CPU(struct asmp_load_data, asmp_data);

static struct delayed_work asmp_work;
static struct workqueue_struct *asmp_workq;
static struct notifier_block asmp_nb;

/*
 * Flag and NOT editable/tunabled
 */
static bool started = false;

static struct asmp_param_struct {
    unsigned int delay;
    bool scroff_single_core;
    unsigned int max_cpus_pc;
    unsigned int max_cpus_bc;
    unsigned int max_cpus_lc;
    unsigned int min_cpus_pc;
    unsigned int min_cpus_bc;
    unsigned int min_cpus_lc;
    unsigned int cpufreq_up_pc;
    unsigned int cpufreq_up_bc;
    unsigned int cpufreq_up_lc;
    unsigned int cpufreq_down_pc;
    unsigned int cpufreq_down_bc;
    unsigned int cpufreq_down_lc;
    unsigned int cycle_up;
    unsigned int cycle_down;
} asmp_param = {
    .delay = 100,
    .scroff_single_core = true,
    .max_cpus_pc = 1, /* Max cpu Prime cluster ! */
    .max_cpus_bc = 4, /* Max cpu Big cluster ! */
    .max_cpus_lc = 4, /* Max cpu Little cluster ! */
    .min_cpus_pc = 0, /* Minimum Prime cluster online */
    .min_cpus_bc = 1, /* Minimum Big cluster online */
    .min_cpus_lc = 2, /* Minimum Little cluster online */
    .cpufreq_up_pc = 30,
    .cpufreq_up_bc = 50,
    .cpufreq_up_lc = 40,
    .cpufreq_down_pc = 18,
    .cpufreq_down_bc = 25,
    .cpufreq_down_lc = 20,
    .cycle_up = 1,
    .cycle_down = 1,
};

static unsigned int cycle = 0;
int asmp_enabled __read_mostly = 1;

static void asmp_online_cpus(unsigned int cpu)
{
    struct device *dev;
    int ret = 0;

    lock_device_hotplug();
    dev = get_cpu_device(cpu);
    ret = device_online(dev);
    if (ret < 0)
        pr_info("%s: failed online cpu %d\n", __func__, cpu);
    unlock_device_hotplug();
}

static void asmp_offline_cpus(unsigned int cpu)
{
    struct device *dev;
    int ret = 0;

    lock_device_hotplug();
    dev = get_cpu_device(cpu);
    ret = device_offline(dev);
    if (ret < 0)
        pr_info("%s: failed offline cpu %d\n", __func__, cpu);
    unlock_device_hotplug();
}

static int get_cpu_loads(unsigned int cpu)
{
    struct asmp_load_data *data = &per_cpu(asmp_data, cpu);
    u64 cur_wall_time, cur_idle_time;
    unsigned int idle_time, wall_time;
    unsigned int load = 0, max_load = 0;

    cur_idle_time = get_cpu_idle_time(cpu, &cur_wall_time, 0);

    wall_time = (unsigned int)(cur_wall_time - data->prev_cpu_wall);
    data->prev_cpu_wall = cur_wall_time;

    idle_time = (unsigned int)(cur_idle_time - data->prev_cpu_idle);
    data->prev_cpu_idle = cur_idle_time;

    if (unlikely(!wall_time || wall_time < idle_time))
        return load;

    load = 100 * (wall_time - idle_time) / wall_time;

    if (load > max_load)
        max_load = load;

    return max_load;
}

static void update_prev_idle(unsigned int cpu)
{
    /* Record cpu idle data for next calculation loads */
    struct asmp_load_data *data = &per_cpu(asmp_data, cpu);
    data->prev_cpu_idle = get_cpu_idle_time(cpu,
                &data->prev_cpu_wall, 0);
}

static void __ref asmp_work_fn(struct work_struct *work)
{
	unsigned int cpu;
	unsigned int cycle_up = asmp_param.cycle_up;
	unsigned int cycle_down = asmp_param.cycle_down;

	/* Cluster info struct */
	struct cluster_info {
		unsigned int start;        /* first CPU index in cluster */
		unsigned int end;          /* last CPU index */
		unsigned int min_online;   /* min CPUs online */
		unsigned int max_online;   /* max CPUs online */
		unsigned int up_load;      /* load threshold to add core */
		unsigned int down_load;    /* load threshold to remove core */
		unsigned int nr_online;    /* current online CPUs */
		unsigned int slow_cpu;     /* slowest CPU index */
		unsigned int slow_load;    /* slowest CPU load */
		unsigned int fast_load;    /* fastest CPU load */
		unsigned int cluster_load; /* max cluster load */
	} clusters[3];

	/* Little cluster (0..3) */
	clusters[0].start = 0;
	clusters[0].end = 3;
	clusters[0].min_online = asmp_param.min_cpus_lc;
	clusters[0].max_online = asmp_param.max_cpus_lc;
	clusters[0].up_load = asmp_param.cpufreq_up_lc;
	clusters[0].down_load = asmp_param.cpufreq_down_lc;

	/* Big cluster (4..6) */
	clusters[1].start = 4;
	clusters[1].end = 6;
	clusters[1].min_online = asmp_param.min_cpus_bc;
	clusters[1].max_online = asmp_param.max_cpus_bc;
	clusters[1].up_load = asmp_param.cpufreq_up_bc;
	clusters[1].down_load = asmp_param.cpufreq_down_bc;

	/* Prime cluster (7..7) */
	clusters[2].start = 7;
	clusters[2].end = 7;
	clusters[2].min_online = asmp_param.min_cpus_pc;
	clusters[2].max_online = asmp_param.max_cpus_pc;
	clusters[2].up_load = asmp_param.cpufreq_up_pc;
	clusters[2].down_load = asmp_param.cpufreq_down_pc;

	/* Initialize per-cluster data */
	for (int i = 0; i < 3; i++) {
		clusters[i].nr_online = 0;
		clusters[i].slow_cpu = clusters[i].start;
		clusters[i].slow_load = 100;
		clusters[i].fast_load = 0;
		clusters[i].cluster_load = 0;
	}

	/* Gather CPU loads */
	get_online_cpus();
	for_each_online_cpu(cpu) {
		unsigned int load = get_cpu_loads(cpu);
		if (cpu >= clusters[0].start && cpu <= clusters[0].end) {
			clusters[0].nr_online++;
			if (load < clusters[0].slow_load) {
				clusters[0].slow_cpu = cpu;
				clusters[0].slow_load = load;
			}
			if (load > clusters[0].fast_load)
				clusters[0].fast_load = load;
		} else if (cpu >= clusters[1].start && cpu <= clusters[1].end) {
			clusters[1].nr_online++;
			if (load < clusters[1].slow_load) {
				clusters[1].slow_cpu = cpu;
				clusters[1].slow_load = load;
			}
			if (load > clusters[1].fast_load)
				clusters[1].fast_load = load;
		} else if (cpu == clusters[2].start) {
			clusters[2].nr_online++;
			clusters[2].slow_cpu = cpu;
			clusters[2].slow_load = load;
			clusters[2].fast_load = load;
		}
	}
	put_online_cpus();

	/* Hotplug logic per cluster */
	for (int i = 0; i < 3; i++) {
		struct cluster_info *cl = &clusters[i];

		/* UP: Add CPU if slowest load > threshold */
		if (cl->slow_load > cl->up_load &&
		    cl->nr_online < cl->max_online &&
		    cycle >= cycle_up) {

			/* Find next offline CPU in cluster */
			for (cpu = cl->start; cpu <= cl->end; cpu++) {
				if (!cpu_online(cpu)) {
					asmp_online_cpus(cpu);
					cycle = 0;
					break;
				}
			}
		}

		/* DOWN: Remove CPU if fastest load < threshold */
		else if (cl->fast_load < cl->down_load &&
			 cl->nr_online > cl->min_online &&
			 cycle >= cycle_down) {

			/* never offline cluster start CPU if min_online reached */
			if (cl->slow_cpu != cl->start || cl->nr_online > cl->min_online)
				asmp_offline_cpus(cl->slow_cpu);

			cycle = 0;
		}
	}

	/* Safety fallback: make sure min_online CPUs are present */
	for (int i = 0; i < 3; i++) {
		struct cluster_info *cl = &clusters[i];
		for (cpu = cl->start; cpu <= cl->end; cpu++) {
			if (cl->nr_online < cl->min_online && !cpu_online(cpu))
				asmp_online_cpus(cpu);
		}
	}

	/* Schedule next check */
	queue_delayed_work(asmp_workq, &asmp_work,
			   msecs_to_jiffies(asmp_param.delay));
}

static void __ref asmp_suspend(void)
{
	unsigned int cpu;

	/* Stop hotplug work during suspend */
	cancel_delayed_work_sync(&asmp_work);

	/*
	 * Keep only the first CPU of Little cluster (0) and
	 * first CPU of Big cluster (4) online for minimal activity
	 */
	for_each_online_cpu(cpu) {
		if (cpu != 0 && cpu != 4)
			asmp_offline_cpus(cpu);
	}
}

static void __ref asmp_resume(void)
{
	unsigned int cpu;

	/* Bring all possible CPUs online */
	for_each_possible_cpu(cpu) {
		if (!cpu_online(cpu))
			asmp_online_cpus(cpu);

		/* Update idle times for load calculations */
		update_prev_idle(cpu);
	}

	/* Schedule first hotplug check after 3 seconds */
	queue_delayed_work(asmp_workq, &asmp_work,
			   msecs_to_jiffies(3000));
}

static int asmp_notifier_cb(struct notifier_block *nb,
                unsigned long event, void *data)
{
    struct fb_event *evdata = data;
    int *blank;

    if (evdata && evdata->data &&
        event == FB_EVENT_BLANK) {
        blank = evdata->data;
        if (*blank == FB_BLANK_UNBLANK) {
            if (asmp_param.scroff_single_core)
                asmp_resume();
        } else if (*blank == FB_BLANK_POWERDOWN) {
            if (asmp_param.scroff_single_core)
                asmp_suspend();
        }
    }

    return 0;
}

static int __ref asmp_start(void)
{
    unsigned int cpu = 0;
    int ret = 0;

    if (started) {
        pr_info(ASMP_TAG"already enabled\n");
        return ret;
    }

    asmp_workq = alloc_workqueue("asmp", WQ_HIGHPRI, 0);
    if (!asmp_workq) {
        ret = -ENOMEM;
        goto err_out;
    }

    for_each_possible_cpu(cpu) {
        /* Online All cores */
        if (!cpu_online(cpu))
            asmp_online_cpus(cpu);

        update_prev_idle(cpu);
    }

    INIT_DELAYED_WORK(&asmp_work, asmp_work_fn);
    queue_delayed_work(asmp_workq, &asmp_work,
            msecs_to_jiffies(asmp_param.delay));

    asmp_nb.notifier_call = asmp_notifier_cb;
    if (fb_register_client(&asmp_nb))
        pr_info("%s: failed register to fb notifier\n", __func__);

    started = true;

    pr_info(ASMP_TAG"enabled\n");

    return ret;

err_out:

    asmp_enabled = 0;
    return ret;
}

static void __ref asmp_stop(void)
{
    unsigned int cpu = 0;

    if (!started) {
        pr_info(ASMP_TAG"already disabled\n");
        return;
    }

    cancel_delayed_work_sync(&asmp_work);
    destroy_workqueue(asmp_workq);

    asmp_nb.notifier_call = 0;
    fb_unregister_client(&asmp_nb);

    for_each_possible_cpu(cpu) {
        if (!cpu_online(cpu))
            asmp_online_cpus(cpu);
    }

    started = false;

    pr_info(ASMP_TAG"disabled\n");
}

static int set_enabled(const char *val,
                 const struct kernel_param *kp)
{
    int ret;

    ret = param_set_bool(val, kp);
    if (asmp_enabled) {

        asmp_start();

    } else {
		
        asmp_stop();

    }
    return ret;
}

static struct kernel_param_ops module_ops = {
    .set = set_enabled,
    .get = param_get_bool,
};

module_param_cb(enabled, &module_ops, &asmp_enabled, 0644);
MODULE_PARM_DESC(enabled, "hotplug/unplug cpu cores based on cpu load");

/***************************** SYSFS START *****************************/

struct global_attr {
    struct attribute attr;
    ssize_t (*show)(struct kobject *, struct attribute *, char *);
    ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

#define define_global_ro(_name)                 \
static struct global_attr _name =                   \
__ATTR(_name, 0444, show_##_name, NULL)

#define define_global_rw(_name)                 \
static struct global_attr _name =                   \
__ATTR(_name, 0644, show_##_name, store_##_name)

struct kobject *asmp_kobject;

#define show_one(file_name, object)                 \
static ssize_t show_##file_name                     \
(struct kobject *kobj, struct attribute *attr, char *buf)       \
{                                   \
    return sprintf(buf, "%u\n", asmp_param.object);         \
}
show_one(delay, delay);
show_one(scroff_single_core, scroff_single_core);
show_one(min_cpus_lc, min_cpus_lc);
show_one(min_cpus_bc, min_cpus_bc);
show_one(min_cpus_pc, min_cpus_pc);
show_one(max_cpus_lc, max_cpus_lc);
show_one(max_cpus_bc, max_cpus_bc);
show_one(max_cpus_pc, max_cpus_pc);
show_one(cpufreq_up_lc, cpufreq_up_lc);
show_one(cpufreq_up_bc, cpufreq_up_bc);
show_one(cpufreq_up_pc, cpufreq_up_pc);
show_one(cpufreq_down_lc, cpufreq_down_lc);
show_one(cpufreq_down_bc, cpufreq_down_bc);
show_one(cpufreq_down_pc, cpufreq_down_pc);
show_one(cycle_up, cycle_up);
show_one(cycle_down, cycle_down);

#define store_one(file_name, object)                    \
static ssize_t store_##file_name                    \
(struct kobject *a, struct attribute *b, const char *buf, size_t count) \
{                                   \
    unsigned int input;                     \
    int ret;                            \
    ret = sscanf(buf, "%u", &input);                \
    if (ret != 1)                           \
        return -EINVAL;                     \
    asmp_param.object = input;                  \
    return count;                           \
}                                   \
define_global_rw(file_name);
store_one(delay, delay);
store_one(scroff_single_core, scroff_single_core);
store_one(cpufreq_up_lc, cpufreq_up_lc);
store_one(cpufreq_up_bc, cpufreq_up_bc);
store_one(cpufreq_up_pc, cpufreq_up_pc);
store_one(cpufreq_down_lc, cpufreq_down_lc);
store_one(cpufreq_down_bc, cpufreq_down_bc);
store_one(cpufreq_down_pc, cpufreq_down_pc);
store_one(cycle_up, cycle_up);
store_one(cycle_down, cycle_down);

/* Little cluster min/max */
static ssize_t store_min_cpus_lc(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int val;
	if (sscanf(buf, "%u", &val) != 1)
		return -EINVAL;

	if (val < 1)
		val = 1;
	if (val > asmp_param.max_cpus_lc)
		return -EINVAL;

	asmp_param.min_cpus_lc = val;
	return count;
}

static ssize_t store_max_cpus_lc(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int val;
	if (sscanf(buf, "%u", &val) != 1)
		return -EINVAL;

	if (val < asmp_param.min_cpus_lc)
		return -EINVAL;
	if (val > 4)
		val = 4;

	asmp_param.max_cpus_lc = val;
	return count;
}

/* Big cluster min/max */
static ssize_t store_min_cpus_bc(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int val;
	if (sscanf(buf, "%u", &val) != 1)
		return -EINVAL;

	if (val < 1)
		val = 1;
	if (val > asmp_param.max_cpus_bc)
		return -EINVAL;

	asmp_param.min_cpus_bc = val;
	return count;
}

static ssize_t store_max_cpus_bc(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int val;
	if (sscanf(buf, "%u", &val) != 1)
		return -EINVAL;

	if (val < asmp_param.min_cpus_bc)
		return -EINVAL;
	if (val > 4)
		val = 4;

	asmp_param.max_cpus_bc = val;
	return count;
}

/* Prime cluster min/max (CPU 7) */
static ssize_t store_min_cpus_pc(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int val;
	if (sscanf(buf, "%u", &val) != 1)
		return -EINVAL;

	if (val < 1)
		val = 1;
	if (val > asmp_param.max_cpus_pc)
		return -EINVAL;

	asmp_param.min_cpus_pc = val;
	return count;
}

static ssize_t store_max_cpus_pc(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int val;
	if (sscanf(buf, "%u", &val) != 1)
		return -EINVAL;

	if (val < asmp_param.min_cpus_pc)
		return -EINVAL;
	if (val > 1) /* Prime cluster only has CPU7 */
		val = 1;

	asmp_param.max_cpus_pc = val;
	return count;
}

define_global_rw(min_cpus_lc);
define_global_rw(min_cpus_bc);
define_global_rw(min_cpus_pc);
define_global_rw(max_cpus_lc);
define_global_rw(max_cpus_bc);
define_global_rw(max_cpus_pc);

static struct attribute *asmp_attributes[] = {
    &delay.attr,
    &scroff_single_core.attr,
    &min_cpus_lc.attr,
    &min_cpus_bc.attr,
    &min_cpus_pc.attr,
    &max_cpus_lc.attr,
    &max_cpus_bc.attr,
    &max_cpus_pc.attr,
    &cpufreq_up_lc.attr,
    &cpufreq_up_bc.attr,
    &cpufreq_up_pc.attr,
    &cpufreq_down_lc.attr,
    &cpufreq_down_bc.attr,
    &cpufreq_down_pc.attr,
    &cycle_up.attr,
    &cycle_down.attr,
    NULL
};

static struct attribute_group asmp_attr_group = {
    .attrs = asmp_attributes,
    .name = "conf",
};

/****************************** SYSFS END ******************************/

static int __init asmp_init(void) {
    int rc = 0;

    asmp_kobject = kobject_create_and_add("autosmp", kernel_kobj);
    if (asmp_kobject) {
        rc = sysfs_create_group(asmp_kobject, &asmp_attr_group);
        if (rc)
            pr_warn(ASMP_TAG"ERROR, create sysfs group");
    } else
        pr_warn(ASMP_TAG"ERROR, create sysfs kobj");

    pr_info(ASMP_TAG"initialized\n");

    return 0;
}
late_initcall(asmp_init);
