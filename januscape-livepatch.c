// fix januscape
// includes https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0cb2af2ea66ad
// includes https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/kprobes.h>
#include <linux/kvm_host.h>

extern bool enable_mmio_caching;
#define PT_PAGE_SIZE_MASK  BIT_ULL(7)
#define PT_WRITABLE_MASK   BIT_ULL(1)

#include "mmu_internal.h"
#include "spte.h"


struct shadow_page_caches {
    struct kvm_mmu_memory_cache *page_header_cache;
    struct kvm_mmu_memory_cache *shadow_page_cache;
    struct kvm_mmu_memory_cache *shadowed_info_cache;
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

static struct kvm_mmu_page *(*fn_get_shadow_page)(struct kvm *kvm,
    struct kvm_vcpu *vcpu, struct shadow_page_caches *caches,
    gfn_t gfn, union kvm_mmu_page_role role);

static union kvm_mmu_page_role (*fn_child_role)(u64 *sptep,
    bool direct, unsigned int access);

static int (*fn_mmu_page_zap_pte)(struct kvm *, struct kvm_mmu_page *,
				   u64 *, struct list_head *);
static int (*fn_pte_list_add)(struct kvm_mmu_memory_cache *, u64 *,
			       struct kvm_rmap_head *);
static void (*fn_mark_unsync)(u64 *);

static void (*fn_commit_zap_page)(struct kvm *, struct list_head *);
static void (*fn_flush_remote_tlbs)(struct kvm *);
static u64 (*fn_make_nonleaf_spte)(u64 *child_pt, bool ad_disabled);

static struct kvm_mmu_page *livepatch_kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
                          u64 *sptep, gfn_t gfn,
                          bool direct, unsigned int access)
{
    union kvm_mmu_page_role role = fn_child_role(sptep, direct, access);
    struct shadow_page_caches caches = {
        .page_header_cache   = &vcpu->arch.mmu_page_header_cache,
        .shadow_page_cache   = &vcpu->arch.mmu_shadow_page_cache,
        .shadowed_info_cache = &vcpu->arch.mmu_shadowed_info_cache,
    };

    if (is_shadow_present_pte(*sptep) &&
        !is_large_pte(*sptep) &&
        spte_to_child_sp(*sptep) &&
        spte_to_child_sp(*sptep)->gfn == gfn &&
        spte_to_child_sp(*sptep)->role.word == role.word)
        return ERR_PTR(-EEXIST);
    // __kvm_mmu_get_shadow_page instead of kvm_mmu_get_shadow_page
    return fn_get_shadow_page(vcpu->kvm, vcpu, &caches, gfn, role);
}

static void livepatch__link_shadow_page(struct kvm *kvm,
			       struct kvm_mmu_memory_cache *cache, u64 *sptep,
			       struct kvm_mmu_page *sp, bool flush)
{
    u64 spte;

    //BUILD_BUG_ON(VMX_EPT_WRITABLE_MASK != PT_WRITABLE_MASK);
    if (is_shadow_present_pte(*sptep)) {
      struct kvm_mmu_page *parent_sp;
      LIST_HEAD(invalid_list);
      parent_sp = sptep_to_sp(sptep);
      WARN_ON_ONCE(parent_sp->role.level == PG_LEVEL_4K);

      fn_mmu_page_zap_pte(kvm, parent_sp, sptep, &invalid_list);
      // kvm_mmu_remote_flush_or_zap(kvm, &invalid_list, true);
      if (!list_empty(&invalid_list))
	fn_commit_zap_page(kvm, &invalid_list);
      else
	fn_flush_remote_tlbs(kvm);
    }

    spte = fn_make_nonleaf_spte(sp->spt, sp_ad_disabled(sp));
    // mmu_spte_set(sptep, spte);
    // mmu_spte_set just calls __set_spte that just does a WRITE_ONCE when x86_64
    WRITE_ONCE(*sptep, spte);
    //mmu_page_add_parent_pte(cache, sp, sptep);
    // mmu_page_add_parent_pte is pte_list_add with parent check
    fn_pte_list_add(cache, sptep, &sp->parent_ptes);

    if (sp->unsync_children || sp->unsync)
      fn_mark_unsync(sptep);
}

static struct klp_func funcs[] = {
    { .old_name = "kvm_mmu_get_child_sp", .new_func = livepatch_kvm_mmu_get_child_sp, },
    { .old_name = "__link_shadow_page", .new_func = livepatch__link_shadow_page, },
    { }
};
static struct klp_object objs[] = {
    { .name = "kvm", .funcs = funcs, },
    { }
};
static struct klp_patch patch = { .mod = THIS_MODULE, .objs = objs, };

static int livepatch_init(void)
{
    kallsyms_lookup_name_t my_kallsyms;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) { pr_err("kprobe failed: %d\n", ret); return ret; }
    my_kallsyms = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    fn_child_role = (void *)my_kallsyms("kvm_mmu_child_role");
    if (!fn_child_role) { pr_err("can't resolve kvm_mmu_child_role\n"); return -ENOENT; }

    fn_get_shadow_page = (void *)my_kallsyms("__kvm_mmu_get_shadow_page");
    if (!fn_get_shadow_page) { pr_err("can't resolve __kvm_mmu_get_shadow_page\n"); return -ENOENT; }

    fn_mmu_page_zap_pte = (void *)my_kallsyms("mmu_page_zap_pte");
    if (!fn_mmu_page_zap_pte) { pr_err("can't resolve mmu_page_zap_pte\n"); return -ENOENT; }

    fn_pte_list_add = (void *)my_kallsyms("pte_list_add");
    if (!fn_pte_list_add) { pr_err("can't resolve pte_list_add\n"); return -ENOENT; }

    fn_commit_zap_page = (void *)my_kallsyms("kvm_mmu_commit_zap_page");
    if (!fn_commit_zap_page) {
      pr_warn("can't resolve kvm_mmu_commit_zap_page, fallbacking on .part.0 ?\n");
      fn_commit_zap_page = (void *)my_kallsyms("kvm_mmu_commit_zap_page.part.0");
      if (!fn_commit_zap_page) { pr_err("can't resolve kvm_mmu_commit_zap_page\n"); return  -ENOENT; }
    }

    fn_flush_remote_tlbs = (void *)my_kallsyms("kvm_flush_remote_tlbs");
    if (!fn_flush_remote_tlbs) { pr_err("can't resolve kvm_flush_remote_tlbs\n"); return -ENOENT; }

    fn_make_nonleaf_spte = (void *)my_kallsyms("make_nonleaf_spte");
    if (!fn_make_nonleaf_spte) { pr_err("can't resolve make_nonleaf_spte\n"); return -ENOENT; }

    fn_mark_unsync = (void *)my_kallsyms("mark_unsync");
    if (!fn_mark_unsync) { pr_err("can't resolve mark_unsync\n"); return -ENOENT; }

    ret = klp_enable_patch(&patch);
    if (ret) { pr_err("klp_enable_patch failed: %d\n", ret); return ret; }

    pr_info("CVE-2026-53359 patch applied\n");
    return 0;
}
static void livepatch_exit(void) {}
module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_DESCRIPTION("CVE-2026-53359 (Januscape) livepatch");
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
