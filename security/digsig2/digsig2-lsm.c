/*
 * DigSig2 security module
 *
 * Copyright 2018 Dmitry Eremin-Solenikov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/file.h>
#include <linux/lsm_audit.h>
#include <linux/lsm_hooks.h>
#include <linux/mman.h>
#include <linux/verification.h>

#include <crypto/pkcs7.h>

#include <keys/asymmetric-type.h>

#include "digsig.h"

static struct key *builtin_digsig_keys;

#ifdef CONFIG_SECURITY_DIGSIG2_DEVELOP
int digsig_enforcing;

static int __init enforcing_setup(char *str)
{
	unsigned long enforcing;

	if (!kstrtoul(str, 0, &enforcing))
		digsig_enforcing = enforcing ? 1 : 0;
	return 1;
}
__setup("enforcing=", enforcing_setup);
#else
const int digsig_enforcing = 1;
#endif

static void digsig_audit(struct file *file)
{
	struct common_audit_data a;

	a.type = LSM_AUDIT_DATA_FILE;
	a.u.file = file;
	common_lsm_audit(&a, NULL, NULL);
}

static struct file *digsig_sig_file(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *parent;
	struct name_snapshot snap;
	char *signame;
	struct file *sigfile;

	take_dentry_name_snapshot(&snap, dentry);
	signame = kasprintf(GFP_KERNEL, "%s.der", snap.name);
	release_dentry_name_snapshot(&snap);
	if (signame == NULL)
		return ERR_PTR(-ENOMEM);

	parent = dget_parent(dentry);
	sigfile = file_open_root(parent, file->f_path.mnt,
			signame, O_RDONLY, 0);
	kfree(signame);
	dput(parent);

	return sigfile;
}

static void *digsig_get_signature(struct file *file, loff_t *sig_len)
{
	struct file *sigfile;
	void *sig;
	int ret;

	sigfile = digsig_sig_file(file);
	if (IS_ERR(sigfile))
		return sigfile;

	ret = kernel_read_file(sigfile, &sig, sig_len, 4096, READING_UNKNOWN);
	fput(sigfile);
	if (ret < 0)
		return ERR_PTR(ret);

	return sig;
}

/*
 * FIXME: This needs to be rewritten to pass data in chunks, so that we do not
 * have to read file completely into the memory.  An alternative approach might
 * be to mmap whole file.
 */
static int digsig_verify(struct file *file)
{
	struct pkcs7_message *pkcs7;
	void *elf, *sig;
	loff_t elf_len, sig_len;
	int ret;

	sig = digsig_get_signature(file, &sig_len);
	if (IS_ERR(sig))
		return PTR_ERR(sig);

	pkcs7 = pkcs7_parse_message(sig, sig_len);
	if (IS_ERR(pkcs7)) {
		ret = PTR_ERR(pkcs7);
		goto err_sig;
	}

	elf_len = i_size_read(file_inode(file));
	ret = kernel_read_file(file, &elf, &elf_len, elf_len, READING_UNKNOWN);
	if (ret < 0)
		goto err_elf;

	if (pkcs7_supply_detached_data(pkcs7, elf, elf_len) < 0) {
		pr_err("PKCS#7 signature with non-detached data\n");
		ret = -EBADMSG;
		goto error;
	}

	ret = pkcs7_verify(pkcs7, VERIFYING_UNSPECIFIED_SIGNATURE);
	if (ret < 0)
		goto error;

	ret = pkcs7_validate_trust(pkcs7, builtin_digsig_keys);
	if (ret < 0) {
		if (ret == -ENOKEY)
			pr_err("PKCS#7 signature not signed with a trusted key\n");
		goto error;
	}

error:
	vfree(elf);
err_elf:
	pkcs7_free_message(pkcs7);
err_sig:
	vfree(sig);

	return ret;
}

static int digsig_mmap_file(struct file *file,
			    unsigned long reqprot,
			    unsigned long prot,
			    unsigned long flags)
{
	int ret;

	/* Anonymous mapping */
	if (!file || !file->f_path.dentry || !file->f_path.dentry->d_name.name)
		return 0;

	if (!(prot & PROT_EXEC))
		return 0;

	ret = digsig_verify(file);
	if (ret < 0)
		digsig_audit(file);

	return digsig_enforcing ? ret : 0;
}

int digsig_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			 unsigned long prot)
{
	return digsig_mmap_file(vma->vm_file, reqprot, prot, 0);
}

static struct security_hook_list digsig_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(mmap_file, digsig_mmap_file),
	LSM_HOOK_INIT(file_mprotect, digsig_file_mprotect),
};

/* Late initialization of DigSig. It is not possible to load certificates
 * during security_initicall, as asymmetric type is not yet registered at that
 * point. */
static __init int digsig_late_init(void)
{
	int ret;

	if (builtin_digsig_keys == NULL)
		return 0;

	pr_notice("Loading compiled-in X.509 certificates for DigSig database\n");
	ret = load_asymmetric_keys_from_buffer(builtin_digsig_keys,
					       shipped_digsig_certs,
					       shipped_digsig_certs_len);
	if (ret < 0) {
		pr_err("Problem parsing in-kernel X.509 certificate list\n");
		keyring_clear(builtin_digsig_keys);
		return ret;
	}

	return 0;
}
late_initcall(digsig_late_init);

static __init int digsig_init(void)
{
	if (!security_module_enable("digsig"))
		return 0;

	pr_info("DigSig:  Initializing.\n");

	builtin_digsig_keys =
		keyring_alloc(".builtin_digsig_keys",
			      KUIDT_INIT(0), KGIDT_INIT(0), current_cred(),
			      ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
			      KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH),
			      KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(builtin_digsig_keys))
		return PTR_ERR(builtin_digsig_keys);

	/*
	 * Register with LSM
	 */
	security_add_hooks(digsig_hooks, ARRAY_SIZE(digsig_hooks), "digsig");

	return 0;
}
security_initcall(digsig_init);
