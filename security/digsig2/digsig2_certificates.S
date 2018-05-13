/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/export.h>
#include <linux/init.h>

	__INITRODATA

	.align 8
	.globl VMLINUX_SYMBOL(shipped_digsig_certs)
VMLINUX_SYMBOL(shipped_digsig_certs):
__cert_list_start:
	.incbin "security/digsig2/x509_certificate_list"
__cert_list_end:

	.align 8
	.globl VMLINUX_SYMBOL(shipped_digsig_certs_len)
VMLINUX_SYMBOL(shipped_digsig_certs_len):
#ifdef CONFIG_64BIT
	.quad __cert_list_end - __cert_list_start
#else
	.long __cert_list_end - __cert_list_start
#endif
