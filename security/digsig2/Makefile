obj-$(CONFIG_SECURITY_DIGSIG2) := digsig2.o

digsig2-y := digsig2-lsm.o digsig2_certificates.o

ifeq ($(CONFIG_SECURITY_DIGSIG2),y)

$(eval $(call config_filename,DIGSIG2_TRUSTED_KEYS))

# GCC doesn't include .incbin files in -MD generated dependencies (PR#66871)
$(obj)/digsig2_certificates.o: $(obj)/x509_certificate_list

# Cope with signing_key.x509 existing in $(srctree) not $(objtree)
AFLAGS_digsig2_certificates.o := -I$(srctree)

quiet_cmd_extract_certs  = EXTRACT_CERTS   $(patsubst "%",%,$(2))
      cmd_extract_certs  = scripts/extract-cert $(2) $@ || ( rm $@; exit 1)

targets += x509_certificate_list
$(obj)/x509_certificate_list: scripts/extract-cert $(DIGSIG2_TRUSTED_KEYS_SRCPREFIX)$(DIGSIG2_TRUSTED_KEYS_FILENAME) FORCE
	$(call if_changed,extract_certs,$(DIGSIG2_TRUSTED_KEYS_SRCPREFIX)$(CONFIG_DIGSIG2_TRUSTED_KEYS))

endif #CONFIG_SECURITY_DIGSIG2
