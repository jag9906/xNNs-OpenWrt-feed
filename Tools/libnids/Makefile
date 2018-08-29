#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
   9 
  10 PKG_NAME:=libnids
  11 PKG_VERSION:=1.24
  12 PKG_RELEASE:=1
  13 
  14 PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
  15 PKG_SOURCE_URL:=@SF/libnids
  16 PKG_MD5SUM:=72d37c79c85615ffe158aa524d649610
  17 
  18 include $(INCLUDE_DIR)/package.mk
  19 
  20 define Package/libnids
	   SECTION:=xNN's Feed
	   CATEGORY:=xNN's Feed
	   SUBMENU:=Tools
  23   DEPENDS:=+libnet0
  24   TITLE:=A network intrusion detection library
  25   URL:=http://libnids.sourceforge.net/
  26 endef
  27 
  28 define Package/libnids/description
  29         An implementation of an E-component of Network Intrusion Detection
  30         System.
  31 endef
  32 
  33 define Build/Configure
  34         $(call Build/Configure/Default, \
  35                 --enable-shared \
  36                 --enable-static \
  37                 --with-libnet="$(STAGING_DIR)/usr/lib/libnet-1.0.x" \
  38                 --with-libpcap="$(STAGING_DIR)/usr" \
  39                 --disable-libglib \
  40                 , \
  41                 CFLAGS="$$$$CFLAGS $$$$CPPFLAGS" \
  42         )
  43 endef
  44 
  45 TARGET_CFLAGS += $(FPIC)
  46 
  47 define Build/Compile
  48         $(MAKE) -C $(PKG_BUILD_DIR) \
  49                 LNETLIB="-L$(STAGING_DIR)/usr/lib/libnet-1.0.x/lib -lnet" \
  50                 PCAPLIB="$(TARGET_LDFLAGS) -lpcap" \
  51                 install_prefix="$(PKG_INSTALL_DIR)" \
  52                 all install
  53 endef
  54 
  55 define Build/InstallDev
  56         $(INSTALL_DIR) $(1)/usr/include
  57         $(CP) $(PKG_INSTALL_DIR)/usr/include/nids.h $(1)/usr/include/
  58         $(INSTALL_DIR) $(1)/usr/lib
  59         $(CP) $(PKG_INSTALL_DIR)/usr/lib/libnids.{a,so*} $(1)/usr/lib/
  60 endef
  61 
  62 define Package/libnids/install
  63         $(INSTALL_DIR) $(1)/usr/lib
  64         $(CP) $(PKG_INSTALL_DIR)/usr/lib/libnids.so.* $(1)/usr/lib/
  65 endef
  66 
  67 $(eval $(call BuildPackage,libnids))
