#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Used by dsniff only, no need to update it

include $(TOPDIR)/rules.mk

PKG_NAME:=libnids
PKG_VERSION:=1.24
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/libnids
PKG_HASH:=314b4793e0902fbf1fdb7fb659af37a3c1306ed1aad5d1c84de6c931b351d359

include $(INCLUDE_DIR)/package.mk

define Package/libnids
  SECTION:=xNN's Feed
  CATEGORY:=xNN's Feed
  SUBMENU:=Wifi-Pineapple
  DEPENDS:=+libnet0
  TITLE:=A network intrusion detection library
  URL:=http://libnids.sourceforge.net/
endef

define Package/libnids/description
	An implementation of an E-component of Network Intrusion Detection
	System.
endef

define Build/Configure
	$(call Build/Configure/Default, \
		--enable-shared \
		--enable-static \
		--with-libnet="$(STAGING_DIR)/usr/lib/libnet-1.0.x" \
		--with-libpcap="$(STAGING_DIR)/usr" \
		--disable-libglib \
		, \
		CFLAGS="$$$$CFLAGS $$$$CPPFLAGS" \
	)
endef

TARGET_CFLAGS += $(FPIC)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		LNETLIB="-L$(STAGING_DIR)/usr/lib/libnet-1.0.x/lib -lnet" \
		PCAPLIB="$(TARGET_LDFLAGS) -lpcap" \
		install_prefix="$(PKG_INSTALL_DIR)" \
		all install
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/nids.h $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnids.{a,so*} $(1)/usr/lib/
endef

define Package/libnids/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnids.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libnids))
