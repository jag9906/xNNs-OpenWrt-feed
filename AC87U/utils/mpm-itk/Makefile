#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mpm-itk
PKG_VERSION:=2.4.7-04
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://mpm-itk.sesse.net/
PKG_HASH:=609f83e8995416c5491348e07139f26046a579db20cf8488ebf75d314668efcf
PKG_FIXUP:=autoreconf
PKG_FIXUP:=patch-libtool
PKG_FIXUP:=gettext-version

include $(INCLUDE_DIR)/package.mk

# PKG_INSTALL:=1
define Package/mpm-itk/Default
  SECTION:=xNN's Feed
  CATEGORY:=xNN's Feed
  SUBMENU:=utils
  DEPENDS:=+apache +libpcap
  URL:=http://mpm-itk.sesse.net/
endef

define Package/mpm-itk
  $(call Package/mpm-itk/Default)
  TITLE:=apache2-mpm-itk (just mpm-itk for short) is an MPM (Multi-Processing Module) for the Apache web server.
endef

define Package/mpm-itk/description
	mpm-itk is based on the traditional prefork MPM, which means it's non-threaded;
	in short, this means you can run non-thread-aware code (like many PHP extensions) 
	without problems. On the other hand, you lose out to any performance benefit 
	you'd get with threads, of course; you'd have to decide for yourself if that's worth it or not.
	 You will also take an additional performance hit over prefork, since there's an extra fork per request.
endef

define Build/Configure
	$(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR,))
endef

define Build/Compile	
	$(MAKE) -C $(PKG_BUILD_DIR)
endef

define Package/mpm-itk/install
	$(INSTALL_DIR) $(1)/usr/lib/httpd/modules
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/.libs/mpm_itk.so $(1)/usr/lib/httpd/modules/mpm_itk.so
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/.libs/mpm_itk.la $(1)/usr/lib/httpd/modules/mpm_itk.la
endef

$(eval $(call BuildPackage,mpm-itk))
