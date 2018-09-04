#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2002

include $(TOPDIR)/rules.mk

PKG_NAME:=dsniff
PKG_VERSION:=2.4b1
PKG_RELEASE:=4

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.monkey.org/~dugsong/dsniff/beta
PKG_HASH:=a9803a7a02ddfe5fb9704ce86f0ffc48453c321e88db85810db411ba0841152a

PKG_BUILD_DEPENDS:=nfs-kernel-server/host

# Make host rpcgen first
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-2.4

include $(INCLUDE_DIR)/package.mk

define Package/dsniff
  SECTION:=xNN's Feed
  CATEGORY:=xNN's Feed
  SUBMENU:=Wifi-Pineapple
  DEPENDS:=+libpcap +libnids +libopenssl +libgdbm
  TITLE:=A collection of tools for network auditing and penetration testing
  URL:=http://www.monkey.org/~dugsong/dsniff/
endef

define Package/dsniff/description
	A collection of tools for network auditing and penetration testing.
endef

CONFIGURE_ARGS += \
	--with-gdbm="$(STAGING_DIR)/usr" \
	--with-libnids="$(STAGING_DIR)/usr" \
	--with-libpcap="$(STAGING_DIR)/usr" \
	--with-libnet="$(STAGING_DIR)/usr/lib/libnet-1.0.x" \
	--with-openssl="$(STAGING_DIR)/usr" \
	--without-db \
	--without-x

# Modify PATH to use host rpcgen
define Build/Compile
	PATH="$(STAGING_DIR_HOSTPKG)/bin:$(TARGET_PATH)" \
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		install_prefix="$(PKG_INSTALL_DIR)" \
		all install
endef

define Package/dsniff/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/* $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP)  $(PKG_INSTALL_DIR)/usr/lib/* $(1)/usr/lib
endef

$(eval $(call BuildPackage,dsniff))
