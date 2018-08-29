#
# Copyright (C) 2006-2015 OpenWrt.org
# Copyright (C) 2018 seb@hak5.org
# Copyright (C) 2018 adde88@gmail.com
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=Wifi-Pineapple-MT7628
PKG_VERSION:=v1_mt7628
PKG_RELEASE:=1
PKG_LICENSE:=GPLv2

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/xnnism/Wifi-Pineapple-MT7628.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/Wifi-Pineapple-MT7628
  SECTION:=xNN's Feed
  CATEGORY:=xNN's Feed
  TITLE:=Auditing platform from Hak5. Thoughtfully developed for mobile and persistent deployments, ...
  DEPENDS:=+php7 +php7-cgi +php7-fastcgi +uhttpd
  MENU:=1
  URL:=https://www.wifipineapple.com/
endef

define Package/Wifi-Pineapple-MT7628/description
	Powerful. Portable. Easy to use. 
	Ready for any deployment scenario.
endef

define Package/Wifi-Pineapple-MT7628/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/pineapple
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/sbin/* $(1)/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/pneapple $(1)/pineapple
endef

$(eval $(call BuildPackage,aircrack-ng-hak5))
