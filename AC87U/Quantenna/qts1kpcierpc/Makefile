include $(TOPDIR)/rules.mk

PKG_NAME:=qts1kpcierpc
PKG_VERSION:=37.3.1.25-OPENWRT
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_SOURCE:=quantenna_sources.tar.gz
PKG_SOURCE_VERSION:=1.0
PKG_SOURCE_URL:=https://cdn.rawgit.com/xNNism/xNNs-OpenWrt-feed/Asus-RT-AC87U/AC87U/Quantenna/src/
PKG_MD5SUM:=152aabe66b4ca4e6ec658b37847b36d0

include $(INCLUDE_DIR)/package.mk

define Package/qts1kpcierpc
  SECTION:=xNN's Feed
  CATEGORY:=xNN's Feed
  SUBMENU:=ASUS RT-AC87U
  TITLE:=Quantenna QTS1000 Driver Utilities
<<<<<<< HEAD
  DEPENDS:=+librpc +QUANTENNA_IWINFO_PLUGIN
=======
  DEPENDS:=+librpc +libiwinfo
>>>>>>> 0fb6a8cae2ec8166fdc442ac35e76cc0ddc76e34
  MENU:=1
endef

define Package/qts1kpcierpc/description
 Utilitys for the Quantenna wifi driver
endef

define Package/qts1kpcierpc/config
	source "$(SOURCE)/Config.in"
endef

define Build/Configure
	$(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))
endef

define Build/Compile
	+$(MAKE_VARS) \
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/$(MAKE_PATH)/../quantenna/client/libqcsapi_client_src \
		$(MAKE_FLAGS) \
		qcsapi_pcie qcsapi_sockrpc qcsapi_sockraw;
	
	+$(MAKE_VARS) \
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/$(MAKE_PATH)/../quantenna/client/qevt-client \
		$(MAKE_FLAGS) \
		qevt_client;
	
endef

define Package/qts1kpcierpc/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/../quantenna/client/libqcsapi_client_src/libqcsapi_client.so $(1)/usr/lib/libqcsapi_client.so
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/../quantenna/client/libqcsapi_client_src/libqcsapi_client.so.1 $(1)/usr/lib/libqcsapi_client.so.1
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/../quantenna/client/libqcsapi_client_src/libqcsapi_client.so.1.0.1 $(1)/usr/lib/libqcsapi_client.so.1.0.1
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/../quantenna/client/libqcsapi_client_src/qcsapi_pcie $(1)/usr/sbin/qcsapi_pcie
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/../quantenna/client/libqcsapi_client_src/qcsapi_sockrpc $(1)/usr/sbin/qcsapi_sockrpc
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/../quantenna/client/libqcsapi_client_src/qcsapi_sockraw $(1)/usr/sbin/qcsapi_sockraw
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/../quantenna/client/qevt-client/qevt_client $(1)/usr/sbin/qevt_client
endef

$(eval $(call BuildPackage,qts1kpcierpc))
