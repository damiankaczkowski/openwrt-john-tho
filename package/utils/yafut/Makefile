include $(TOPDIR)/rules.mk

PKG_NAME:=yafut
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/kempniu/yafut.git
PKG_SOURCE_DATE:=2023-04-06
PKG_SOURCE_VERSION:=5124b7085e2287bdc14898c3146717dcd35a164c

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_INSTALL:=1

define Package/yafut
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Yet Another File UTility
  DEPENDS:=@NAND_SUPPORT
endef

define Package/yafut/description
  A program for copying files from/to Yaffs file systems from userspace.
endef

define Package/yafut/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/yafut $(1)/usr/bin
endef

$(eval $(call BuildPackage,yafut))
