#!/usr/bin/env bash
# AEGIS 发行版检测：输出 DISTRO / PM / PKG_INSTALL / INIT
# 兼容：CentOS 7+/8/9, RHEL, AlmaLinux, Rocky, Fedora, TencentOS, OpenCloudOS,
#       Ubuntu, Debian, Kali, Deepin/UOS(部分), openSUSE(实验)

set -u

detect() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="${ID:-unknown}"
        DISTRO_VER="${VERSION_ID:-0}"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="centos"
        DISTRO_VER="7"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        DISTRO_VER="10"
    else
        DISTRO="unknown"
        DISTRO_VER="0"
    fi
    case "$DISTRO" in
        centos|rhel|almalinux|rocky|tencentos|opencloudos|fedora|anolis|openeuler|kylin)
            PM="yum"
            [ -x /usr/bin/dnf ] && PM="dnf"
            PKG_INSTALL="$PM install -y"
            PKG_UPDATE="$PM makecache"
            INIT="systemctl"
            ;;
        ubuntu|debian|kali|deepin|uos|linuxmint)
            PM="apt"
            PKG_INSTALL="apt-get install -y --no-install-recommends"
            PKG_UPDATE="apt-get update"
            INIT="systemctl"
            ;;
        opensuse*|sles)
            PM="zypper"
            PKG_INSTALL="zypper install -y"
            PKG_UPDATE="zypper refresh"
            INIT="systemctl"
            ;;
        alpine)
            PM="apk"
            PKG_INSTALL="apk add --no-cache"
            PKG_UPDATE="apk update"
            INIT="openrc"
            ;;
        *)
            PM="unknown"
            PKG_INSTALL="echo UNSUPPORTED"
            PKG_UPDATE="echo UNSUPPORTED"
            INIT="systemctl"
            ;;
    esac
    echo "DISTRO=$DISTRO"
    echo "DISTRO_VER=$DISTRO_VER"
    echo "PM=$PM"
    echo "PKG_INSTALL=$PKG_INSTALL"
    echo "PKG_UPDATE=$PKG_UPDATE"
    echo "INIT=$INIT"
}

detect "$@"
