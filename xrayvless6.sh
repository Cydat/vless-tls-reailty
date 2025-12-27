#!/bin/bash
set -e
#====== 彩色输出函数 ======
green() { echo -e "\033[32m$1\033[0m"; }
red()   { echo -e "\033[31m$1\033[0m"; }
yellow() { echo -e "\033[33m$1\033[0m"; } 

#====== 检测操作系统 ======
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
  else
    OS=$(uname -s)
  fi
  echo "$OS"
}
OS=$(detect_os)

install_dependencies() {
  green "检测到系统: $OS，安装依赖..."
  case "$OS" in
    ubuntu|debian)
      sudo apt update
      sudo apt install -y curl wget xz-utils jq xxd >/dev/null 2>&1
      ;;
    centos|rhel|rocky|alma)
      sudo yum install -y epel-release
      sudo yum install -y curl wget xz jq vim-common >/dev/null 2>&1
      ;;
    alpine)
      sudo apk update
      sudo apk add --no-cache curl wget xz jq vim bash openssl
      ;;
    *)
      red "不支持的系统: $OS"
      exit 1
      ;;
  esac
}
install_dependencies

#====== 检测并安装 Xray ======
check_and_install_xray() {
  if command -v xray >/dev/null 2>&1; then
    green "✅ Xray 已安装"
  else
    green "❗ 正在安装 Xray (IPv6 环境)..."
    if [ "$OS" = "alpine" ]; then
        bash <(curl -L https://github.com/Cydat/vless-tls-reailty/raw/refs/heads/main/xrayinstall-alpine.sh)
    else
        bash <(curl -L https://github.com/Cydat/vless-tls-reailty/raw/refs/heads/main/xrayinstall.sh)
    fi
    XRAY_BIN=$(command -v xray || echo "/usr/local/bin/xray")
    if [ ! -x "$XRAY_BIN" ]; then red "❌ 安装失败"; exit 1; fi
  fi
}

#====== 获取 IPv6 地址函数 ======
get_ipv6() {
  # 优先尝试多个 IPv6 获取接口
  local ip=$(curl -6 -s --max-time 5 https://6.ipw.cn || curl -6 -s --max-time 5 https://api64.ipify.org || echo "")
  if [ -z "$ip" ]; then
    red "❌ 未检测到有效的公网 IPv6 地址，请确保服务器已开启 IPv6"
    exit 1
  fi
  echo "$ip"
}

#====== Trojan Reality (IPv6 版) ======
install_trojan_reality() {
  check_and_install_xray
  XRAY_BIN=$(command -v xray || echo "/usr/local/bin/xray")
  read -rp "监听端口 (默认 443): " PORT
  PORT=${PORT:-443}
  read -rp "节点备注: " REMARK
  REMARK=${REMARK:-Trojan_IPv6}

  PASSWORD=$(openssl rand -hex 8)
  KEYS=$($XRAY_BIN x25519)
  PRIV_KEY=$(echo "$KEYS" | awk '/PrivateKey:/ {print $2}')
  PUB_KEY=$(echo "$KEYS" | awk '/PublicKey:/ {print $2}') # 修正原脚本变量名错误
  SHORT_ID=$(head -c 4 /dev/urandom | xxd -p)
  SNI="icloud.cdn-apple.com"

  cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": $PORT,
    "protocol": "trojan",
    "settings": { "clients": [{ "password": "$PASSWORD", "email": "$REMARK"}] },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$SNI:443",
        "xver": 0,
        "serverNames": ["$SNI"],
        "privateKey": "$PRIV_KEY",
        "shortIds": ["$SHORT_ID"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

  # 重启服务
  [ "$OS" = "alpine" ] && (rc-service xray restart; rc-update add xray default) || (systemctl restart xray; systemctl enable xray)
  
  IP=$(get_ipv6)
  # IPv6 链接必须给 IP 加上中括号 []
  LINK="trojan://$PASSWORD@[$IP]:$PORT?security=reality&sni=$SNI&pbk=$PUB_KEY&sid=$SHORT_ID&type=tcp&headerType=none#$REMARK"
  green "✅ Trojan Reality IPv6 节点："
  echo "$LINK"
  read -rp "按任意键返回菜单..."
}

#====== 主菜单 ======
while true; do
  clear
  green "======= VLESS Reality IPv6 专用脚本 ======="
  echo "1) 安装 VLESS Reality Vision (IPv6)"  
  echo "2) 安装 Trojan Reality (IPv6)"
  echo "3) 开启 BBR 加速"
  echo "4) 卸载 Xray"
  echo "0) 退出"
  read -rp "选择: " choice

  case "$choice" in
    1)
      check_and_install_xray
      XRAY_BIN=$(command -v xray || echo "/usr/local/bin/xray")
      read -rp "端口: " PORT
      read -rp "备注: " REMARK
      UUID=$(cat /proc/sys/kernel/random/uuid)
      KEYS=$($XRAY_BIN x25519)
      PRIV_KEY=$(echo "$KEYS" | awk '/PrivateKey:/ {print $2}')
      PUB_KEY=$(echo "$KEYS" | awk '/PublicKey:/ {print $2}')
      SHORT_ID=$(head -c 4 /dev/urandom | xxd -p)
      SNI="icloud.cdn-apple.com"

      cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "email": "$REMARK" , "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$SNI:443",
        "xver": 0,
        "serverNames": ["$SNI"],
        "privateKey": "$PRIV_KEY",
        "shortIds": ["$SHORT_ID"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
      [ "$OS" = "alpine" ] && (rc-service xray restart) || (systemctl restart xray)
      IP=$(get_ipv6)
      LINK="vless://$UUID@[$IP]:$PORT?type=tcp&security=reality&flow=xtls-rprx-vision&sni=$SNI&fp=chrome&pbk=$PUB_KEY&sid=$SHORT_ID#$REMARK"
      green "✅ VLESS IPv6 节点："
      echo "$LINK"
      read -rp "按任意键返回菜单..."
      ;;
    2) install_trojan_reality ;;
    3)
      echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
      echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
      sysctl -p
      green "✅ BBR 已开启"
      read -rp "按任意键..."
      ;;
    4)
      [ "$OS" = "alpine" ] && rc-service xray stop || systemctl stop xray
      rm -rf /usr/local/etc/xray /usr/local/bin/xray
      green "✅ 已卸载"
      sleep 1
      ;;
    0) exit 0 ;;
  esac
done
