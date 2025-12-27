#!/bin/bash
set -e
#====== 彩色输出函数 (必须放前面) ======
green() { echo -e "\033[32m$1\033[0m"; }
red()   { echo -e "\033[31m$1\033[0m"; }
yellow() { echo -e "\033[33m$1\033[0m"; }

#====== 获取 IPv4 和 IPv6 地址 ======
get_ip_addresses() {
  local ipv4 ipv6
  
  # 获取 IPv4
  ipv4=$(curl -s --max-time 5 https://ipv4.ip.sb || curl -s --max-time 5 https://ifconfig.me || echo "")
  
  # 获取 IPv6
  ipv6=$(curl -s --max-time 5 https://ipv6.ip.sb || echo "")
  
  # 如果 IPv6 为空，尝试从本地接口获取
  if [ -z "$ipv6" ]; then
    ipv6=$(ip -6 addr show scope global | grep -oP '(?<=inet6\s)\S+(? =/|$)' | head -1 || echo "")
  fi
  
  echo "IPv4:$ipv4|IPv6:$ipv6"
}

#====== 显示节点链接 (同时输出 IPv4 和 IPv6) ======
show_node_links() {
  local protocol=$1
  local link_ipv4=$2
  local link_ipv6=$3
  
  green "✅ 节点链接如下："
  echo
  if [ -n "$link_ipv4" ]; then
    green "📌 IPv4 链接："
    echo "$link_ipv4"
    echo
  fi
  if [ -n "$link_ipv6" ]; then
    green "📌 IPv6 链接："
    echo "$link_ipv6"
    echo
  fi
  read -rp "按任意键返回菜单..."
}

#====== 安装依赖 ======
sudo apt install -y curl wget xz-utils jq xxd >/dev/null 2>&1

#====== 检测xray是否安装 =====
check_and_install_xray() {
  if command -v xray >/dev/null 2>&1; then
    green "✅ Xray 已安装，跳过安装"
  else
    green "❗检测到 Xray 未安装，正在安装..."
    bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
    XRAY_BIN=$(command -v xray || echo "/usr/local/bin/xray")
    if [ ! -x "$XRAY_BIN" ]; then
      red "❌ Xray 安装失败，请检查"
      exit 1
    fi
    green "✅ Xray 安装完成"
  fi
}

#====== 流媒体解锁检测 ======
check_streaming_unlock() {
  green "==== 流媒体解锁检测 ===="

  test_site() {
    local name=$1 url=$2 keyword=$3
    echo -n "检测 $name ...  "
    html=$(curl -s --max-time 10 -A "Mozilla/5.0" "$url")
    if echo "$html" | grep -qi "$keyword"; then
      echo "✅ 解锁"
    else
      echo "❌ 未解锁"
    fi
  }

  test_site "Netflix" "https://www.netflix.com/title/80018499" "netflix"
  test_site "Disney+" "https://www.disneyplus.com/" "disney"
  test_site "YouTube Premium" "https://www.youtube.com/premium" "Premium"
  test_site "ChatGPT" "https://chat.openai.com/" "OpenAI"
  test_site "Twitch" "https://www.twitch.tv/" "Twitch"
  test_site "HBO Max" "https://play.hbomax.com/" "HBO"

  echo "=========================="
  read -rp "按任意键返回菜单..."
}

#====== IP 纯净度检测 ======
check_ip_clean() {
  echo "==== IP 纯净度检测 ===="
  IP=$(curl -s https://api.ipify.org)
  echo "本机公网 IP：$IP"
  hosts=("openai.com" "api.openai.com" "youtube.com" "tiktok. com" "twitter.com" "wikipedia.org")
  for h in "${hosts[@]}"; do
    echo -n "测试 $h ... "
    if timeout 5 curl -sI https://$h >/dev/null; then
      echo "✅"
    else
      echo "❌"
    fi
  done
  echo "========================"
  read -rp "按任意键返回菜单..."
}

#====== 查询已部署的入站协议并生成链接 ======
show_deployed_protocols() {
  CONFIG="/usr/local/etc/xray/config.json"
  if [ !  -f "$CONFIG" ]; then
    red "❌ 找不到 Xray 配置文件：$CONFIG"
    read -rp "按任意键返回菜单..."
    return
  fi

  green "📥 正在分析已部署协议..."

  IPS=$(get_ip_addresses)
  IP_IPV4=$(echo "$IPS" | cut -d'|' -f1 | cut -d': ' -f2)
  IP_IPV6=$(echo "$IPS" | cut -d'|' -f2 | cut -d':' -f2)

  mapfile -t INBOUNDS < <(jq -c '.inbounds[]' "$CONFIG")

  if [ ${#INBOUNDS[@]} -eq 0 ]; then
    red "未发现入站协议配置"
    read -rp "按任意键返回菜单..."
    return
  fi

  for inbound in "${INBOUNDS[@]}"; do
    proto=$(echo "$inbound" | jq -r '.protocol')
    port=$(echo "$inbound" | jq -r '.port')
    clients=$(echo "$inbound" | jq -c '.settings.clients // empty')

    case $proto in
      vless)
        echo "$clients" | jq -c '.[]' | while read -r client; do
          uuid=$(echo "$client" | jq -r '.id')
          remark=$(echo "$client" | jq -r '.email // "VLESS"')
          sni=$(echo "$inbound" | jq -r '. streamSettings.realitySettings.serverNames[0] // "www.cloudflare.com"')
          pbk=$(echo "$inbound" | jq -r '.streamSettings. realitySettings.publicKey // "PUBKEY"')
          sid=$(echo "$inbound" | jq -r '.streamSettings.realitySettings.shortIds[0] // "SID"')
          
          if [ -n "$IP_IPV4" ]; then
            link_ipv4="vless://$uuid@$IP_IPV4:$port?type=tcp&security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid#$remark"
            green "🎯 VLESS IPv4 链接：$link_ipv4"
          fi
          
          if [ -n "$IP_IPV6" ]; then
            link_ipv6="vless://$uuid@[$IP_IPV6]:$port?type=tcp&security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid#$remark"
            green "🎯 VLESS IPv6 链接：$link_ipv6"
          fi
        done
        ;;

      vmess)
        echo "$clients" | jq -c '.[]' | while read -r client; do
          uuid=$(echo "$client" | jq -r '.id')
          remark=$(echo "$client" | jq -r '.email // "VMESS"')
          link_json=$(jq -n \
            --arg v "2" \
            --arg add "$IP_IPV4" \
            --arg port "$port" \
            --arg id "$uuid" \
            --arg aid "0" \
            --arg net "tcp" \
            --arg type "none" \
            --arg host "" \
            --arg path "" \
            --arg tls "none" \
            --arg name "$remark" \
            '{
              v: $v, ps: $name, add: $add, port:  $port,
              id: $id, aid: $aid, net: $net,
              type: $type, host: $host, path: $path, tls: $tls
            }')
          encoded=$(echo "$link_json" | base64 -w 0)
          green "🎯 VMess IPv4 链接：vmess://$encoded"
        done
        ;;

      shadowsocks)
        method=$(echo "$inbound" | jq -r '.settings.method')
        password=$(echo "$inbound" | jq -r '.settings.password')
        remark="Shadowsocks-$port"
        userpass=$(echo -n "$method: $password" | base64)
        green "🎯 SS IPv4 链接：ss://$userpass@$IP_IPV4:$port#$remark"
        ;;

      trojan)
        echo "$clients" | jq -c '.[]' | while read -r client; do
          password=$(echo "$client" | jq -r '.password')
          remark=$(echo "$client" | jq -r '.email // "trojan"')
          if [ -n "$IP_IPV4" ]; then
            green "🎯 Trojan IPv4 链接：trojan://$password@$IP_IPV4:$port#${remark}"
          fi
          if [ -n "$IP_IPV6" ]; then
            green "🎯 Trojan IPv6 链接：trojan://$password@[$IP_IPV6]:$port#${remark}"
          fi
        done
        ;;

      *)
        yellow "⚠️  未支持的协议:  $proto"
        ;;
    esac
  done

  echo
  read -rp "按任意键返回菜单..."
}

#====== 安装 Trojan Reality ======
install_trojan_reality() {
  check_and_install_xray
  XRAY_BIN=$(command -v xray || echo "/usr/local/bin/xray")
  read -rp "监听端口（如 443）:  " PORT
  read -rp "节点备注（如：trojanNode）: " REMARK

  PASSWORD=$(openssl rand -hex 8)
  KEYS=$($XRAY_BIN x25519)
  PRIV_KEY=$(echo "$KEYS" | awk '/Private/ {print $3}')
  PUB_KEY=$(echo "$KEYS" | awk '/Public/ {print $3}')
  SHORT_ID=$(head -c 4 /dev/urandom | xxd -p)
  SNI="www.cloudflare.com"

  mkdir -p /usr/local/etc/xray
  cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": $PORT,
    "protocol": "trojan",
    "settings": {
      "clients": [{ "password": "$PASSWORD", "email": "$REMARK" }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$SNI: 443",
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

  systemctl daemon-reexec
  systemctl restart xray
  systemctl enable xray

  IPS=$(get_ip_addresses)
  IP_IPV4=$(echo "$IPS" | cut -d'|' -f1 | cut -d':' -f2)
  IP_IPV6=$(echo "$IPS" | cut -d'|' -f2 | cut -d':' -f2)
  
  LINK_IPV4=""
  LINK_IPV6=""
  
  if [ -n "$IP_IPV4" ]; then
    LINK_IPV4="trojan://$PASSWORD@$IP_IPV4:$PORT#$REMARK"
  fi
  
  if [ -n "$IP_IPV6" ]; then
    LINK_IPV6="trojan://$PASSWORD@[$IP_IPV6]:$PORT#$REMARK"
  fi
  
  show_node_links "Trojan Reality" "$LINK_IPV4" "$LINK_IPV6"
}

#====== 主菜单 ======
while true; do
  clear
  green "AD：优秀流媒体便宜小鸡：sadidc.cn"
  green "AD：拼好机：gelxc.cloud"
  green "======= VLESS Reality 一键脚本V4.1（IPv4+IPv6支持） ======="
  echo "1) 安装并配置 VLESS Reality 节点"  
  echo "2) 生成 Trojan Reality 节点"
  echo "3) 生成 VLESS 中转链接"
  echo "4) 开启 BBR 加速"
  echo "5) 测试流媒体解锁"
  echo "6) 检查 IP 纯净度"
  echo "7) Ookla Speedtest 测试"
  echo "8) 卸载 Xray"
  echo "9) 查询 Xray 已部署协议"
  echo "0) 退出"
  echo
  read -rp "请选择操作:  " choice

  case "$choice" in
    1)
      check_and_install_xray
      XRAY_BIN=$(command -v xray || echo "/usr/local/bin/xray")
      read -rp "监听端口（如 443）: " PORT
      read -rp "节点备注:  " REMARK
      UUID=$(cat /proc/sys/kernel/random/uuid)
      KEYS=$($XRAY_BIN x25519)
      PRIV_KEY=$(echo "$KEYS" | awk '/Private/ {print $3}')
      PUB_KEY=$(echo "$KEYS" | awk '/Public/ {print $3}')
      SHORT_ID=$(head -c 4 /dev/urandom | xxd -p)
      SNI="www.cloudflare.com"

      mkdir -p /usr/local/etc/xray
      cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds":  [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "email": "$REMARK" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network":  "tcp",
      "security":  "reality",
      "realitySettings": {
        "show":  false,
        "dest": "$SNI:443",
        "xver": 0,
        "serverNames": ["$SNI"],
        "privateKey": "$PRIV_KEY",
        "shortIds": ["$SHORT_ID"]
      }
    }
  }],
  "outbounds": [{ "protocol":  "freedom" }]
}
EOF

      systemctl daemon-reexec
      systemctl restart xray
      systemctl enable xray

      IPS=$(get_ip_addresses)
      IP_IPV4=$(echo "$IPS" | cut -d'|' -f1 | cut -d': ' -f2)
      IP_IPV6=$(echo "$IPS" | cut -d'|' -f2 | cut -d':' -f2)
      
      LINK_IPV4=""
      LINK_IPV6=""
      
      if [ -n "$IP_IPV4" ]; then
        LINK_IPV4="vless://$UUID@$IP_IPV4:$PORT? type=tcp&security=reality&sni=$SNI&fp=chrome&pbk=$PUB_KEY&sid=$SHORT_ID#$REMARK"
      fi
      
      if [ -n "$IP_IPV6" ]; then
        LINK_IPV6="vless://$UUID@[$IP_IPV6]:$PORT?type=tcp&security=reality&sni=$SNI&fp=chrome&pbk=$PUB_KEY&sid=$SHORT_ID#$REMARK"
      fi
      
      show_node_links "VLESS Reality" "$LINK_IPV4" "$LINK_IPV6"
      ;;
    2)
      install_trojan_reality
      ;;
    3)
      read -rp "请输入原始 VLESS 链接: " old_link
      read -rp "请输入中转服务器地址（IP 或域名）: " new_server
      new_link=$(echo "$old_link" | sed -E "s#(@)[^: ]+#\\1$new_server#")
      green "🎯 生成的新中转链接："
      echo "$new_link"
      read -rp "按任意键返回菜单..."
      ;;

    4)
      echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
      echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
      sysctl -p
      green "✅ BBR 加速已启用"
      read -rp "按任意键返回菜单..."
      ;;

    5)
      check_streaming_unlock
      ;;

    6)
      check_ip_clean
      ;;

    7)
      wget -q https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz
      tar -zxf ookla-speedtest-1.2.0-linux-x86_64.tgz
      chmod +x speedtest
      ./speedtest --accept-license --accept-gdpr
      rm -f speedtest speedtest. 5 speedtest.md ookla-speedtest-1.2.0-linux-x86_64.tgz
      read -rp "按任意键返回菜单..."
      ;;

    8)
      systemctl stop xray
      systemctl disable xray
      rm -rf /usr/local/etc/xray /usr/local/bin/xray
      green "✅ Xray 已卸载"
      read -rp "按任意键返回菜单..."
      ;;

    9)
      show_deployed_protocols
      ;;

    0)
      exit 0
      ;;

    *)
      red "❌ 无效选项，请重试"
      sleep 1
      ;;
  esac
done
