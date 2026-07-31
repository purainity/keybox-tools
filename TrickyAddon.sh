#!/usr/bin/env sh

set -eu

PRIMARY_URL="https://raw.githubusercontent.com/KOWX712/Tricky-Addon-Update-Target-List/keybox/.extra"
TAKR_API_URL="https://keybox.kowx712.cc/api/keyboxes"
TAKR_SITE_URL="https://keybox.kowx712.cc"
OUTPUT_PATH="${1:-./keybox.xml}"

if [ "$OUTPUT_PATH" = "-h" ] || [ "$OUTPUT_PATH" = "--help" ]; then
  echo "用法: $0 [输出文件]"
  echo "默认输出: ./keybox.xml"
  exit 0
fi

# 下载到文件（优先 curl，回退 wget）
download_to_file() {
  url="$1"
  file="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$file"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$file" "$url"
  else
    echo "错误: 需要安装 curl 或 wget。" >&2
    exit 1
  fi
}

if ! command -v xxd >/dev/null 2>&1; then
  echo "错误: 需要 xxd 命令。" >&2
  exit 1
fi

if ! command -v base64 >/dev/null 2>&1; then
  echo "错误: 需要 base64 命令。" >&2
  exit 1
fi

OUTPUT_DIR=$(dirname "$OUTPUT_PATH")
mkdir -p "$OUTPUT_DIR"

TMP_HEX=$(mktemp)
TMP_B64=$(mktemp)
TAKR_TMP=$(mktemp)

cleanup() {
  rm -f "$TMP_HEX" "$TMP_B64" "$TAKR_TMP"
}
trap cleanup EXIT INT TERM

if ! download_to_file "$PRIMARY_URL" "$TMP_HEX"; then
  echo "错误: 下载编码后的 keybox 数据失败。" >&2
  exit 1
fi

if [ ! -s "$TMP_HEX" ]; then
  echo "错误: .extra 当前为空（keybox 已被吊销或未更新）。" >&2
  echo "" >&2
  echo "正在查询 TAKR (Tricky Addon Keybox Repository)..." >&2
  echo ""

  if download_to_file "$TAKR_API_URL" "$TAKR_TMP" 2>/dev/null && [ -s "$TAKR_TMP" ]; then
    all_entries=$(grep -o '"id":[0-9]*[^}]*}' "$TAKR_TMP" || true)
    if [ -n "$all_entries" ]; then
      printf '%s\n' "$all_entries" | while IFS= read -r obj; do
        id=$(printf '%s' "$obj" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
        identity=$(printf '%s' "$obj" | sed -n 's/.*"identity":"\([^"]*\)".*/\1/p')
        status=$(printf '%s' "$obj" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
        root_type=$(printf '%s' "$obj" | sed -n 's/.*"root_type":"\([^"]*\)".*/\1/p')
        cert_count=$(printf '%s' "$obj" | sed -n 's/.*"cert_count":\([0-9]*\).*/\1/p')
        key_format=$(printf '%s' "$obj" | sed -n 's/.*"key_format":"\([^"]*\)".*/\1/p')
        download_count=$(printf '%s' "$obj" | sed -n 's/.*"download_count":\([0-9]*\).*/\1/p')
        created=$(printf '%s' "$obj" | sed -n 's/.*"created_at":"\([^"]*\)".*/\1/p')

        if [ -z "$id" ]; then
          continue
        fi

        if [ "$status" = "valid" ]; then
          if [ "$root_type" = "hardware" ]; then
            tag="强认证/硬件密钥"
          else
            tag="强认证"
          fi
        else
          tag="已吊销"
        fi

        local_time=$(date -d "$created" "+%Y年%-m月%-d日 %H:%M:%S" 2>/dev/null || printf '%s' "$created")

        echo "  TAKR $id  $identity" >&2
        echo "  $tag · ${cert_count}证书 · 密钥算法: $key_format" >&2
        echo "  上传于: $local_time · 下载次数: $download_count" >&2
        echo "" >&2
      done
    else
      echo "  (TAKR 仓库无可用 keybox)" >&2
    fi
    echo "" >&2
    echo "TAKR 下载受 Cloudflare 保护，无法通过脚本自动获取。" >&2
    echo "请通过浏览器访问 $TAKR_SITE_URL 手动下载 keybox。" >&2
  else
    echo "无法查询 TAKR API。" >&2
    echo "请通过浏览器访问 $TAKR_SITE_URL 获取 keybox。" >&2
  fi
  exit 1
fi

if ! xxd -r -p "$TMP_HEX" > "$TMP_B64" 2>/dev/null; then
  echo "错误: 十六进制层解码失败。" >&2
  exit 1
fi

if ! base64 -d "$TMP_B64" > "$OUTPUT_PATH" 2>/dev/null; then
  echo "错误: base64 层解码失败。" >&2
  exit 1
fi

if [ ! -s "$OUTPUT_PATH" ]; then
  echo "错误: 解码后输出文件为空。" >&2
  exit 1
fi

echo "已保存 keybox 到: $OUTPUT_PATH"
