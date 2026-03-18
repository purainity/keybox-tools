#!/usr/bin/env sh

set -eu

PRIMARY_URL="https://raw.githubusercontent.com/KOWX712/Tricky-Addon-Update-Target-List/keybox/.extra"
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

cleanup() {
  rm -f "$TMP_HEX" "$TMP_B64"
}
trap cleanup EXIT INT TERM

if ! download_to_file "$PRIMARY_URL" "$TMP_HEX"; then
  echo "错误: 下载编码后的 keybox 数据失败。" >&2
  exit 1
fi

if [ ! -s "$TMP_HEX" ]; then
  echo "错误: 下载的 keybox 数据为空。" >&2
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
