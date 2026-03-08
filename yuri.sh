#!/usr/bin/env sh

set -eu

REMOTE_URL="https://raw.githubusercontent.com/Yurii0307/yurikey/main/key"
OUTPUT_PATH="${1:-./keybox.xml}"

if [ "$OUTPUT_PATH" = "-h" ] || [ "$OUTPUT_PATH" = "--help" ]; then
  echo "用法: $0 [输出文件]"
  echo "默认输出: ./keybox.xml"
  exit 0
fi

download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$REMOTE_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$REMOTE_URL"
  else
    echo "错误: 需要安装 curl 或 wget。" >&2
    exit 1
  fi
}

if ! command -v base64 >/dev/null 2>&1; then
  echo "错误: 需要 base64 命令。" >&2
  exit 1
fi

OUTPUT_DIR=$(dirname "$OUTPUT_PATH")
mkdir -p "$OUTPUT_DIR"

TMP_FILE=$(mktemp)
cleanup() {
  rm -f "$TMP_FILE"
}
trap cleanup EXIT INT TERM

if ! download > "$TMP_FILE"; then
  echo "错误: 下载 keybox 数据失败。" >&2
  exit 1
fi

if ! base64 -d "$TMP_FILE" > "$OUTPUT_PATH" 2>/dev/null; then
  echo "错误: 解码 keybox 数据失败（base64 无效）。" >&2
  exit 1
fi

echo "已保存 keybox 到: $OUTPUT_PATH"
