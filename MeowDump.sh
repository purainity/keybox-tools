#!/usr/bin/env sh

set -eu

REMOTE_URL="https://raw.githubusercontent.com/MeowDump/MeowDump/main/NullVoid/OptimusPrime"
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

if ! command -v xxd >/dev/null 2>&1; then
  echo "错误: 需要 xxd 命令。" >&2
  exit 1
fi

OUTPUT_DIR=$(dirname "$OUTPUT_PATH")
mkdir -p "$OUTPUT_DIR"

TMP_FILES=""
make_tmp() {
  t=$(mktemp)
  TMP_FILES="$TMP_FILES $t"
  printf '%s' "$t"
}

cleanup() {
  for file in $TMP_FILES; do
    rm -f "$file"
  done
}
trap cleanup EXIT INT TERM

current_file=$(make_tmp)
if ! download > "$current_file"; then
  echo "错误: 下载 keybox 数据失败。" >&2
  exit 1
fi

for _ in $(seq 1 10); do
  next_file=$(make_tmp)
  if ! base64 -d "$current_file" > "$next_file" 2>/dev/null; then
    echo "错误: 多层 base64 解码失败。" >&2
    exit 1
  fi
  current_file="$next_file"
done

hex_file=$(make_tmp)
if ! xxd -r -p "$current_file" > "$hex_file" 2>/dev/null; then
  echo "错误: 十六进制解码失败。" >&2
  exit 1
fi

if ! tr 'A-Za-z' 'N-ZA-Mn-za-m' < "$hex_file" > "$OUTPUT_PATH"; then
  echo "错误: ROT13 解码失败。" >&2
  exit 1
fi

if [ ! -s "$OUTPUT_PATH" ]; then
  echo "错误: 解码后输出文件为空。" >&2
  exit 1
fi

echo "已保存 keybox 到: $OUTPUT_PATH"
