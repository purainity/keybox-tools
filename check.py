#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Keybox 检测脚本

功能概览：
1. 深度校验证书链签名与有效期，支持 ECDSA 和 RSA 算法验证。
2. 实时拉取 Google 在线吊销列表，并支持本地数据自动回退。
3. 自动识别 Google 硬件、Knox 及 AOSP 等多种根证书来源与类型。
4. 灵活支持单个 XML 文件检测或目录批量扫描，自动过滤无关文件。
5. 采用高容错处理，支持单文件多 Key 检测，私钥异常时不中断流程。
6. 提供全中文 Emoji 可视化报告，清晰展示 SN 提取结果与最终结论。
"""

import argparse
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding


GOOGLE_STATUS_URL = "https://android.googleapis.com/attestation/status"


def load_public_key_from_file(file_path):
    """从 PEM 文件读取并反序列化公钥对象。"""
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())


def compare_keys(public_key1, public_key2):
    """对比两个公钥是否一致（按标准 PEM 编码字节比较）。"""
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fetch_revocation_status_online():
    """从 Google 在线接口拉取吊销状态 JSON。"""
    headers = {
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    params = {"ts": int(time.time())}
    response = requests.get(GOOGLE_STATUS_URL, headers=headers, params=params, timeout=12)
    response.raise_for_status()
    return response.json()


def fetch_revocation_status_with_fallback(res_dir):
    """
    获取吊销状态数据。

    优先访问在线接口；若在线失败，则回退读取本地 `status.json`。
    返回值为 (status_json, source, online_error_text)。
    """
    try:
        status_json = fetch_revocation_status_online()
        return status_json, "online", None
    except Exception as online_err:
        local_path = os.path.join(res_dir, "status.json")
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                return json.load(f), "local", str(online_err)
        except Exception as local_err:
            raise RuntimeError(
                f"在线拉取失败且本地兜底失败。在线错误: {online_err}; 本地错误: {local_err}"
            ) from local_err


def build_overall_status(revoke_reason, keychain_valid, root_type):
    """根据吊销结果、证书链和根证书类型生成最终状态文案。"""
    if revoke_reason:
        reason_map = {
            "KEY_COMPROMISE": "❌ 无效（密钥泄露）",
            "SOFTWARE_FLAW": "❌ 无效（软件缺陷）",
            "CA_COMPROMISE": "❌ 无效（CA 泄露）",
            "SUPERSEDED": "❌ 无效（已替代/停用）",
        }
        return reason_map.get(revoke_reason, f"❌ 无效（未知吊销原因: {revoke_reason}）")

    if not keychain_valid:
        return "❌ 无效（证书链校验失败）"

    root_map = {
        "google": "✅ 有效（Google 硬件证明）",
        "aosp_ec": "🟡 有效（AOSP 软件证明 EC）",
        "aosp_rsa": "🟡 有效（AOSP 软件证明 RSA）",
        "knox": "✅ 有效（Samsung Knox 证明）",
        "unknown": "🟡 有效（软件签名/未知根）",
    }
    return root_map.get(root_type, "❌ 无效（无法识别状态）")


def format_subject(subject):
    """将证书 Subject 结构拼接为可读字符串。"""
    parts = []
    for rdn in subject:
        parts.append(f"{rdn.oid._name}={rdn.value}")
    return ", ".join(parts)


def extract_subject_fields(subject):
    """
    从证书 Subject 中提取常用字段。

    重点提取 OID `2.5.4.5`（Keybox SN）以及常见的人类可读字段。
    """
    fields = {
        "keybox_sn": "",
        "title": "",
        "organizationName": "",
        "commonName": "",
    }
    for rdn in subject:
        oid_name = rdn.oid._name
        oid_dot = rdn.oid.dotted_string
        if oid_dot == "2.5.4.5":
            fields["keybox_sn"] = str(rdn.value)
        if oid_name in fields:
            fields[oid_name] = str(rdn.value)

    if not fields["keybox_sn"]:
        keybox_match = re.search(r"2\.5\.4\.5=([0-9a-fA-F]+)", str(subject))
        if keybox_match:
            fields["keybox_sn"] = keybox_match.group(1)

    return fields


def detect_root_certificate(root_public_key, trusted_root_keys):
    """根据根证书公钥识别根证书类别。"""
    if compare_keys(root_public_key, trusted_root_keys["google"]):
        return "google", "✅ Google 硬件证明根证书"
    if compare_keys(root_public_key, trusted_root_keys["aosp_ec"]):
        return "aosp_ec", "🟡 AOSP 软件证明根证书（EC）"
    if compare_keys(root_public_key, trusted_root_keys["aosp_rsa"]):
        return "aosp_rsa", "🟡 AOSP 软件证明根证书（RSA）"
    if compare_keys(root_public_key, trusted_root_keys["knox"]):
        return "knox", "✅ Samsung Knox 证明根证书"
    return "unknown", "❌ 未知根证书"


def friendly_cert_error(err):
    """将底层证书解析异常转换成更易理解的中文提示。"""
    text = str(err)
    hint = "证书 PEM 内容可能被污染、截断，或 Base64 内容被改写。"
    if "asn1" in text.lower() or "parse" in text.lower():
        return f"ASN.1 解析失败。{hint} 原始错误: {text}"
    return f"证书解析失败。{hint} 原始错误: {text}"


def parse_xml_candidates(xml_path):
    """
    从 XML 文件中提取待检测的 Key 列表。

    每个候选项包含：Keybox 序号、Key 序号、设备 ID、算法、
    声明证书数、实际 PEM 证书列表、私钥原文。
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # 收集所有可检测的 Key 候选项。
    candidates = []
    keyboxes = root.findall(".//Keybox")
    if not keyboxes:
        raise ValueError("未找到 Keybox 节点")

    # 逐个遍历 Keybox，再遍历其下每个 Key。
    for kb_idx, keybox in enumerate(keyboxes, start=1):
        device_id = keybox.get("DeviceID") or "Unknown"
        keys = keybox.findall("Key")
        if not keys:
            continue

        for key_idx, key_node in enumerate(keys, start=1):
            algorithm = key_node.get("algorithm") or "Unknown"
            chain_node = key_node.find("CertificateChain")
            if chain_node is None:
                continue

            # NumberOfCertificates 为声明值，用于和实际读取数量做提示比对。
            number_node = chain_node.find("NumberOfCertificates")
            if number_node is None or not number_node.text:
                declared_count = None
            else:
                declared_count = int(number_node.text.strip())

            # 只读取 PEM 格式证书，忽略其他格式节点。
            cert_nodes = chain_node.findall('.//Certificate[@format="pem"]')
            pem_certificates = []
            for cert_node in cert_nodes:
                if cert_node.text and cert_node.text.strip():
                    pem_certificates.append(cert_node.text.strip())

            # PrivateKey 可能缺失；后续检测会给出提示但不中断整体流程。
            private_key_node = key_node.find("PrivateKey")
            private_key_raw = None
            if private_key_node is not None and private_key_node.text:
                private_key_raw = private_key_node.text.strip()

            candidates.append(
                {
                    "keybox_index": kb_idx,
                    "key_index": key_idx,
                    "device_id": device_id,
                    "algorithm": algorithm,
                    "declared_count": declared_count,
                    "pem_certificates": pem_certificates,
                    "private_key_raw": private_key_raw,
                }
            )

    if not candidates:
        raise ValueError("未找到可检测的 Key（缺少 CertificateChain 或证书数据）")

    return candidates


def load_certificates_for_candidate(pem_certificates, key_label):
    """将 PEM 文本列表解析为证书对象列表，解析失败时附带定位信息。"""
    cert_objs = []
    for idx, pem in enumerate(pem_certificates, start=1):
        try:
            cert_objs.append(x509.load_pem_x509_certificate(pem.encode(), default_backend()))
        except Exception as e:
            raise ValueError(f"{key_label} 第 {idx} 张证书损坏：{friendly_cert_error(e)}") from e
    return cert_objs


def verify_keychain(cert_objs):
    """
    逐级验证证书链。

    校验内容包含：颁发者/主题衔接关系，以及子证书签名是否能被父证书公钥验证。
    """
    for i in range(len(cert_objs) - 1):
        # 当前证书由下一级（父级）证书签发。
        son_certificate = cert_objs[i]
        father_certificate = cert_objs[i + 1]

        if son_certificate.issuer != father_certificate.subject:
            return False

        # 准备验签所需参数：签名值、被签名原文、父证书公钥。
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()

        try:
            # 按签名算法分支验签：RSA / ECDSA。
            if signature_algorithm in [
                "sha256WithRSAEncryption",
                "sha1WithRSAEncryption",
                "sha384WithRSAEncryption",
                "sha512WithRSAEncryption",
            ]:
                hash_algorithm = {
                    "sha256WithRSAEncryption": hashes.SHA256(),
                    "sha1WithRSAEncryption": hashes.SHA1(),
                    "sha384WithRSAEncryption": hashes.SHA384(),
                    "sha512WithRSAEncryption": hashes.SHA512(),
                }[signature_algorithm]
                public_key.verify(signature, tbs_certificate, padding.PKCS1v15(), hash_algorithm)
            elif signature_algorithm in [
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA1",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
            ]:
                hash_algorithm = {
                    "ecdsa-with-SHA256": hashes.SHA256(),
                    "ecdsa-with-SHA1": hashes.SHA1(),
                    "ecdsa-with-SHA384": hashes.SHA384(),
                    "ecdsa-with-SHA512": hashes.SHA512(),
                }[signature_algorithm]
                public_key.verify(signature, tbs_certificate, ec.ECDSA(hash_algorithm))
            else:
                # 未覆盖的算法类型暂按失败处理。
                return False
        except Exception:
            return False

    return True


def check_one_candidate(candidate, trusted_root_keys, status_json):
    """执行单个 Key 的完整检测并返回结构化结果。"""
    key_label = f"Keybox#{candidate['keybox_index']}/Key#{candidate['key_index']}"
    pem_certificates = candidate["pem_certificates"]
    if not pem_certificates:
        return {
            "key_label": key_label,
            "ok": False,
            "error": f"{key_label} 未找到 PEM 证书",
        }

    try:
        cert_objs = load_certificates_for_candidate(pem_certificates, key_label)
    except Exception as e:
        return {
            "key_label": key_label,
            "ok": False,
            "error": str(e),
        }

    # 约定：链首为叶子证书，链尾为根证书。
    leaf_cert = cert_objs[0]
    root_cert = cert_objs[-1]

    # 统一使用小写十六进制序列号，便于与吊销列表匹配。
    cert_serial = hex(leaf_cert.serial_number)[2:].lower()
    subject_text = format_subject(leaf_cert.subject)
    subject_fields = extract_subject_fields(leaf_cert.subject)

    # 有效期：基于 UTC 时间比较，避免时区歧义。
    not_valid_before = leaf_cert.not_valid_before_utc
    not_valid_after = leaf_cert.not_valid_after_utc
    now_utc = datetime.now(timezone.utc)
    validity_ok = not_valid_before <= now_utc <= not_valid_after

    # 私钥检查：格式是否可解析，以及是否与叶子证书公钥匹配。
    private_key_raw = candidate["private_key_raw"]
    private_key_valid = False
    private_match = False
    private_key_note = None
    if private_key_raw is None:
        private_key_note = "缺失 PrivateKey 字段"
    else:
        try:
            # 去掉每行开头多余空白，兼容部分缩进格式的私钥文本。
            cleaned_private_key = re.sub(re.compile(r"^\s+", re.MULTILINE), "", private_key_raw)
            private_key_obj = serialization.load_pem_private_key(
                cleaned_private_key.encode(), password=None, backend=default_backend()
            )
            private_key_valid = True
            private_match = compare_keys(private_key_obj.public_key(), leaf_cert.public_key())
        except Exception as e:
            private_key_note = f"私钥解析失败: {e}"

    # 证书链校验。
    keychain_valid = verify_keychain(cert_objs)

    # 根证书识别。
    root_type, root_desc = detect_root_certificate(root_cert.public_key(), trusted_root_keys)

    # 吊销检查：链上任意证书命中吊销条目即视为命中。
    revoke_reason = None
    revoke_sn = None
    entries = status_json.get("entries", {})
    for cert in cert_objs:
        sn_hex = hex(cert.serial_number)[2:].lower()
        entry = entries.get(sn_hex)
        if entry:
            revoke_reason = entry.get("reason", "UNKNOWN")
            revoke_sn = sn_hex
            break

    overall_status = build_overall_status(revoke_reason, keychain_valid, root_type)

    return {
        "key_label": key_label,
        "ok": True,
        "device_id": candidate["device_id"],
        "algorithm": candidate["algorithm"],
        "declared_count": candidate["declared_count"],
        "actual_count": len(cert_objs),
        "subject_fields": subject_fields,
        "subject_text": subject_text,
        "cert_serial": cert_serial,
        "not_valid_before": not_valid_before,
        "not_valid_after": not_valid_after,
        "validity_ok": validity_ok,
        "private_key_valid": private_key_valid,
        "private_match": private_match,
        "private_key_note": private_key_note,
        "keychain_valid": keychain_valid,
        "root_desc": root_desc,
        "revoke_reason": revoke_reason,
        "revoke_sn": revoke_sn,
        "overall_status": overall_status,
    }


def print_key_result(result):
    """按模块化分段打印单个 Key 的检测结果。"""
    print(f"\n🧩 检测对象：{result['key_label']}")
    if not result["ok"]:
        print(f"- 结果：❌ 解析失败")
        print(f"- 说明：{result['error']}")
        return

    print("\n📱 设备信息")
    print(f"- Device ID：{result['device_id']}")
    print(f"- 算法：{result['algorithm']}")

    print("\n🧾 证书主题信息")
    keybox_sn = result["subject_fields"]["keybox_sn"]
    if keybox_sn:
        print(f"- Keybox SN（OID 2.5.4.5）：{keybox_sn}")
    else:
        print("- Keybox SN（OID 2.5.4.5）：🟡 未提取到（可能为软件或无该字段）")
    print(f"- 证书序列号（Cert SN）：{result['cert_serial']}")
    if result["subject_fields"]["title"]:
        print(f"- Title：{result['subject_fields']['title']}")
    if result["subject_fields"]["organizationName"]:
        print(f"- Organization：{result['subject_fields']['organizationName']}")
    if result["subject_fields"]["commonName"]:
        print(f"- CommonName：{result['subject_fields']['commonName']}")
    print(f"- Subject 原文：{result['subject_text']}")

    print("\n⏳ 有效期检查")
    if result["validity_ok"]:
        print("- 结果：✅ 证书在有效期内")
    else:
        now_utc = datetime.now(timezone.utc)
        if now_utc > result["not_valid_after"]:
            print("- 结果：❌ 证书已过期")
        else:
            print("- 结果：❌ 证书尚未生效")
    print(f"- 生效时间（UTC）：{result['not_valid_before'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"- 失效时间（UTC）：{result['not_valid_after'].strftime('%Y-%m-%d %H:%M:%S')}")

    print("\n🔐 私钥检查")
    if result["private_key_valid"]:
        print("- 私钥格式：✅ 有效")
    else:
        print("- 私钥格式：❌ 无效")
        if result["private_key_note"]:
            print(f"- 说明：{result['private_key_note']}")

    if result["private_key_valid"]:
        if result["private_match"]:
            print("- 私钥与叶子证书公钥匹配：✅ 匹配")
        else:
            print("- 私钥与叶子证书公钥匹配：❌ 不匹配")
    else:
        print("- 私钥与叶子证书公钥匹配：🟡 未检查（私钥不可用）")

    print("\n🧷 证书链检查")
    print(f"- 结果：{'✅ 证书链有效' if result['keychain_valid'] else '❌ 证书链无效'}")
    print(f"- 证书数量：{result['actual_count']}")
    if result["declared_count"] is not None and result["declared_count"] != result["actual_count"]:
        print(f"- 提示：🟡 声明数量为 {result['declared_count']}，实际读取为 {result['actual_count']}")
    if result["actual_count"] >= 4:
        print("- 提示：🟡 证书链数量大于 3")

    print("\n🌐 根证书检查")
    print(f"- 结果：{result['root_desc']}")

    print("\n🚫 吊销状态检查")
    if result["revoke_reason"]:
        print("- 结果：❌ 命中 Google 吊销列表")
        print(f"- 命中序列号：{result['revoke_sn']}")
        print(f"- 吊销原因：{result['revoke_reason']}")
    else:
        print("- 结果：✅ 未命中 Google 吊销列表")

    print("\n📌 总体结论")
    print(f"- Overall Status：{result['overall_status']}")


def run_check_file(xml_path, trusted_root_keys, status_json, status_source, status_online_error):
    """检测单个 XML 文件，并输出该文件下所有 Key 的结果与汇总。"""
    print("🔍 开始检测 Keybox 文件")
    print(f"📂 文件路径：{xml_path}")

    print("\n🚫 吊销状态数据源")
    if status_source == "online":
        print("- 数据源：Google 在线状态接口")
    else:
        print("- 数据源：本地 status.json（在线失败回退）")
        if status_online_error:
            print(f"- 提示：⚠️ 在线获取失败：{status_online_error}")

    # 解析候选 Key 后逐个检测，确保单个 Key 异常不会影响其他 Key。
    candidates = parse_xml_candidates(xml_path)
    results = []
    for candidate in candidates:
        result = check_one_candidate(candidate, trusted_root_keys, status_json)
        results.append(result)
        print_key_result(result)

    # 统计文件级结果：解析失败、有效、无效。
    ok_count = 0
    bad_count = 0
    invalid_count = 0
    for item in results:
        if not item["ok"]:
            bad_count += 1
            continue
        if item["overall_status"].startswith("❌"):
            invalid_count += 1
        else:
            ok_count += 1

    print("\n🕒 检测时间")
    print(f"- UTC：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")

    print("\n📊 文件汇总")
    print(f"- 可解析 Key 数：{len(results) - bad_count}")
    print(f"- 解析失败 Key 数：{bad_count}")
    print(f"- 判定有效 Key 数：{ok_count}")
    print(f"- 判定无效 Key 数：{invalid_count}")

    # 返回码策略：存在解析失败或判定无效时返回非 0。
    if bad_count > 0 or invalid_count > 0:
        return 1
    return 0


def list_xml_files(folder_path):
    """列出目录下一层中的所有 `.xml` 文件（不递归）。"""
    xml_files = []
    for name in sorted(os.listdir(folder_path)):
        full_path = os.path.join(folder_path, name)
        if os.path.isfile(full_path) and name.lower().endswith(".xml"):
            xml_files.append(full_path)
    return xml_files


def load_trusted_root_keys(res_dir):
    """从 `res/` 目录加载预置信任根公钥。"""
    return {
        "google": load_public_key_from_file(os.path.join(res_dir, "google.pem")),
        "aosp_ec": load_public_key_from_file(os.path.join(res_dir, "aosp_ec.pem")),
        "aosp_rsa": load_public_key_from_file(os.path.join(res_dir, "aosp_rsa.pem")),
        "knox": load_public_key_from_file(os.path.join(res_dir, "knox.pem")),
    }


def run_single_or_batch(target_path):
    """自动识别目标是文件还是目录，并执行对应检测流程。"""
    # 资源目录与脚本同级，避免受当前工作目录影响。
    script_dir = os.path.dirname(os.path.abspath(__file__))
    res_dir = os.path.join(script_dir, "res")

    trusted_root_keys = load_trusted_root_keys(res_dir)
    status_json, status_source, status_online_error = fetch_revocation_status_with_fallback(res_dir)

    # 文件模式：直接检测该 XML。
    if os.path.isfile(target_path):
        return run_check_file(
            target_path,
            trusted_root_keys,
            status_json,
            status_source,
            status_online_error,
        )

    # 目录模式：按文件名排序后逐个检测。
    if os.path.isdir(target_path):
        xml_files = list_xml_files(target_path)
        if not xml_files:
            print(f"❌ 错误：目录中未找到 XML 文件 -> {target_path}")
            return 2

        print(f"📦 批量检测模式：共发现 {len(xml_files)} 个 XML 文件")
        total_ok = 0
        total_fail = 0
        file_results = {}

        # 每个文件独立 try/except，确保批量场景下不中途终止。
        for idx, xml_file in enumerate(xml_files, start=1):
            print("\n" + "=" * 64)
            print(f"📄 [{idx}/{len(xml_files)}] {xml_file}")
            print("=" * 64)
            try:
                code = run_check_file(
                    xml_file,
                    trusted_root_keys,
                    status_json,
                    status_source,
                    status_online_error,
                )
                file_results[xml_file] = code
                if code == 0:
                    total_ok += 1
                else:
                    total_fail += 1
            except Exception as e:
                total_fail += 1
                file_results[xml_file] = 1
                print(f"❌ 文件检测失败：{e}")

        print("\n" + "=" * 64)
        print("📋 批量检测汇总")
        print(f"- 文件总数：{len(xml_files)}")
        print(f"- 成功文件数：{total_ok}")
        print(f"- 失败文件数：{total_fail}")
        for xml_file, code in file_results.items():
            icon = "✅" if code == 0 else "❌"
            print(f"- {icon} {xml_file}")

        if total_fail > 0:
            return 1
        return 0

    print(f"❌ 错误：输入路径不存在 -> {target_path}")
    return 2


def main():
    """命令行入口：解析参数并返回进程退出码。"""
    parser = argparse.ArgumentParser(description="Keybox 检测脚本")
    parser.add_argument("target", help="keybox.xml 文件路径或目录路径")
    args = parser.parse_args()

    try:
        return run_single_or_batch(args.target)
    except Exception as e:
        print(f"❌ 检测失败：{e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
