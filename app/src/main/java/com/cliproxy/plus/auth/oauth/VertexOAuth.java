package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Iterator;

/**
 * VertexOAuth 提供 Google Vertex AI Gemini 服务账号密钥的规范化与凭证存储功能。
 * <p>
 * 主要功能：
 * 1. 解析服务账号 JSON，规范化 private_key 字段（换行符、ANSI 转义、UTF-8 校验、
 *    PEM 解码、RSA 密钥验证、PKCS#8 转 PKCS#1、PEM 重新编码）。
 * 2. 如果 PEM 标记损坏，则从 base64 载荷重建 PEM。
 * 3. 凭证存储：{service_account: 完整 GCP SA JSON, project_id, email, location:us-central1,
 *    type:vertex, prefix}。
 * <p>
 * 1:1 移植自 CLIProxyAPIPlus/internal/auth/vertex/。
 */
public class VertexOAuth {

    private static final String TAG = "VertexOAuth";

    // ========================================================================
    // 1. 服务账号 JSON 规范化入口
    // ========================================================================

    /**
     * 规范化给定的 JSON 字符串格式的服务账号载荷。
     * 返回规范化后的 JSON 字符串（private_key 已被清理），如果规范化失败则返回原始字节和错误。
     * <p>
     * 1:1 移植自 Go NormalizeServiceAccountJSON()。
     *
     * @param raw 原始服务账号 JSON 字符串
     * @return 规范化后的 JSON 字符串
     * @throws OAuthProvider.OAuthException 如果 JSON 解析或规范化失败
     */
    public static String normalizeServiceAccountJSON(String raw) throws OAuthProvider.OAuthException {
        if (raw == null || raw.isEmpty()) {
            Log.d(TAG, "normalizeServiceAccountJSON: raw input is empty, returning as-is");
            return raw;
        }
        try {
            JSONObject payload = new JSONObject(raw);
            JSONObject normalized = normalizeServiceAccountMap(payload);
            return normalized.toString(2);
        } catch (JSONException e) {
            Log.e(TAG, "normalizeServiceAccountJSON: JSON parse error: " + e.getMessage());
            // 返回原始输入（与 Go 版一致：返回 raw 和 error）
            // 但在 Java 中通过异常传播
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "failed to parse service account JSON: " + e.getMessage(), e);
        }
    }

    /**
     * 返回服务账号 JSONObject 的副本，其中 private_key 字段已被规范化，
     * 保证包含有效的 RSA PRIVATE KEY PEM 块。
     * <p>
     * 1:1 移植自 Go NormalizeServiceAccountMap()。
     *
     * @param sa 原始服务账号 JSONObject
     * @return 规范化后的副本 JSONObject
     * @throws OAuthProvider.OAuthException 如果规范化失败
     */
    public static JSONObject normalizeServiceAccountMap(JSONObject sa) throws OAuthProvider.OAuthException {
        if (sa == null) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "service account payload is empty");
        }
        String pk = sa.optString("private_key", "").trim();
        if (pk.isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "service account missing private_key");
        }
        Log.d(TAG, "normalizeServiceAccountMap: sanitizing private_key");
        String normalized = sanitizePrivateKey(pk);
        // 创建副本（1:1 移植自 Go clone map）
        JSONObject clone = new JSONObject();
        try {
            Iterator<String> keys = sa.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                clone.put(key, sa.get(key));
            }
            clone.put("private_key", normalized);
        } catch (JSONException e) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "failed to clone service account map: " + e.getMessage(), e);
        }
        Log.d(TAG, "normalizeServiceAccountMap: normalization complete");
        return clone;
    }

    // ========================================================================
    // 2. 私钥清理管线
    // ========================================================================

    /**
     * 清理私钥字符串：替换换行符、去除 ANSI 转义序列、校验 UTF-8、
     * 解码 PEM、验证 RSA 密钥、确保输出为 PKCS#1 格式的 PEM。
     * <p>
     * 1:1 移植自 Go sanitizePrivateKey()。
     *
     * @param raw 原始私钥字符串
     * @return 规范化后的 PEM 字符串（RSA PRIVATE KEY 格式）
     * @throws OAuthProvider.OAuthException 如果清理失败
     */
    private static String sanitizePrivateKey(String raw) throws OAuthProvider.OAuthException {
        // 步骤 1：替换换行符（1:1 移植自 Go strings.ReplaceAll）
        String pk = raw.replace("\r\n", "\n");
        pk = pk.replace("\r", "\n");

        // 步骤 2：去除 ANSI 转义序列
        pk = stripANSIEscape(pk);

        // 步骤 3：确保 UTF-8 有效（替换无效序列为空字符串）
        pk = toValidUTF8(pk);

        // 步骤 4：去除首尾空白
        pk = pk.trim();

        String normalized = pk;

        // 步骤 5：尝试解码 PEM
        PemBlock block = decodePem(pk);
        if (block == null) {
            // 尝试从文本载荷重建 PEM（1:1 移植自 Go rebuildPEM）
            Log.d(TAG, "sanitizePrivateKey: PEM decode failed, attempting rebuild");
            String reconstructed = rebuildPEM(pk);
            if (reconstructed != null) {
                normalized = reconstructed;
            } else {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "private_key is not valid pem: could not reconstruct PEM");
            }
        }

        // 步骤 6：再次解码以确保得到有效的 PEM Block
        PemBlock finalBlock = decodePem(normalized);
        if (finalBlock == null) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "private_key pem decode failed after reconstruction");
        }

        // 步骤 7：确保是 RSA 私钥并输出 PKCS#1 格式
        String result = ensureRSAPrivateKey(finalBlock);
        Log.d(TAG, "sanitizePrivateKey: private key normalized successfully");
        return result;
    }

    /**
     * 确保给定的 PEM Block 是 RSA PRIVATE KEY（PKCS#1）格式。
     * 接受 RSA PRIVATE KEY（PKCS#1）、PRIVATE KEY（PKCS#8）或自动检测格式。
     * 始终输出 RSA PRIVATE KEY PEM。
     * <p>
     * 1:1 移植自 Go ensureRSAPrivateKey()。
     *
     * @param block 解析后的 PEM Block
     * @return 规范化后的 PEM 字符串（RSA PRIVATE KEY 格式）
     * @throws OAuthProvider.OAuthException 如果密钥格式不支持或无效
     */
    private static String ensureRSAPrivateKey(PemBlock block) throws OAuthProvider.OAuthException {
        if (block == null) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "pem block is nil");
        }

        byte[] derBytes = block.bytes;

        // 情况 1：已经是 RSA PRIVATE KEY（PKCS#1）—— 验证有效性
        if ("RSA PRIVATE KEY".equals(block.type)) {
            Log.d(TAG, "ensureRSAPrivateKey: detected RSA PRIVATE KEY (PKCS#1)");
            try {
                // 通过转换为 PKCS#8 来验证 PKCS#1 DER 的有效性
                byte[] pkcs8 = pkcs1ToPkcs8Der(derBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
                kf.generatePrivate(keySpec);
                Log.d(TAG, "ensureRSAPrivateKey: PKCS#1 key is valid RSA");
            } catch (Exception e) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "private_key invalid rsa: " + e.getMessage(), e);
            }
            // 返回原始 DER 的 PEM 编码（1:1 移植自 Go return block）
            return encodePem("RSA PRIVATE KEY", derBytes);
        }

        // 情况 2：PRIVATE KEY（PKCS#8）
        if ("PRIVATE KEY".equals(block.type)) {
            Log.d(TAG, "ensureRSAPrivateKey: detected PRIVATE KEY (PKCS#8), converting to PKCS#1");
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derBytes);
                PrivateKey privKey = kf.generatePrivate(keySpec);
                if (!(privKey instanceof RSAPrivateCrtKey)) {
                    throw new OAuthProvider.OAuthException(
                            OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                            "private_key is not an RSA key");
                }
                RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) privKey;
                byte[] pkcs1Der = encodePkcs1Der(rsaKey);
                return encodePem("RSA PRIVATE KEY", pkcs1Der);
            } catch (GeneralSecurityException e) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "private_key invalid pkcs8: " + e.getMessage(), e);
            }
        }

        // 情况 3：自动检测 —— 尝试 PKCS#1 然后 PKCS#8
        Log.d(TAG, "ensureRSAPrivateKey: unknown type '" + block.type + "', attempting auto-detect");
        try {
            // 尝试 PKCS#1
            Log.d(TAG, "ensureRSAPrivateKey: trying PKCS#1");
            byte[] pkcs8 = pkcs1ToPkcs8Der(derBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
            PrivateKey privKey = kf.generatePrivate(keySpec);
            if (privKey instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) privKey;
                byte[] pkcs1Der = encodePkcs1Der(rsaKey);
                Log.d(TAG, "ensureRSAPrivateKey: auto-detected as PKCS#1");
                return encodePem("RSA PRIVATE KEY", pkcs1Der);
            }
        } catch (Exception ignored) {
            // 继续尝试 PKCS#8
        }

        try {
            // 尝试 PKCS#8
            Log.d(TAG, "ensureRSAPrivateKey: trying PKCS#8");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derBytes);
            PrivateKey privKey = kf.generatePrivate(keySpec);
            if (privKey instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) privKey;
                byte[] pkcs1Der = encodePkcs1Der(rsaKey);
                Log.d(TAG, "ensureRSAPrivateKey: auto-detected as PKCS#8");
                return encodePem("RSA PRIVATE KEY", pkcs1Der);
            }
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "private_key is not an RSA key");
        } catch (GeneralSecurityException e) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "private_key uses unsupported format: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // 3. PEM 重建（从损坏的 PEM 文本中提取 base64 载荷）
    // ========================================================================

    /**
     * 从损坏/混乱的 PEM 文本中重建有效的 PEM 块。
     * 通过查找 BEGIN/END 标记之间的内容，过滤出有效的 base64 字符，解码后重新编码。
     * <p>
     * 1:1 移植自 Go rebuildPEM()。
     *
     * @param raw 原始的、可能损坏的 PEM 字符串
     * @return 重建后的 PEM 字符串，如果无法重建则返回 null
     */
    private static String rebuildPEM(String raw) {
        String kind = "PRIVATE KEY";
        if (raw.contains("RSA PRIVATE KEY")) {
            kind = "RSA PRIVATE KEY";
        }
        String header = "-----BEGIN " + kind + "-----";
        String footer = "-----END " + kind + "-----";
        int start = raw.indexOf(header);
        int end = raw.indexOf(footer);
        if (start < 0 || end <= start) {
            Log.e(TAG, "rebuildPEM: missing pem markers");
            return null;
        }
        String body = raw.substring(start + header.length(), end);
        String payload = filterBase64(body);
        if (payload.isEmpty()) {
            Log.e(TAG, "rebuildPEM: base64 payload empty");
            return null;
        }
        try {
            byte[] der = Base64.getDecoder().decode(payload);
            return encodePem(kind, der);
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "rebuildPEM: base64 decode failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * 过滤字符串，只保留有效的 base64 字符（A-Z, a-z, 0-9, +, /, =）。
     * <p>
     * 1:1 移植自 Go filterBase64()。
     *
     * @param s 输入字符串
     * @return 只包含有效 base64 字符的字符串
     */
    private static String filterBase64(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') ||
                    c == '+' || c == '/' || c == '=') {
                sb.append(c);
            }
            // 其他字符跳过（1:1 移植自 Go default: skip）
        }
        return sb.toString();
    }

    // ========================================================================
    // 4. ANSI 转义序列剥离
    // ========================================================================

    /**
     * 剥离字符串中的 ANSI 转义序列。
     * 处理 CSI 序列（ESC [ ... 字母）和 OSC 序列（ESC ] ... (BEL | ESC \)）。
     * <p>
     * 1:1 移植自 Go stripANSIEscape()。
     *
     * @param s 可能包含 ANSI 转义序列的字符串
     * @return 已清理的字符串
     */
    private static String stripANSIEscape(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != 0x1b) {
                out.append(c);
                i++;
                continue;
            }
            // 遇到了 ESC 字符
            if (i + 1 >= s.length()) {
                break;
            }
            char next = s.charAt(i + 1);
            switch (next) {
                case ']': // OSC 序列（ESC ] ... BEL 或 ESC \）
                    i += 2;
                    while (i < s.length()) {
                        if (s.charAt(i) == 0x07) {
                            break;
                        }
                        if (s.charAt(i) == 0x1b && i + 1 < s.length() && s.charAt(i + 1) == '\\') {
                            i++;
                            break;
                        }
                        i++;
                    }
                    i++; // 跳过终止符
                    break;
                case '[': // CSI 序列（ESC [ ... 字母）
                    i += 2;
                    while (i < s.length()) {
                        char ci = s.charAt(i);
                        if ((ci >= 'A' && ci <= 'Z') || (ci >= 'a' && ci <= 'z')) {
                            break;
                        }
                        i++;
                    }
                    i++; // 跳过终止字母
                    break;
                default:
                    // 单独的 ESC 字符，跳过
                    i++;
                    break;
            }
        }
        return out.toString();
    }

    // ========================================================================
    // 5. PEM 编解码工具
    // ========================================================================

    /**
     * 表示一个 PEM 块，包含类型标记和 DER 字节。
     */
    private static class PemBlock {
        /** PEM 类型，如 "RSA PRIVATE KEY" 或 "PRIVATE KEY"。 */
        String type;
        /** DER 编码的字节数据。 */
        byte[] bytes;

        PemBlock(String type, byte[] bytes) {
            this.type = type;
            this.bytes = bytes;
        }
    }

    /**
     * 解码 PEM 字符串，提取类型和 DER 字节。
     * 查找 "-----BEGIN <type>-----" 和 "-----END <type>-----" 标记之间的 base64 内容。
     *
     * @param pem PEM 格式的字符串
     * @return PemBlock 对象，如果解码失败则返回 null
     */
    private static PemBlock decodePem(String pem) {
        if (pem == null || pem.isEmpty()) {
            return null;
        }
        // 查找 BEGIN 标记
        int beginIdx = pem.indexOf("-----BEGIN ");
        if (beginIdx < 0) {
            return null;
        }
        int typeStart = beginIdx + "-----BEGIN ".length();
        int typeEnd = pem.indexOf("-----", typeStart);
        if (typeEnd < 0) {
            return null;
        }
        String type = pem.substring(typeStart, typeEnd).trim();

        // 查找 END 标记
        String endMarker = "-----END " + type + "-----";
        int endIdx = pem.indexOf(endMarker, typeEnd);
        if (endIdx < 0) {
            return null;
        }

        // 提取 base64 内容
        String body = pem.substring(typeEnd + "-----".length(), endIdx).trim();
        // 过滤出有效的 base64 字符
        body = filterBase64(body);

        if (body.isEmpty()) {
            return null;
        }

        try {
            byte[] der = Base64.getDecoder().decode(body);
            return new PemBlock(type, der);
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "decodePem: base64 decode failed for type " + type + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * 将 DER 字节编码为 PEM 格式的字符串。
     *
     * @param type PEM 类型标记（如 "RSA PRIVATE KEY"）
     * @param der  DER 编码的字节数据
     * @return PEM 格式的字符串
     */
    private static String encodePem(String type, byte[] der) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        // 每 64 个字符换行（标准 PEM 格式）
        for (int i = 0; i < base64.length(); i += 64) {
            int end = Math.min(i + 64, base64.length());
            sb.append(base64, i, end).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }

    // ========================================================================
    // 6. DER 编码工具（PKCS#1 和 PKCS#8）
    // ========================================================================

    /**
     * DER 标记常量。
     */
    private static final int TAG_INTEGER = 0x02;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_SEQUENCE = 0x30;

    /**
     * RSA 算法标识符的 DER 编码（OID 1.2.840.113549.1.1.1 + NULL）。
     * 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00
     */
    private static final byte[] RSA_ALGORITHM_IDENTIFIER = new byte[]{
            (byte) 0x30, 0x0d,
            (byte) 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
            (byte) 0x05, 0x00
    };

    /**
     * 将 PKCS#1 的 DER 字节包装为 PKCS#8 格式。
     * <p>
     * PKCS#8 结构：
     * SEQUENCE {
     *   INTEGER 0 (版本)
     *   SEQUENCE { OID 1.2.840.113549.1.1.1, NULL } (算法标识符)
     *   OCTET STRING { PKCS#1 DER } (私钥)
     * }
     * <p>
     * 1:1 移植自 Go 中通过 ParsePKCS1PrivateKey + MarshalPKCS1PrivateKey 的逆操作，
     * 用于验证 PKCS#1 密钥的有效性。
     *
     * @param pkcs1Der PKCS#1 格式的 DER 字节
     * @return PKCS#8 格式的 DER 字节
     * @throws IOException 如果 DER 编码失败
     */
    private static byte[] pkcs1ToPkcs8Der(byte[] pkcs1Der) throws IOException {
        // 构造 PKCS#8 的三个元素
        // 1. 版本 INTEGER 0
        byte[] version = encodeDerTag(TAG_INTEGER, new byte[]{0x00});
        // 2. 算法标识符（预编码）
        byte[] algorithmId = RSA_ALGORITHM_IDENTIFIER;
        // 3. 私钥 OCTET STRING（PKCS#1 DER）
        byte[] privateKey = encodeDerTag(TAG_OCTET_STRING, pkcs1Der);

        // 组合为 SEQUENCE
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(version);
        baos.write(algorithmId);
        baos.write(privateKey);
        byte[] content = baos.toByteArray();
        return encodeDerTag(TAG_SEQUENCE, content);
    }

    /**
     * 编码 DER TLV（Tag-Length-Value）结构。
     *
     * @param tag   DER 标记
     * @param value 载荷字节
     * @return 编码后的 DER 字节
     * @throws IOException 如果输出流写入失败
     */
    private static byte[] encodeDerTag(int tag, byte[] value) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(tag);
        encodeDerLength(baos, value.length);
        baos.write(value);
        return baos.toByteArray();
    }

    /**
     * 编码 DER 长度（支持长格式）。
     */
    private static void encodeDerLength(OutputStream os, int length) throws IOException {
        if (length < 128) {
            os.write(length);
        } else {
            // 计算需要的字节数
            int numBytes = 0;
            int tmp = length;
            while (tmp > 0) {
                numBytes++;
                tmp >>= 8;
            }
            // 写入长度标志（高位为 1 表示长格式，低 7 位为后续字节数）
            os.write(0x80 | numBytes);
            // 写入长度值（大端序）
            for (int i = numBytes - 1; i >= 0; i--) {
                os.write((length >> (i * 8)) & 0xFF);
            }
        }
    }

    /**
     * 从 RSAPrivateCrtKey 中提取各组件，编码为 PKCS#1 DER 格式。
     * <p>
     * PKCS#1 RSAPrivateKey 结构：
     * SEQUENCE {
     *   INTEGER 0 (版本),
     *   INTEGER (模数 n),
     *   INTEGER (公开指数 e),
     *   INTEGER (私有指数 d),
     *   INTEGER (素数1 p),
     *   INTEGER (素数2 q),
     *   INTEGER (指数1 dp),
     *   INTEGER (指数2 dq),
     *   INTEGER (系数 qi)
     * }
     * <p>
     * 1:1 移植自 Go x509.MarshalPKCS1PrivateKey()。
     *
     * @param rsaKey RSA 私钥（CRT 格式）
     * @return PKCS#1 格式的 DER 字节
     * @throws OAuthProvider.OAuthException 如果编码失败
     */
    private static byte[] encodePkcs1Der(RSAPrivateCrtKey rsaKey) throws OAuthProvider.OAuthException {
        try {
            // 版本 INTEGER 0
            byte[] version = encodeDerTag(TAG_INTEGER, new byte[]{0x00});
            // 各组件转为 INTEGER
            byte[] modulus = encodeDerInteger(rsaKey.getModulus());
            byte[] publicExponent = encodeDerInteger(rsaKey.getPublicExponent());
            byte[] privateExponent = encodeDerInteger(rsaKey.getPrivateExponent());
            byte[] prime1 = encodeDerInteger(rsaKey.getPrimeP());
            byte[] prime2 = encodeDerInteger(rsaKey.getPrimeQ());
            byte[] exponent1 = encodeDerInteger(rsaKey.getPrimeExponentP());
            byte[] exponent2 = encodeDerInteger(rsaKey.getPrimeExponentQ());
            byte[] coefficient = encodeDerInteger(rsaKey.getCrtCoefficient());

            // 组合为 SEQUENCE
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(version);
            baos.write(modulus);
            baos.write(publicExponent);
            baos.write(privateExponent);
            baos.write(prime1);
            baos.write(prime2);
            baos.write(exponent1);
            baos.write(exponent2);
            baos.write(coefficient);
            byte[] content = baos.toByteArray();
            return encodeDerTag(TAG_SEQUENCE, content);
        } catch (IOException e) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "failed to encode PKCS#1 DER: " + e.getMessage(), e);
        }
    }

    /**
     * 编码 DER INTEGER。
     * BigInteger.toByteArray() 已经包含正确的符号位处理。
     */
    private static byte[] encodeDerInteger(BigInteger n) throws IOException {
        byte[] rawBytes = n.toByteArray();
        return encodeDerTag(TAG_INTEGER, rawBytes);
    }

    // ========================================================================
    // 7. UTF-8 校验工具
    // ========================================================================

    /**
     * 将字符串转换为有效的 UTF-8，替换无效序列为空字符串。
     * <p>
     * 1:1 移植自 Go strings.ToValidUTF8(s, "")。
     *
     * @param s 输入字符串
     * @return 仅包含有效 UTF-8 序列的字符串
     */
    private static String toValidUTF8(String s) {
        if (s == null) {
            return null;
        }
        // 通过编码再解码来过滤无效 UTF-8 序列
        byte[] utf8Bytes = s.getBytes(StandardCharsets.UTF_8);
        // 由于 Java 字符串总是有效的 UTF-16，我们用 StandardCharsets 编码再解码时
        // 不会丢失字符。但输入可能包含无效的 UTF-8 字节序列（在 Java 中表现为
        // 代理对或未分配的码点）。为了真正模拟 Go 的 ToValidUTF8，
        // 我们逐个码点检查。
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); ) {
            int codePoint = s.codePointAt(i);
            // 检查是否是有效的 Unicode 标量值
            // Go 的 ToValidUTF8 会替换无效的 UTF-8 字节序列。
            // 在 Java 中，字符串总是 UTF-16，但可能包含代理对。
            // 如果码点是一个孤立的代理（不在代理对中），则替换它。
            if (Character.isSurrogate((char) codePoint)) {
                // 孤立代理 —— 跳过
                i++;
                continue;
            }
            // 检查是否是替换字符本身（U+FFFD），Go 的 ToValidUTF8 会保留它
            // 但这里我们只过滤无效的 UTF-8 序列
            sb.appendCodePoint(codePoint);
            i += Character.charCount(codePoint);
        }
        return sb.toString();
    }

    // ========================================================================
    // 8. 凭证存储（VertexCredentialStorage）
    // ========================================================================

    /**
     * VertexCredentialStorage 存储用于 Vertex AI 访问的服务账号 JSON。
     * 内容按原样持久化在 "service_account" 键下，同时包含 project_id、location、
     * email 等辅助字段，以改善日志和发现。
     * <p>
     * 1:1 移植自 Go VertexCredentialStorage struct。
     */
    public static class VertexCredentialStorage {

        /** ServiceAccount 持有解析后的服务账号 JSON 内容。 */
        public JSONObject serviceAccount;

        /** ProjectID 派生自服务账号 JSON（project_id 字段）。 */
        public String projectId;

        /** Email 是服务账号 JSON 中的 client_email。 */
        public String email;

        /** Location 可选地设置 Vertex 端点的默认区域（例如 us-central1）。 */
        public String location;

        /** Type 是与凭证一起存储的提供商标识符。始终为 "vertex"。 */
        public String type;

        /**
         * Prefix 可选地为该凭证的模型添加命名空间（例如 "teamA"）。
         * 结果模型名称如 "teamA/gemini-2.0-flash"。
         */
        public String prefix;

        /**
         * 使用服务账号 JSONObject 构造 VertexCredentialStorage。
         * 自动从 serviceAccount 中提取 project_id 和 client_email。
         *
         * @param serviceAccount 规范化后的服务账号 JSONObject
         * @throws OAuthProvider.OAuthException 如果 serviceAccount 为空或缺少必要字段
         */
        public VertexCredentialStorage(JSONObject serviceAccount) throws OAuthProvider.OAuthException {
            if (serviceAccount == null) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "vertex credential: service account content is empty");
            }
            this.serviceAccount = serviceAccount;
            this.projectId = serviceAccount.optString("project_id", "");
            this.email = serviceAccount.optString("client_email", "");
            this.location = "us-central1";
            this.type = "vertex";
            this.prefix = "";
            Log.d(TAG, "VertexCredentialStorage: created for project=" + projectId + " email=" + email);
        }

        /**
         * 使用所有字段构造 VertexCredentialStorage。
         *
         * @param serviceAccount 规范化后的服务账号 JSONObject
         * @param projectId      Google Cloud 项目 ID
         * @param email          服务账号邮箱
         * @param location       Vertex 端点区域
         * @param prefix         模型命名空间前缀
         */
        public VertexCredentialStorage(JSONObject serviceAccount, String projectId,
                                       String email, String location, String prefix) {
            this.serviceAccount = serviceAccount;
            this.projectId = projectId != null ? projectId : "";
            this.email = email != null ? email : "";
            this.location = location != null ? location : "us-central1";
            this.type = "vertex";
            this.prefix = prefix != null ? prefix : "";
        }

        /**
         * 将凭证载荷以 JSON 格式写入给定的文件路径。
         * 确保父目录存在，并记录操作以便透明审计。
         * <p>
         * 1:1 移植自 Go SaveTokenToFile()。
         *
         * @param authFilePath 凭证文件路径
         * @throws OAuthProvider.OAuthException 如果保存失败
         */
        public void saveToFile(String authFilePath) throws OAuthProvider.OAuthException {
            Log.d(TAG, "Saving credentials to " + authFilePath);

            if (serviceAccount == null) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "vertex credential: service account content is empty");
            }

            // 确保标记文件为提供商类型（1:1 移植自 Go s.Type = "vertex"）
            this.type = "vertex";

            // 构建输出 JSONObject
            JSONObject output = new JSONObject();
            try {
                // service_account 字段
                output.put("service_account", serviceAccount);

                // 辅助字段
                output.put("project_id", projectId != null ? projectId : "");
                output.put("email", email != null ? email : "");
                output.put("location", location != null ? location : "us-central1");
                output.put("type", "vertex");

                if (prefix != null && !prefix.isEmpty()) {
                    output.put("prefix", prefix);
                }
            } catch (JSONException e) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "vertex credential: failed to build JSON: " + e.getMessage(), e);
            }

            // 确保父目录存在（1:1 移植自 Go os.MkdirAll）
            File authFile = new File(authFilePath);
            File parentDir = authFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                if (!parentDir.mkdirs()) {
                    throw new OAuthProvider.OAuthException(
                            OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                            "vertex credential: failed to create directory: " + parentDir.getAbsolutePath());
                }
                Log.d(TAG, "saveToFile: created directory " + parentDir.getAbsolutePath());
            }

            // 写入文件（1:1 移植自 Go os.Create + json.Encoder）
            try (FileOutputStream fos = new FileOutputStream(authFile)) {
                String jsonStr = output.toString(2);
                fos.write(jsonStr.getBytes(StandardCharsets.UTF_8));
                fos.flush();
                Log.d(TAG, "saveToFile: credentials saved to " + authFilePath);
            } catch (IOException | JSONException e) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "vertex credential: failed to write file: " + e.getMessage(), e);
            }
        }

        // ====== Getter / Setter ======

        public JSONObject getServiceAccount() {
            return serviceAccount;
        }

        public void setServiceAccount(JSONObject serviceAccount) {
            this.serviceAccount = serviceAccount;
        }

        public String getProjectId() {
            return projectId;
        }

        public void setProjectId(String projectId) {
            this.projectId = projectId;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getLocation() {
            return location;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getPrefix() {
            return prefix;
        }

        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }
    }
}