package cn.rentaotao.commons.codec;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author rtt
 * @date 2023/4/21 17:06
 */
public class Rsa {
    /**
     * 算法名称
     */
    public static final String KEY_ALGORITHM = "RSA";

    public static final KeyFactory KEY_FACTORY;

    public Rsa() {
    }

    /**
     * 生成秘钥对
     *
     * @param config RsaConfig
     * @return 秘钥对
     * @throws NoSuchAlgorithmException 异常
     */
    public static SecretKey createSecretKey(RsaConfig config) throws NoSuchAlgorithmException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(config.getKeySize());
        KeyPair keyPair = rsa.generateKeyPair();
        String privateKey = encodeBase64(keyPair.getPrivate().getEncoded());
        String publicKey = encodeBase64(keyPair.getPublic().getEncoded());
        return new SecretKey(privateKey, publicKey);
    }

    /**
     * base64 解码
     *
     * @param str 待解码的字符串
     * @return 解码后的字节数组
     */
    public static byte[] decodeBase64(String str) {
        String base64 = str.replace("-", "+").replace("_", "/");
        int mod = base64.length() % 4;
        if (mod > 0) {
            base64 = base64 + "====".substring(mod);
        }

        return Base64.decodeBase64(base64);
    }

    /**
     * base64 编码
     *
     * @param bytes 待编码的字节数组
     * @return 编码后的字符串
     */
    public static String encodeBase64(byte[] bytes) {
        return Base64.encodeBase64URLSafeString(bytes);
    }

    /**
     * 私钥加密
     *
     * @param str 待加密内容
     * @param privateKey 私钥
     * @param config RsaConfig
     * @return 加密后，经 base64 编码的内容
     * @throws Exception 异常
     */
    public static String encryptByPrivateKey(String str, String privateKey, RsaConfig config) throws Exception {
        PrivateKey key = KEY_FACTORY.generatePrivate(new PKCS8EncodedKeySpec(decodeBase64(privateKey)));
        Cipher cipher = Cipher.getInstance(KEY_FACTORY.getAlgorithm());
        cipher.init(1, key);
        return encodeBase64(encryptAndDecrypt(str.getBytes(StandardCharsets.UTF_8), cipher, config.getMaxEncryptSize()));
    }

    /**
     * 公钥加密
     *
     * @param str 待加密内容
     * @param publicKey 公钥
     * @param config RsaConfig
     * @return 加密后，经 base64 编码的内容
     * @throws Exception 异常
     */
    public static String encryptByPublicKey(String str, String publicKey, RsaConfig config) throws Exception {
        PublicKey key = KEY_FACTORY.generatePublic(new X509EncodedKeySpec(decodeBase64(publicKey)));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(1, key);
        return encodeBase64(encryptAndDecrypt(str.getBytes(StandardCharsets.UTF_8), cipher, config.getMaxEncryptSize()));
    }

    /**
     * 公钥解密
     *
     * @param str 待解密内容
     * @param publicKey 公钥
     * @param config RsaConfig
     * @return 解密后的内容
     * @throws Exception 异常
     */
    public static String decryptByPublicKey(String str, String publicKey, RsaConfig config) throws Exception {
        PublicKey key = KEY_FACTORY.generatePublic(new X509EncodedKeySpec(decodeBase64(publicKey)));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(2, key);
        return new String(encryptAndDecrypt(decodeBase64(str), cipher, config.getMaxDecryptSize()), StandardCharsets.UTF_8);
    }

    /**
     * 私钥解密
     *
     * @param str 待解密内容
     * @param privateKey 私钥
     * @param config RsaConfig
     * @return 解密后的内容
     * @throws Exception 异常
     */
    public static String decryptByPrivateKey(String str, String privateKey, RsaConfig config) throws Exception {
        PrivateKey key = KEY_FACTORY.generatePrivate(new PKCS8EncodedKeySpec(decodeBase64(privateKey)));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(2, key);
        return new String(encryptAndDecrypt(decodeBase64(str), cipher, config.getMaxDecryptSize()), StandardCharsets.UTF_8);
    }

    /**
     * 加密解密
     *
     * @param data 待加密解密内容
     * @param cipher Cipher
     * @param maxSize 最大加密解密长度
     * @return 加密解密后的内容
     * @throws Exception 异常
     */
    private static byte[] encryptAndDecrypt(byte[] data, Cipher cipher, int maxSize) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] cache;
        try {
            int inputLen = data.length;

            for(int offSet = 0; inputLen - offSet > 0; offSet += maxSize) {
                if (inputLen - offSet > maxSize) {
                    cache = cipher.doFinal(data, offSet, maxSize);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }

                out.write(cache, 0, cache.length);
            }

            cache = out.toByteArray();
        } catch (Throwable var8) {
            try {
                out.close();
            } catch (Throwable var7) {
                var8.addSuppressed(var7);
            }

            throw var8;
        }

        out.close();
        return cache;
    }

    /**
     * 签名
     *
     * @param content 待签名内容
     * @param privateKey 私钥
     * @param signatureAlgorithm 签名算法
     * @return base64编码的签名
     * @throws Exception 异常
     */
    public static String sign(String content, String privateKey, SignatureAlgorithm signatureAlgorithm) throws Exception {
        return sign(content.getBytes(StandardCharsets.UTF_8), privateKey, signatureAlgorithm);
    }

    /**
     * 签名
     *
     * @param bytes 待签名内容
     * @param privateKey 私钥
     * @param signatureAlgorithm 签名算法
     * @return base64编码的签名
     * @throws Exception 异常
     */
    public static String sign(byte[] bytes, String privateKey, SignatureAlgorithm signatureAlgorithm) throws Exception {
        PrivateKey key = KEY_FACTORY.generatePrivate(new PKCS8EncodedKeySpec(decodeBase64(privateKey)));
        Signature signature = Signature.getInstance(signatureAlgorithm.getAlgorithm());
        signature.initSign(key);
        signature.update(bytes);
        return encodeBase64(signature.sign());
    }

    /**
     * 签名验证
     *
     * @param content 待签名内容
     * @param sign 签名
     * @param publicKey 公钥
     * @param signatureAlgorithm 签名算法
     * @return true:验证通过 false:验证失败
     * @throws Exception 异常
     */
    public static boolean verify(String content, String sign, String publicKey, SignatureAlgorithm signatureAlgorithm) throws Exception {
        PublicKey key = KEY_FACTORY.generatePublic(new X509EncodedKeySpec(decodeBase64(publicKey)));
        Signature signature = Signature.getInstance(signatureAlgorithm.getAlgorithm());
        signature.initVerify(key);
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        return signature.verify(decodeBase64(sign));
    }

    static {
        try {
            KEY_FACTORY = KeyFactory.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException var1) {
            throw new RuntimeException(var1);
        }
    }

    /**
     * 密钥对
     */
    public static class SecretKey {
        private final String privateKey;
        private final String publicKey;

        public SecretKey(String privateKey, String publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return this.privateKey;
        }

        public String getPublicKey() {
            return this.publicKey;
        }
    }

    /**
     * RSA配置
     */
    public enum RsaConfig {
        RSA1024(1024, 117, 128),
        RSA2048(2048, 245, 256),
        RSA4096(4096, 501, 512);

        private final int keySize;
        private final int maxEncryptSize;
        private final int maxDecryptSize;

        RsaConfig(int keySize, int maxEncryptSize, int maxDecryptSize) {
            this.keySize = keySize;
            this.maxEncryptSize = maxEncryptSize;
            this.maxDecryptSize = maxDecryptSize;
        }

        public int getKeySize() {
            return this.keySize;
        }

        public int getMaxEncryptSize() {
            return this.maxEncryptSize;
        }

        public int getMaxDecryptSize() {
            return this.maxDecryptSize;
        }
    }

    /**
     * 签名算法
     */
    public enum SignatureAlgorithm {
        SHA256WithRSA("SHA256WithRSA"),
        MD5withRSA("MD5withRSA");

        private final String algorithm;

        SignatureAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return this.algorithm;
        }
    }
}
