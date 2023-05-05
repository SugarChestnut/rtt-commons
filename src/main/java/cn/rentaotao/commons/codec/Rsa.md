# RSA 加密类文档

## 1. 说明

### 1.1. 作用
用于RSA加密解密，签名验签，密钥生成等操作

### 1.2. 依赖
```xml
<dependency>
    <groupId>commons-codec</groupId>
    <artifactId>commons-codec</artifactId>
    <version>1.15</version>
</dependency>
```

### 1.3. RSA 长度
RsaConfig 中定义了常用的RSA长度，可以根据需要自行修改</br>
加解密使用的密钥程度必须相同，否则会报错

## 2. 使用

### 2.1 生成密钥对
```java
/**
 * @param config 配置
 */
Rsa.createSecretKey(RsaConfig config);
```

### 2.2. 公钥加密
```java
/**
 * @param str 待加密字符串
 * @param publicKey 公钥
 * @param config 配置
 */
Rsa.encryptByPublicKey(String str, String publicKey, RsaConfig config);
```

### 2.3. 私钥加密
```java
/**
 * @param str 待加密字符串
 * @param privateKey 私钥
 * @param config 配置
 */
Rsa.encryptByPrivateKey(String str, String privateKey, RsaConfig config);
```

### 2.4. 公钥解密
```java
/**
 * @param str 待解密字符串
 * @param publicKey 公钥
 * @param config 配置
 */
Rsa.decryptByPublicKey(String str, String publicKey, RsaConfig config);
```

### 2.5. 私钥解密
```java
/**
 * @param str 待解密字符串
 * @param privateKey 私钥
 * @param config 配置
 */
Rsa.decryptByPrivateKey(String str, String privateKey, RsaConfig config);
```

### 2.6. 签名
```java
/**
 * @param content 待签名内容
 * @param privateKey 私钥
 * @param signatureAlgorithm 签名算法
 */
Rsa.sign(String content, String privateKey, SignatureAlgorithm signatureAlgorithm);
```

### 2.7. 验签
```java
/**
 * @param content 待验签内容
 * @param sign 签名
 * @param publicKey 公钥
 */
Rsa.verify(String content, String sign, String publicKey, SignatureAlgorithm signatureAlgorithm);
```

### 3. 示例
```java
public class RsaTest {

    @Test
    public void test() throws Exception {
        String str = "昨天山西大部气温骤降，局地降幅近30℃，一天之内完成“夏返冬”。";
        // 生成秘钥对
        Rsa.SecretKey secretKey = Rsa.createSecretKey(Rsa.RsaConfig.RSA1024);
        // 公钥加密
        String encrypt = Rsa.encryptByPublicKey(str, secretKey.getPublicKey(), Rsa.RsaConfig.RSA1024);
        // 私钥签名
        String sign = Rsa.sign(encrypt, secretKey.getPrivateKey(), Rsa.SignatureAlgorithm.MD5withRSA);
        // 公钥验签
        assertTrue(Rsa.verify(encrypt, sign, secretKey.getPublicKey(), Rsa.SignatureAlgorithm.MD5withRSA));
        // 私钥解密
        assertEquals(str, Rsa.decryptByPrivateKey(encrypt, secretKey.getPrivateKey(), Rsa.RsaConfig.RSA1024));
    }
}
```

