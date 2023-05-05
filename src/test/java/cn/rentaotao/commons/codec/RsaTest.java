package cn.rentaotao.commons.codec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author rtt
 * @date 2023/4/21 17:07
 */
public class RsaTest {

    @Test
    public void test() throws Exception {
        String str = "昨天山西大部气温骤降，局地降幅近30℃，一天之内完成“夏返冬”。";
        // 生成秘钥对
        Rsa.SecretKey secretKey = Rsa.createSecretKey(Rsa.RsaConfig.RSA1024);
        // 加密
        String encrypt = Rsa.encryptByPublicKey(str, secretKey.getPublicKey(), Rsa.RsaConfig.RSA1024);
        // 签名
        String sign = Rsa.sign(encrypt, secretKey.getPrivateKey(), Rsa.SignatureAlgorithm.MD5withRSA);
        // 验签
        assertTrue(Rsa.verify(encrypt, sign, secretKey.getPublicKey(), Rsa.SignatureAlgorithm.MD5withRSA));
        // 解密
        assertEquals(str, Rsa.decryptByPrivateKey(encrypt, secretKey.getPrivateKey(), Rsa.RsaConfig.RSA1024));
    }
}
