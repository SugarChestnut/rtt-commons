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
        String str = "昨天山西大部气温骤降，局地降幅近30℃，一天之内完成“夏返冬”。另外，今晨8时山西左云积雪深度达24厘米，右玉23厘米，右玉打破当地有气象观测记录来最深积雪纪录。之后大范围雨雪还要下，对于山西来说，春天连续4天出现降水的时候并不多。截至目前，山西已拉响全省范围的暴雪黄色预警。";

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
