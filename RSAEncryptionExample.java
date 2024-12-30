import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class RSAEncryptionExample {

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();

        // 明文文件路径
        String plaintextFile = "plaintext.txt";
        // 公钥和私钥文件路径
        String publicKeyFile = "publickey.txt";
        String privateKeyFile = "privatekey.txt";
        // 密文文件路径
        String ciphertextFile = "ciphertext.txt";
        // 解密后明文结果文件路径
        String resultFile = "result.txt";

        // 读取明文
        String plaintext = new String(Files.readAllBytes(Paths.get(plaintextFile)), StandardCharsets.UTF_8);

        // 加密
        byte[] encryptedBytes = encrypt(plaintext, keyPair.getPublic());

        // 将密文写入文件
        Files.write(Paths.get(ciphertextFile), encryptedBytes);

        // 解密
        String decryptedText = decrypt(encryptedBytes, keyPair.getPrivate());

        // 输出解密后的明文到控制台
        System.out.println("解密后的明文：");
        System.out.println(decryptedText);

        // 将解密后的明文写入文件
        Files.write(Paths.get(resultFile), decryptedText.getBytes(StandardCharsets.UTF_8));

        // 将公钥和私钥写入文件
        writeKeyToFile(keyPair.getPublic(), publicKeyFile);
        writeKeyToFile(keyPair.getPrivate(), privateKeyFile);
    }

    // 生成RSA密钥对
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        return generator.generateKeyPair();
    }

    // 加密方法
    public static byte[] encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    // 解密方法
    public static String decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // 将密钥写入文件
    public static void writeKeyToFile(Key key, String filePath) throws Exception {
        byte[] keyBytes = key.getEncoded();
        Files.write(Paths.get(filePath), keyBytes);
    }
}
