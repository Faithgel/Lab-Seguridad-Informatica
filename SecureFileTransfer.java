import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class SecureFileTransfer {

    public static void main(String[] args) {
        try {
            // Generar una clave de sesión para AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // Tamaño de clave de sesión AES en bits
            SecretKey secretKey = keyGen.generateKey();

            // Encriptar el archivo de texto con AES
            String archivoPlano = "test.txt"; // Reemplaza con tu archivo de texto
            String archivoCifrado = "archivo_cifrado.txt";

            encryptFile(archivoPlano, archivoCifrado, secretKey);

            // Generar una clave pública y privada para RSA
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048); // Tamaño de clave RSA en bits
            //Obetener la clave pública desde mycert.cer
            FileInputStream fis = new FileInputStream("mycert.cer");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            @SuppressWarnings("deprecation")
            Certificate cert = cf.generateCertificate(fis);
            PublicKey publicKey = cert.getPublicKey();

            // Encriptar la clave de sesión AES con la clave pública RSA
            byte[] encryptedSessionKey = encryptAESKey(secretKey, publicKey);

            // Guardar la clave de sesión cifrada en un archivo
            String archivoClaveCifrada = "clave_cifrada.txt";
            saveEncryptedSessionKey(encryptedSessionKey, archivoClaveCifrada);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Función para encriptar un archivo de texto con AES
    public static void encryptFile(String inputFile, String outputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);

        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            cipherOutputStream.write(buffer, 0, bytesRead);
        }

        cipherOutputStream.close();
        inputStream.close();
        outputStream.close();
    }

    // Función para encriptar la clave de sesión AES con RSA
    public static byte[] encryptAESKey(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());
        return encryptedKey;
    }

    // Función para guardar la clave de sesión cifrada en un archivo
    public static void saveEncryptedSessionKey(byte[] encryptedKey, String outputFile) throws Exception {
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(encryptedKey);
        outputStream.close();
    }
}
