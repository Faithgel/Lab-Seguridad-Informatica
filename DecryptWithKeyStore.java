import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DecryptWithKeyStore {

    public static void main(String[] args) {
        File inFile = new File("salida.txt"); // Nombre del archivo cifrado
        File outFile = new File("resultado.txt"); // Nombre del archivo de salida
        File keyStoreFile = new File("KeyStore.jks");
        String password = "store1234";

        try {
            // Cargar el almacén de claves
            KeyStore myKeyStore = KeyStore.getInstance("JKS");
            FileInputStream inStream = new FileInputStream(keyStoreFile);
            myKeyStore.load(inStream, password.toCharArray());

            // Obtener la clave privada RSA del almacén de claves
            PrivateKey privateKey = (PrivateKey) myKeyStore.getKey("mykey", password.toCharArray());

            // Inicializar el objeto Cipher RSA para descifrar la clave AES
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Leer la clave AES cifrada del archivo
            FileInputStream keyStream = new FileInputStream(inFile);
            byte[] encodedKey = new byte[256]; // Ajusta el tamaño según sea necesario
            keyStream.read(encodedKey);

            // Descifrar la clave AES utilizando la clave privada RSA
            byte[] aesKeyBytes = rsaCipher.doFinal(encodedKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Inicializar el objeto Cipher AES para descifrar los datos
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

            // Leer los datos cifrados del archivo
            FileInputStream cipherStream = new FileInputStream(inFile);
            byte[] cipherText = new byte[(int) (inFile.length() - 256)]; // Ajusta el tamaño según sea necesario
            cipherStream.skip(256); // Saltar los primeros 256 bytes que son la clave cifrada
            cipherStream.read(cipherText);

            // Descifrar los datos
            byte[] plainText = aesCipher.doFinal(cipherText);

            // Escribir los datos descifrados en el archivo de salida
            FileOutputStream outToFile = new FileOutputStream(outFile);
            outToFile.write(plainText);

            // Cerrar archivos
            keyStream.close();
            cipherStream.close();
            outToFile.close();

            System.out.println("Desencriptación completada con éxito.");
        } catch (Exception e) {
            System.out.println("Error en la desencriptación: " + e);
        }
    }
}
