import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class Hash {
    public static void main( String[] args ) throws Exception
    {
        File inFile = new File("test.txt");//args[0]);
        File outFile = new File("resultado-hash.txt");//args[1]);
        //File resultado = new File("final.txt");
        File keyStoreFile = new File("KeyStore.jks");
        String password = "store1234";

        try {
            //Lee el texto desde el archivo 
            FileInputStream rawDataFromFile = new FileInputStream(inFile);
            byte[] plainText = new byte[(int) inFile.length()];

            System.out.println("Layendo Datos");
            rawDataFromFile.read(plainText);

            //Crea un hash del archivo leido
            MessageDigest md = MessageDigest.getInstance( "SHA");
            md.update( plainText );
            byte[] digest = md.digest();

            //Imprime por pantalla el hash resultante
            for ( byte b : digest )
    	    {
    		    System.out.print( Integer.toHexString( b & 0xff ));
    	    }
            System.out.println();

            // Generar una llave simetrica para encriptar datos
            KeyGenerator sKenGen = KeyGenerator.getInstance("AES");
            Key aesKey = sKenGen.generateKey();

            // Carga el keystore
            KeyStore myKeyStore = KeyStore.getInstance("JKS");
            FileInputStream inStream = new FileInputStream(keyStoreFile);
            myKeyStore.load(inStream, password.toCharArray());

            // Lee las llaves privada y publica del keystore.
            @SuppressWarnings("unused")
            PrivateKey privatekey = (PrivateKey) myKeyStore.getKey("mykey", password.toCharArray());

            // Inicializa el Objeto Cipher RSA
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, privatekey);

            // Encriptar llave simetrica AES con la llave publica RSA
            byte[] encodedKey = rsaCipher.doFinal(aesKey.getEncoded());

            System.out.println("Abriendo archivo a escribir: " + outFile);
            FileOutputStream outToFile = new FileOutputStream(outFile);

            System.out.println("Escribiendo Datos");
            //Escribir llave AES encriptada al archivo.
            outToFile.write(encodedKey);
            // Escribir el texto plano encriptado al archivo.
            outToFile.write(digest);

            System.out.println("Cerrando Archivos");
            rawDataFromFile.close();
            outToFile.close();
        } catch (Exception e) {
            System.out.println("Doh: " + e);
        } 
    } 
}
