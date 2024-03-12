package ru.namerpro.cryptography;

import ru.namerpro.cryptography.context.SymmetricEncrypterContext;
import ru.namerpro.cryptography.context.encrypter.Encrypter;
import ru.namerpro.cryptography.context.mode.Mode;
import ru.namerpro.cryptography.context.padding.Padding;

import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        byte[] key = { 0x02, 0x01, (byte) 0xff, (byte) 0xcc, 0x24, (byte) 0x93, 0x22, 0x33 };
        byte[] iv = { 0x1, 0x22, 0x3f, (byte) 0xff, 0x22, 0x44, 0x44, 0x44 };
        try(SymmetricEncrypterContext context = new SymmetricEncrypterContext(Encrypter.DES, key, Mode.RD, Padding.PKCS7, iv)) {
            context.encrypt("This is an example message to test DES functionality!".getBytes())
                    .thenAccept(encryptedText -> {
                        System.out.println("Encrypted text as bytes: ");
                        System.out.println(Arrays.toString(encryptedText));

                        context.decrypt(encryptedText)
                                .thenAccept(decryptedText -> {
                                    System.out.println("Decrypted text as bytes: ");
                                    System.out.println(new String(decryptedText));
                                });
                    });
            Thread.sleep(250);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

}