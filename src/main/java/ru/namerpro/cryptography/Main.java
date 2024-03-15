package ru.namerpro.cryptography;

import ru.namerpro.cryptography.context.SymmetricEncrypterContext;
import ru.namerpro.cryptography.context.encrypter.Encrypter;
import ru.namerpro.cryptography.mode.Mode;
import ru.namerpro.cryptography.padding.Padding;

import java.util.Arrays;
import java.util.concurrent.ExecutionException;

public class Main {

    public static void main(String[] args) {
        byte[] key = { 0x02, 0x01, (byte) 0xff, (byte) 0xcc, 0x24, (byte) 0x93, 0x22, 0x33, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x02, 0x01, (byte) 0xff, (byte) 0xcc, 0x24, (byte) 0x93, 0x22, 0x33, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        byte[] iv = { 0x1, 0x22, 0x3f, (byte) 0xff, 0x22, 0x44, 0x44, 0x44, 0x1, 0x22, 0x3f, (byte) 0xff, 0x22, 0x44, 0x44, 0x44 };
        try(SymmetricEncrypterContext context = new SymmetricEncrypterContext(Encrypter.DEAL, key, Mode.PCBC, Padding.ISO_10126, iv)) {
            var resp = context.encrypt("Hello World!".getBytes()).get();
            System.out.println(Arrays.toString(resp));
            var resp2 = context.decrypt(resp).get();
            System.out.println(new String(resp2));

//            context.decrypt("C:/Users/AP-3a/Desktop/encrypted_animal.jpeg", "C:/Users/AP-3a/Desktop/decrypted_animal.jpeg").get();
//            context.encrypt("THis is an exampLE texT to TEST deS!!! 847328r2hf83".getBytes()).thenAccept(encrypted -> {
//                System.out.println("Encrypted:");
//                System.out.println(Arrays.toString(encrypted));
//
//                context.decrypt(encrypted).thenAccept(decrypted -> {
//                    System.out.println("Decrypted:");
//                    System.out.println(new String(decrypted));
//                });
//            });
//            Thread.sleep(250);
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

}