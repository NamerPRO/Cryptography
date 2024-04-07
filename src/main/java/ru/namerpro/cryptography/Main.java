package ru.namerpro.cryptography;

import lombok.Cleanup;
import lombok.extern.slf4j.Slf4j;
import ru.namerpro.cryptography.context.SymmetricEncrypterContext;
import ru.namerpro.cryptography.context.encrypter.Encrypter;
import ru.namerpro.cryptography.mode.Mode;
import ru.namerpro.cryptography.padding.Padding;
import ru.namerpro.cryptography.symmetricencrypters.rijndael.Rijndael;
import ru.namerpro.cryptography.utils.stateless.CryptoGF;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

@Slf4j
public class Main {

    public static void main(String[] args) throws ExecutionException, InterruptedException {


//        log.info("Irreducible polynomials:");
//        var polynomials = CryptoGF.getIrreduciblePolynomials8();
//        for (var i : polynomials) {
//            var number = (1 << 8) | (i & 0xff);
//            log.info(Integer.toBinaryString(number) + " = " + number);
//        }
//        log.info("Total amount: " + polynomials.length);
//        log.info("===============");
//        log.info("");
//
//        var data = "Hello World!";
//        byte[] key = new byte[]{0x2b, 0x28, (byte) 0xab, 0x09, 0x7e, (byte) 0xae, 0x15, (byte) 0xff, 0x00, 0x01, 0x33, (byte) 0xde, (byte) 0x88, (byte) 0xab, (byte) 0xbb, 0x22, 0x01, 0x02, 0x1d, 0x22, (byte) 0xdd, (byte) 0xff, (byte) 0xcc, 0x00};
//        byte[] iv = new byte[]{0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01};
//
//        @Cleanup
//        SymmetricEncrypterContext context = new SymmetricEncrypterContext(Encrypter.RIJNDAEL, key, Mode.CBC, Padding.ISO_10126, iv, Rijndael.RijndaelBlockSize.SZ_192_BITS, 299);
//
//        context.encrypt(data.getBytes()).thenAccept(encrypted -> {
//            StringBuilder encryptedString = new StringBuilder();
//            for (var i : encrypted) {
//                encryptedString.append(String.format("%02x ", i & 0xff));
//            }
//            log.info("Encrypted text: " + encryptedString);
//
//            context.decrypt(encrypted).thenAccept(decrypted -> log.info("Decrypted text: " + new String(decrypted, StandardCharsets.UTF_8)));
//        });
//
//        Thread.sleep(500);
    }

}