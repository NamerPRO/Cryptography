package ru.namerpro.cryptography;

import lombok.extern.java.Log;
import ru.namerpro.cryptography.asymmetricencrypters.rsa.fermatattack.FermatAttack;
import ru.namerpro.cryptography.asymmetricencrypters.rsa.vinnerattack.VinnerAttack;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

@Log
public class Main {

    public static void main(String[] args) throws ExecutionException, InterruptedException, IOException {
        VinnerAttack.runDemoVinnerAttack();
//
//        VinnerAttack.runDemoVinnerAttack();

        //        FermatAttack.attack(new RSA.RSAKeyGenerator.PublicKey())
        //        RSA rsa = new RSA(1024);
//        var keys = rsa.getKeyGeneratorInstance().getKeys();
//
//        String m = "Жили-были в одном волшебном лесу маленькие существа, называемые капибарами. Они были очень дружелюбными и добрыми созданиями, которые всегда помогали друг другу в беде. Однажды, в этом лесу произошел несчастный случай: одна из капибар по имени Капищера потерялась.";
//        BigInteger[] encrypted = rsa.encrypt(m.getBytes(), keys.getKey()).get();
//
//        byte[] decrypted = rsa.decrypt(encrypted, keys.getValue()).get();
//        System.out.println(new String(decrypted, StandardCharsets.UTF_8));
    }

}