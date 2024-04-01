package ru.namerpro.cryptography.asymmetricencrypters.rsa.vinnerattack;

import lombok.extern.java.Log;
import ru.namerpro.cryptography.asymmetricencrypters.rsa.RSA;
import ru.namerpro.cryptography.utils.Pair;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutionException;

@Log
public class VinnerAttack {

    private VinnerAttack() {}

    private static final String VINNER_ATTACK_TEST = "You have been attacked using Vinner scheme! This text is meant to check whether d is found.";

    public static Pair<ArrayList<Pair<BigInteger, BigInteger>>, Pair<BigInteger, BigInteger>> attack(RSA.RSAKeyGenerator.PublicKey key) throws ExecutionException, InterruptedException {
        ArrayList<BigInteger> coefficients = getContinuedFraction(key.e(), key.n());
        ArrayList<Pair<BigInteger, BigInteger>> fractions = new ArrayList<>();
        RSA rsa = new RSA(50);
        fractions.add(Pair.of(coefficients.get(0), BigInteger.ONE));
        for (int i = 1; i < coefficients.size(); ++i) {
            fractions.add(
                    Pair.of(
                            coefficients.get(i).multiply(fractions.get(i - 1).getKey()).add(i == 1 ? BigInteger.ONE : fractions.get(i - 2).getKey()),
                            coefficients.get(i).multiply(fractions.get(i - 1).getValue()).add(i == 1 ? BigInteger.ZERO : fractions.get(i - 2).getValue())
                    )
            );
            BigInteger[] encrypted = rsa.encrypt(VINNER_ATTACK_TEST.getBytes(), key).get();
            try {
                byte[] decrypted = rsa.decrypt(encrypted, new RSA.RSAKeyGenerator.PrivateKey(fractions.get(i).getValue(), key.n())).get();
                if (Arrays.equals(decrypted, VINNER_ATTACK_TEST.getBytes())) {
                    break;
                }
            } catch (ExecutionException ignored) {
                // ignored
            }
        }
        var lastFraction = fractions.get(fractions.size() - 1);
        BigInteger phi = getPhi(lastFraction, key);
        return Pair.of(fractions, Pair.of(phi, lastFraction.getValue()));
    }

    private static ArrayList<BigInteger> getContinuedFraction(BigInteger e, BigInteger n) {
        ArrayList<BigInteger> coefficients = new ArrayList<>();
        if (e.compareTo(n) < 0) {
            coefficients.add(BigInteger.ZERO);
            e = e.add(n);
            n = e.subtract(n);
            e = e.subtract(n);
        }
        while (!n.equals(BigInteger.ZERO) && e.compareTo(n) >= 0) {
            coefficients.add(e.divide(n));
            e = e.remainder(n).add(n);
            n = e.subtract(n);
            e = e.subtract(n);
        }
        return coefficients;
    }

    private static BigInteger getPhi(Pair<BigInteger, BigInteger> lastFraction, RSA.RSAKeyGenerator.PublicKey key) {
        BigInteger f = key.e().multiply(lastFraction.getValue()).subtract(BigInteger.ONE).divide(lastFraction.getKey());
        BigInteger bCoefficient = key.n().subtract(f).add(BigInteger.ONE);
        BigInteger sqrtD = Utility.bigSqrtN(bCoefficient.multiply(bCoefficient).subtract(BigInteger.valueOf(4).multiply(key.n())), 2);
        BigInteger p = bCoefficient.add(sqrtD).divide(BigInteger.TWO);
        BigInteger q = bCoefficient.subtract(sqrtD).divide(BigInteger.TWO);
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static void runDemoVinnerAttack() throws ExecutionException, InterruptedException {
        var numberOne = BigInteger.probablePrime(1024, new Random());
        var numberTwo = BigInteger.probablePrime(1024, new Random());

        log.info("p = " + numberOne);
        log.info("q = " + numberTwo);
        log.info("|q - p| = " + numberTwo.subtract(numberOne).abs());

        var phi = numberOne.subtract(BigInteger.ONE).multiply(numberTwo.subtract(BigInteger.ONE));

        log.info("phi = " + phi);

        var n = numberOne.multiply(numberTwo);

        var dToValue = Utility.bigSqrtN(n, 4).divide(BigInteger.valueOf(3)).subtract(BigInteger.valueOf(200000));
        var d = Utility.getRandom(BigInteger.valueOf(65537), dToValue);
        if (d.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            d = d.subtract(BigInteger.ONE);
        }
        while (!CryptoMath.gcd(d, phi).equals(BigInteger.ONE)) {
            d = d.subtract(BigInteger.TWO);
        }

        var e = CryptoMath.egcd(d, phi).getValue().getKey();
        e = e.remainder(phi).add(phi).remainder(phi);

        log.info("e = " + e);
        log.info("d = " + d);
        log.info("N = " + n);

        log.info("==========================\n");
        var stolen = VinnerAttack.attack(new RSA.RSAKeyGenerator.PublicKey(e, n));
        log.info("phi = " + stolen.getValue().getKey());
        log.info("d = " + stolen.getValue().getValue());
        log.info("phi is correct = " + stolen.getValue().getKey().equals(phi));
        log.info("d is correct = " + stolen.getValue().getValue().equals(d));
        log.info("Fractions: ");
        for (var i : stolen.getKey()) {
            log.info(i.getKey() + "/" + i.getValue());
        }
        log.info("\n==========================");
    }

}
