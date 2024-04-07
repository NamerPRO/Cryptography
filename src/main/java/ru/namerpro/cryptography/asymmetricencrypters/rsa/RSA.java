package ru.namerpro.cryptography.asymmetricencrypters.rsa;

import lombok.Getter;
import ru.namerpro.cryptography.api.asymmetric.AsymmetricEncrypter;
import ru.namerpro.cryptography.api.probability.ProbabilityTest;
import ru.namerpro.cryptography.probabilitytests.fermat.FermatProbabilityTest;
import ru.namerpro.cryptography.probabilitytests.millerrabin.MillerRabinProbabilityTest;
import ru.namerpro.cryptography.probabilitytests.solovaystrassen.SolovayStrassen;
import ru.namerpro.cryptography.utils.Pair;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;

public class RSA implements AsymmetricEncrypter {

    private static final Map<Pair<BigInteger, byte[]>, Set<BigInteger>> amountOfEncryptions = new HashMap<>();

    @Getter
    private final RSAKeyGenerator keyGeneratorInstance;

    public RSA(int keyBitLength) {
        this(ProbabilityTestType.MILLER_RABIN, 0.995f, keyBitLength);
    }

    public RSA(ProbabilityTestType test, float probability, int keyBitLength) {
        keyGeneratorInstance = new RSAKeyGenerator(test, probability, keyBitLength);
    }

    public CompletableFuture<BigInteger[]> encrypt(byte[] text, RSAKeyGenerator.PublicKey key) {
        return CompletableFuture.supplyAsync(() -> {
            if (key.e().compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) < 0) {
                var bucket = amountOfEncryptions.get(Pair.of(key.e(), text));
                if (bucket != null && !bucket.contains(key.n()) && BigInteger.valueOf(bucket.size() + 1L).compareTo(key.e()) >= 0) {
                    throw new SecurityException("This message was already ciphered " + key.e().subtract(BigInteger.ONE) + " times with the same cipher exponent! If an attacker somehow managed to intercept them and will intercept this he will be able to restore initial message. Please, generate new pair of keys with different cipher exponent and recall this method.");
                }
                if (bucket == null) {
                    bucket = new HashSet<>();
                    amountOfEncryptions.put(Pair.of(key.e(), text), bucket);
                }
                bucket.add(key.n());
            }
            String textAsBase64 = Base64.getEncoder().encodeToString(text);
            String numberThatRepresentsText = base64ToNumber(textAsBase64);
            int blockSize = key.n().toString().length();
            blockSize -= (blockSize & 1) == 0 ? 2 : 1;
            List<BigInteger> split = splitNumber(numberThatRepresentsText, blockSize);
            BigInteger[] encrypted = new BigInteger[split.size()];
            for (int i = 0; i < split.size(); ++i) {
                encrypted[i] = CryptoMath.pow(split.get(i), key.e(), key.n());
            }
            return encrypted;
        });
    }

    public CompletableFuture<byte[]> decrypt(BigInteger[] text, RSAKeyGenerator.PrivateKey key) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                StringBuilder base64 = new StringBuilder();
                for (BigInteger bigInteger : text) {
                    String numberAsString = CryptoMath.pow(bigInteger, key.d(), key.n()).toString();
                    base64.append(numberToBase64(numberAsString));
                }
                return Base64.getDecoder().decode(base64.toString());
            } catch (IllegalArgumentException error) {
                throw new SecurityException("Cannot decrypt text with given key!");
            }
        });
    }

    private String base64ToNumber(String base64) {
        StringBuilder numberAsString = new StringBuilder();
        for (int i = 0; i < base64.length(); ++i) {
            char symbol = base64.charAt(i);
            if (Character.isUpperCase(symbol)) {
                numberAsString.append(symbol - 'A' + 10);
            } else if (Character.isLowerCase(symbol)) {
                numberAsString.append(symbol - 'a' + 36);
            } else if (Character.isDigit(symbol)) {
                numberAsString.append(symbol - '0' + 62);
            } else if (symbol == '+') {
                numberAsString.append("72");
            } else if (symbol == '/') {
                numberAsString.append("73");
            } else {
                numberAsString.append("74");
            }
        }
        return numberAsString.toString();
    }

    private String numberToBase64(String numberAsString) {
        StringBuilder base64 = new StringBuilder();
        for (int i = 0; i + 1 < numberAsString.length(); i += 2) {
            int number = Integer.parseInt(numberAsString.charAt(i) + "" + numberAsString.charAt(i + 1));
            if (number >= 10 && number <= 35) {
                base64.append((char) (number - 10 + 'A'));
            } else if (number >= 36 && number <= 61) {
                base64.append((char) (number - 36 + 'a'));
            } else if (number >= 62 && number <= 71) {
                base64.append((char) (number - 62 + '0'));
            } else if (number == 72) {
                base64.append('+');
            } else if (number == 73) {
                base64.append('/');
            } else {
                base64.append('=');
            }
        }
        return base64.toString();
    }

    private List<BigInteger> splitNumber(String numberAsString, int blockSize) {
        List<BigInteger> split = new ArrayList<>();
        StringBuilder number = new StringBuilder();
        for (int i = 0; i < numberAsString.length(); i += blockSize) {
            for (int j = 0; j < blockSize && i + j < numberAsString.length(); j += 2) {
                number.append(numberAsString.charAt(i + j)).append(numberAsString.charAt(i + j + 1));
            }
            split.add(new BigInteger(number.toString()));
            number.setLength(0);
        }
        return split;
    }

    public enum ProbabilityTestType {
        FERMAT,
        SOLOVAY_STRASSEN,
        MILLER_RABIN
    }

    public static class RSAKeyGenerator {
        public record PublicKey(BigInteger e, BigInteger n) {}
        public record PrivateKey(BigInteger d, BigInteger n) {}

        private final ProbabilityTest testType;
        private final float probability;
        private final int keyBitLength;

        public RSAKeyGenerator(ProbabilityTestType testType, float probability, int keyBitLength) {
            this.testType = switch (testType) {
                case FERMAT -> new FermatProbabilityTest();
                case SOLOVAY_STRASSEN -> new SolovayStrassen();
                case MILLER_RABIN -> new MillerRabinProbabilityTest();
            };
            this.probability = probability;
            this.keyBitLength = keyBitLength;
        }

        public Pair<PublicKey, PrivateKey> getKeys() {
            var primeNumbers = getPrimeNumbers();

            var n = primeNumbers.getKey().multiply(primeNumbers.getValue());

            var phi = primeNumbers.getKey().subtract(BigInteger.ONE).multiply(primeNumbers.getValue().subtract(BigInteger.ONE));
            var dFromValue = Utility.bigSqrtN(n, 4).add(BigInteger.ONE).divide(BigInteger.valueOf(3)).add(BigInteger.ONE);
            BigInteger d = Utility.getRandom(dFromValue, phi);
            if (d.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
                d = d.subtract(BigInteger.ONE);
            }
            while (!CryptoMath.gcd(d, phi).equals(BigInteger.ONE)) {
                d = d.add(BigInteger.TWO);
            }

            BigInteger e = CryptoMath.egcd(d, phi).getValue().getKey();
            e = e.remainder(phi).add(phi).remainder(phi);

            return Pair.of(new PublicKey(e, n), new PrivateKey(d, n));
        }

        private Pair<BigInteger, BigInteger> getPrimeNumbers() {
            BigInteger prime1;
            do {
                prime1 = Utility.getRandom(BigInteger.ONE.shiftLeft(keyBitLength - 1), BigInteger.ONE.shiftLeft(keyBitLength)).or(BigInteger.ONE);
            } while (!testType.isProbablyPrime(prime1, probability));
            BigInteger prime2;
            do {
                prime2 = Utility.getRandom(BigInteger.ONE.shiftLeft(keyBitLength - 1), BigInteger.ONE.shiftLeft(keyBitLength)).or(BigInteger.ONE);
            } while (prime2.subtract(prime1).abs().compareTo(BigInteger.ONE.shiftLeft(keyBitLength / 2)) < 0 || !testType.isProbablyPrime(prime2, probability));
            return Pair.of(prime1, prime2);
        }
    }

}



