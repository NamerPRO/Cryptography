package ru.namerpro.cryptography.asymmetricencrypters.rsa;

import lombok.Getter;
import ru.namerpro.cryptography.api.AsymmetricEncrypter;
import ru.namerpro.cryptography.api.ProbabilityTest;
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
    private static final int MINIMUM_NUMBER_OF_RANDOM_BYTES = 8;
    public RSA(int keyBitLength) {
        this(ProbabilityTestType.MillerRabin, 0.995f, keyBitLength);
    }

    @Getter
    private final RSAKeyGenerator keyGeneratorInstance;

    public RSA(ProbabilityTestType test, float probability, int keyBitLength) {
        keyGeneratorInstance = this.new RSAKeyGenerator(test, probability, keyBitLength);
    }

    public CompletableFuture<BigInteger[]> encrypt(byte[] text, RSAKeyGenerator.PublicKey key) {
        return CompletableFuture.supplyAsync(() -> {
            if (key.e().compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) < 0) {
                var bucket = amountOfEncryptions.get(Pair.of(key.e(), text));
                if (bucket != null && !bucket.contains(key.n()) && BigInteger.valueOf(bucket.size() + 1).compareTo(key.e()) >= 0) {
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
                for (int i = 0; i < text.length; ++i) {
                    String numberAsString = CryptoMath.pow(text[i], key.d(), key.n()).toString();
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
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    public class RSAKeyGenerator {
        public record PublicKey(BigInteger e, BigInteger n) {}
        public record PrivateKey(BigInteger d, BigInteger n) {}

        private final BigInteger[] lowPrimes = new BigInteger[] { BigInteger.valueOf(2), BigInteger.valueOf(3), BigInteger.valueOf(5), BigInteger.valueOf(7), BigInteger.valueOf(11), BigInteger.valueOf(13), BigInteger.valueOf(17), BigInteger.valueOf(19), BigInteger.valueOf(23), BigInteger.valueOf(29), BigInteger.valueOf(31), BigInteger.valueOf(37), BigInteger.valueOf(41), BigInteger.valueOf(43), BigInteger.valueOf(47), BigInteger.valueOf(53), BigInteger.valueOf(59), BigInteger.valueOf(61), BigInteger.valueOf(67), BigInteger.valueOf(71), BigInteger.valueOf(73), BigInteger.valueOf(79), BigInteger.valueOf(83), BigInteger.valueOf(89), BigInteger.valueOf(97), BigInteger.valueOf(101), BigInteger.valueOf(103), BigInteger.valueOf(107), BigInteger.valueOf(109), BigInteger.valueOf(113), BigInteger.valueOf(127), BigInteger.valueOf(131), BigInteger.valueOf(137), BigInteger.valueOf(139), BigInteger.valueOf(149), BigInteger.valueOf(151), BigInteger.valueOf(157), BigInteger.valueOf(163), BigInteger.valueOf(167), BigInteger.valueOf(173), BigInteger.valueOf(179), BigInteger.valueOf(181), BigInteger.valueOf(191), BigInteger.valueOf(193), BigInteger.valueOf(197), BigInteger.valueOf(199), BigInteger.valueOf(211), BigInteger.valueOf(223), BigInteger.valueOf(227), BigInteger.valueOf(229), BigInteger.valueOf(233), BigInteger.valueOf(239), BigInteger.valueOf(241), BigInteger.valueOf(251), BigInteger.valueOf(257), BigInteger.valueOf(263), BigInteger.valueOf(269), BigInteger.valueOf(271), BigInteger.valueOf(277), BigInteger.valueOf(281), BigInteger.valueOf(283), BigInteger.valueOf(293), BigInteger.valueOf(307), BigInteger.valueOf(311), BigInteger.valueOf(313), BigInteger.valueOf(317), BigInteger.valueOf(331), BigInteger.valueOf(337), BigInteger.valueOf(347), BigInteger.valueOf(349), BigInteger.valueOf(353), BigInteger.valueOf(359), BigInteger.valueOf(367), BigInteger.valueOf(373), BigInteger.valueOf(379), BigInteger.valueOf(383), BigInteger.valueOf(389), BigInteger.valueOf(397), BigInteger.valueOf(401), BigInteger.valueOf(409), BigInteger.valueOf(419), BigInteger.valueOf(421), BigInteger.valueOf(431), BigInteger.valueOf(433), BigInteger.valueOf(439), BigInteger.valueOf(443), BigInteger.valueOf(449), BigInteger.valueOf(457), BigInteger.valueOf(461), BigInteger.valueOf(463), BigInteger.valueOf(467), BigInteger.valueOf(479), BigInteger.valueOf(487), BigInteger.valueOf(491), BigInteger.valueOf(499), BigInteger.valueOf(503), BigInteger.valueOf(509), BigInteger.valueOf(521), BigInteger.valueOf(523), BigInteger.valueOf(541), BigInteger.valueOf(547), BigInteger.valueOf(557), BigInteger.valueOf(563), BigInteger.valueOf(569), BigInteger.valueOf(571), BigInteger.valueOf(577), BigInteger.valueOf(587), BigInteger.valueOf(593), BigInteger.valueOf(599), BigInteger.valueOf(601), BigInteger.valueOf(607), BigInteger.valueOf(613), BigInteger.valueOf(617), BigInteger.valueOf(619), BigInteger.valueOf(631), BigInteger.valueOf(641), BigInteger.valueOf(643), BigInteger.valueOf(647), BigInteger.valueOf(653), BigInteger.valueOf(659), BigInteger.valueOf(661), BigInteger.valueOf(673), BigInteger.valueOf(677), BigInteger.valueOf(683), BigInteger.valueOf(691), BigInteger.valueOf(701), BigInteger.valueOf(709), BigInteger.valueOf(719), BigInteger.valueOf(727), BigInteger.valueOf(733), BigInteger.valueOf(739), BigInteger.valueOf(743), BigInteger.valueOf(751), BigInteger.valueOf(757), BigInteger.valueOf(761), BigInteger.valueOf(769), BigInteger.valueOf(773), BigInteger.valueOf(787), BigInteger.valueOf(797), BigInteger.valueOf(809), BigInteger.valueOf(811), BigInteger.valueOf(821), BigInteger.valueOf(823), BigInteger.valueOf(827), BigInteger.valueOf(829), BigInteger.valueOf(839), BigInteger.valueOf(853), BigInteger.valueOf(857), BigInteger.valueOf(859), BigInteger.valueOf(863), BigInteger.valueOf(877), BigInteger.valueOf(881), BigInteger.valueOf(883), BigInteger.valueOf(887), BigInteger.valueOf(907), BigInteger.valueOf(911), BigInteger.valueOf(919), BigInteger.valueOf(929), BigInteger.valueOf(937), BigInteger.valueOf(941), BigInteger.valueOf(947), BigInteger.valueOf(953), BigInteger.valueOf(967), BigInteger.valueOf(971), BigInteger.valueOf(977), BigInteger.valueOf(983), BigInteger.valueOf(991), BigInteger.valueOf(997), BigInteger.valueOf(1009), BigInteger.valueOf(1013), BigInteger.valueOf(1019), BigInteger.valueOf(1021), BigInteger.valueOf(1031), BigInteger.valueOf(1033), BigInteger.valueOf(1039), BigInteger.valueOf(1049), BigInteger.valueOf(1051), BigInteger.valueOf(1061), BigInteger.valueOf(1063), BigInteger.valueOf(1069), BigInteger.valueOf(1087), BigInteger.valueOf(1091), BigInteger.valueOf(1093), BigInteger.valueOf(1097), BigInteger.valueOf(1103), BigInteger.valueOf(1109), BigInteger.valueOf(1117), BigInteger.valueOf(1123), BigInteger.valueOf(1129), BigInteger.valueOf(1151), BigInteger.valueOf(1153), BigInteger.valueOf(1163), BigInteger.valueOf(1171), BigInteger.valueOf(1181), BigInteger.valueOf(1187), BigInteger.valueOf(1193), BigInteger.valueOf(1201), BigInteger.valueOf(1213), BigInteger.valueOf(1217), BigInteger.valueOf(1223), BigInteger.valueOf(1229), BigInteger.valueOf(1231), BigInteger.valueOf(1237), BigInteger.valueOf(1249), BigInteger.valueOf(1259), BigInteger.valueOf(1277), BigInteger.valueOf(1279), BigInteger.valueOf(1283), BigInteger.valueOf(1289), BigInteger.valueOf(1291), BigInteger.valueOf(1297), BigInteger.valueOf(1301), BigInteger.valueOf(1303), BigInteger.valueOf(1307), BigInteger.valueOf(1319), BigInteger.valueOf(1321), BigInteger.valueOf(1327), BigInteger.valueOf(1361), BigInteger.valueOf(1367), BigInteger.valueOf(1373), BigInteger.valueOf(1381), BigInteger.valueOf(1399), BigInteger.valueOf(1409), BigInteger.valueOf(1423), BigInteger.valueOf(1427), BigInteger.valueOf(1429), BigInteger.valueOf(1433), BigInteger.valueOf(1439), BigInteger.valueOf(1447), BigInteger.valueOf(1451), BigInteger.valueOf(1453), BigInteger.valueOf(1459), BigInteger.valueOf(1471), BigInteger.valueOf(1481), BigInteger.valueOf(1483), BigInteger.valueOf(1487), BigInteger.valueOf(1489), BigInteger.valueOf(1493), BigInteger.valueOf(1499), BigInteger.valueOf(1511), BigInteger.valueOf(1523), BigInteger.valueOf(1531), BigInteger.valueOf(1543), BigInteger.valueOf(1549), BigInteger.valueOf(1553), BigInteger.valueOf(1559), BigInteger.valueOf(1567), BigInteger.valueOf(1571), BigInteger.valueOf(1579), BigInteger.valueOf(1583), BigInteger.valueOf(1597), BigInteger.valueOf(1601), BigInteger.valueOf(1607), BigInteger.valueOf(1609), BigInteger.valueOf(1613), BigInteger.valueOf(1619), BigInteger.valueOf(1621), BigInteger.valueOf(1627), BigInteger.valueOf(1637), BigInteger.valueOf(1657), BigInteger.valueOf(1663), BigInteger.valueOf(1667), BigInteger.valueOf(1669), BigInteger.valueOf(1693), BigInteger.valueOf(1697), BigInteger.valueOf(1699), BigInteger.valueOf(1709), BigInteger.valueOf(1721), BigInteger.valueOf(1723), BigInteger.valueOf(1733), BigInteger.valueOf(1741), BigInteger.valueOf(1747), BigInteger.valueOf(1753), BigInteger.valueOf(1759), BigInteger.valueOf(1777), BigInteger.valueOf(1783), BigInteger.valueOf(1787), BigInteger.valueOf(1789), BigInteger.valueOf(1801), BigInteger.valueOf(1811), BigInteger.valueOf(1823), BigInteger.valueOf(1831), BigInteger.valueOf(1847), BigInteger.valueOf(1861), BigInteger.valueOf(1867), BigInteger.valueOf(1871), BigInteger.valueOf(1873), BigInteger.valueOf(1877), BigInteger.valueOf(1879), BigInteger.valueOf(1889), BigInteger.valueOf(1901), BigInteger.valueOf(1907), BigInteger.valueOf(1913), BigInteger.valueOf(1931), BigInteger.valueOf(1933), BigInteger.valueOf(1949), BigInteger.valueOf(1951), BigInteger.valueOf(1973), BigInteger.valueOf(1979), BigInteger.valueOf(1987), BigInteger.valueOf(1993), BigInteger.valueOf(1997), BigInteger.valueOf(1999), BigInteger.valueOf(2003), BigInteger.valueOf(2011), BigInteger.valueOf(2017), BigInteger.valueOf(2027), BigInteger.valueOf(2029), BigInteger.valueOf(2039), BigInteger.valueOf(2053), BigInteger.valueOf(2063), BigInteger.valueOf(2069), BigInteger.valueOf(2081), BigInteger.valueOf(2083), BigInteger.valueOf(2087), BigInteger.valueOf(2089), BigInteger.valueOf(2099), BigInteger.valueOf(2111), BigInteger.valueOf(2113), BigInteger.valueOf(2129), BigInteger.valueOf(2131), BigInteger.valueOf(2137), BigInteger.valueOf(2141), BigInteger.valueOf(2143), BigInteger.valueOf(2153), BigInteger.valueOf(2161), BigInteger.valueOf(2179), BigInteger.valueOf(2203), BigInteger.valueOf(2207), BigInteger.valueOf(2213), BigInteger.valueOf(2221), BigInteger.valueOf(2237), BigInteger.valueOf(2239), BigInteger.valueOf(2243), BigInteger.valueOf(2251), BigInteger.valueOf(2267), BigInteger.valueOf(2269), BigInteger.valueOf(2273), BigInteger.valueOf(2281), BigInteger.valueOf(2287), BigInteger.valueOf(2293), BigInteger.valueOf(2297), BigInteger.valueOf(2309), BigInteger.valueOf(2311), BigInteger.valueOf(2333), BigInteger.valueOf(2339), BigInteger.valueOf(2341), BigInteger.valueOf(2347), BigInteger.valueOf(2351), BigInteger.valueOf(2357), BigInteger.valueOf(2371), BigInteger.valueOf(2377), BigInteger.valueOf(2381), BigInteger.valueOf(2383), BigInteger.valueOf(2389), BigInteger.valueOf(2393), BigInteger.valueOf(2399), BigInteger.valueOf(2411), BigInteger.valueOf(2417), BigInteger.valueOf(2423), BigInteger.valueOf(2437), BigInteger.valueOf(2441), BigInteger.valueOf(2447), BigInteger.valueOf(2459), BigInteger.valueOf(2467), BigInteger.valueOf(2473), BigInteger.valueOf(2477), BigInteger.valueOf(2503), BigInteger.valueOf(2521), BigInteger.valueOf(2531), BigInteger.valueOf(2539), BigInteger.valueOf(2543), BigInteger.valueOf(2549), BigInteger.valueOf(2551), BigInteger.valueOf(2557), BigInteger.valueOf(2579), BigInteger.valueOf(2591), BigInteger.valueOf(2593), BigInteger.valueOf(2609), BigInteger.valueOf(2617), BigInteger.valueOf(2621), BigInteger.valueOf(2633), BigInteger.valueOf(2647), BigInteger.valueOf(2657), BigInteger.valueOf(2659), BigInteger.valueOf(2663), BigInteger.valueOf(2671), BigInteger.valueOf(2677), BigInteger.valueOf(2683), BigInteger.valueOf(2687), BigInteger.valueOf(2689), BigInteger.valueOf(2693), BigInteger.valueOf(2699), BigInteger.valueOf(2707), BigInteger.valueOf(2711), BigInteger.valueOf(2713), BigInteger.valueOf(2719), BigInteger.valueOf(2729), BigInteger.valueOf(2731), BigInteger.valueOf(2741), BigInteger.valueOf(2749), BigInteger.valueOf(2753), BigInteger.valueOf(2767), BigInteger.valueOf(2777), BigInteger.valueOf(2789), BigInteger.valueOf(2791), BigInteger.valueOf(2797), BigInteger.valueOf(2801), BigInteger.valueOf(2803), BigInteger.valueOf(2819), BigInteger.valueOf(2833), BigInteger.valueOf(2837), BigInteger.valueOf(2843), BigInteger.valueOf(2851), BigInteger.valueOf(2857), BigInteger.valueOf(2861), BigInteger.valueOf(2879), BigInteger.valueOf(2887), BigInteger.valueOf(2897), BigInteger.valueOf(2903), BigInteger.valueOf(2909), BigInteger.valueOf(2917), BigInteger.valueOf(2927), BigInteger.valueOf(2939), BigInteger.valueOf(2953), BigInteger.valueOf(2957), BigInteger.valueOf(2963), BigInteger.valueOf(2969), BigInteger.valueOf(2971), BigInteger.valueOf(2999), BigInteger.valueOf(3001), BigInteger.valueOf(3011), BigInteger.valueOf(3019), BigInteger.valueOf(3023), BigInteger.valueOf(3037), BigInteger.valueOf(3041), BigInteger.valueOf(3049), BigInteger.valueOf(3061), BigInteger.valueOf(3067), BigInteger.valueOf(3079), BigInteger.valueOf(3083), BigInteger.valueOf(3089), BigInteger.valueOf(3109), BigInteger.valueOf(3119), BigInteger.valueOf(3121), BigInteger.valueOf(3137), BigInteger.valueOf(3163), BigInteger.valueOf(3167), BigInteger.valueOf(3169), BigInteger.valueOf(3181), BigInteger.valueOf(3187), BigInteger.valueOf(3191), BigInteger.valueOf(3203), BigInteger.valueOf(3209), BigInteger.valueOf(3217), BigInteger.valueOf(3221), BigInteger.valueOf(3229), BigInteger.valueOf(3251), BigInteger.valueOf(3253), BigInteger.valueOf(3257), BigInteger.valueOf(3259), BigInteger.valueOf(3271), BigInteger.valueOf(3299), BigInteger.valueOf(3301), BigInteger.valueOf(3307), BigInteger.valueOf(3313), BigInteger.valueOf(3319), BigInteger.valueOf(3323), BigInteger.valueOf(3329), BigInteger.valueOf(3331), BigInteger.valueOf(3343), BigInteger.valueOf(3347), BigInteger.valueOf(3359), BigInteger.valueOf(3361), BigInteger.valueOf(3371), BigInteger.valueOf(3373), BigInteger.valueOf(3389), BigInteger.valueOf(3391), BigInteger.valueOf(3407), BigInteger.valueOf(3413), BigInteger.valueOf(3433), BigInteger.valueOf(3449), BigInteger.valueOf(3457), BigInteger.valueOf(3461), BigInteger.valueOf(3463), BigInteger.valueOf(3467), BigInteger.valueOf(3469), BigInteger.valueOf(3491), BigInteger.valueOf(3499), BigInteger.valueOf(3511), BigInteger.valueOf(3517), BigInteger.valueOf(3527), BigInteger.valueOf(3529), BigInteger.valueOf(3533), BigInteger.valueOf(3539), BigInteger.valueOf(3541), BigInteger.valueOf(3547), BigInteger.valueOf(3557), BigInteger.valueOf(3559), BigInteger.valueOf(3571), BigInteger.valueOf(3581), BigInteger.valueOf(3583), BigInteger.valueOf(3593), BigInteger.valueOf(3607), BigInteger.valueOf(3613), BigInteger.valueOf(3617), BigInteger.valueOf(3623), BigInteger.valueOf(3631), BigInteger.valueOf(3637), BigInteger.valueOf(3643), BigInteger.valueOf(3659), BigInteger.valueOf(3671), BigInteger.valueOf(3673), BigInteger.valueOf(3677), BigInteger.valueOf(3691), BigInteger.valueOf(3697), BigInteger.valueOf(3701), BigInteger.valueOf(3709), BigInteger.valueOf(3719), BigInteger.valueOf(3727), BigInteger.valueOf(3733), BigInteger.valueOf(3739), BigInteger.valueOf(3761), BigInteger.valueOf(3767), BigInteger.valueOf(3769), BigInteger.valueOf(3779), BigInteger.valueOf(3793), BigInteger.valueOf(3797), BigInteger.valueOf(3803), BigInteger.valueOf(3821), BigInteger.valueOf(3823), BigInteger.valueOf(3833), BigInteger.valueOf(3847), BigInteger.valueOf(3851), BigInteger.valueOf(3853), BigInteger.valueOf(3863), BigInteger.valueOf(3877), BigInteger.valueOf(3881), BigInteger.valueOf(3889), BigInteger.valueOf(3907), BigInteger.valueOf(3911), BigInteger.valueOf(3917), BigInteger.valueOf(3919), BigInteger.valueOf(3923), BigInteger.valueOf(3929), BigInteger.valueOf(3931), BigInteger.valueOf(3943), BigInteger.valueOf(3947), BigInteger.valueOf(3967), BigInteger.valueOf(3989), BigInteger.valueOf(4001), BigInteger.valueOf(4003), BigInteger.valueOf(4007), BigInteger.valueOf(4013), BigInteger.valueOf(4019), BigInteger.valueOf(4021), BigInteger.valueOf(4027), BigInteger.valueOf(4049), BigInteger.valueOf(4051), BigInteger.valueOf(4057), BigInteger.valueOf(4073), BigInteger.valueOf(4079), BigInteger.valueOf(4091), BigInteger.valueOf(4093), BigInteger.valueOf(4099), BigInteger.valueOf(4111), BigInteger.valueOf(4127), BigInteger.valueOf(4129), BigInteger.valueOf(4133), BigInteger.valueOf(4139), BigInteger.valueOf(4153), BigInteger.valueOf(4157), BigInteger.valueOf(4159), BigInteger.valueOf(4177), BigInteger.valueOf(4201), BigInteger.valueOf(4211), BigInteger.valueOf(4217), BigInteger.valueOf(4219), BigInteger.valueOf(4229), BigInteger.valueOf(4231), BigInteger.valueOf(4241), BigInteger.valueOf(4243), BigInteger.valueOf(4253), BigInteger.valueOf(4259), BigInteger.valueOf(4261), BigInteger.valueOf(4271), BigInteger.valueOf(4273), BigInteger.valueOf(4283), BigInteger.valueOf(4289), BigInteger.valueOf(4297), BigInteger.valueOf(4327), BigInteger.valueOf(4337), BigInteger.valueOf(4339), BigInteger.valueOf(4349), BigInteger.valueOf(4357), BigInteger.valueOf(4363), BigInteger.valueOf(4373), BigInteger.valueOf(4391), BigInteger.valueOf(4397), BigInteger.valueOf(4409), BigInteger.valueOf(4421), BigInteger.valueOf(4423), BigInteger.valueOf(4441), BigInteger.valueOf(4447), BigInteger.valueOf(4451), BigInteger.valueOf(4457), BigInteger.valueOf(4463), BigInteger.valueOf(4481), BigInteger.valueOf(4483), BigInteger.valueOf(4493), BigInteger.valueOf(4507), BigInteger.valueOf(4513), BigInteger.valueOf(4517), BigInteger.valueOf(4519), BigInteger.valueOf(4523), BigInteger.valueOf(4547), BigInteger.valueOf(4549), BigInteger.valueOf(4561), BigInteger.valueOf(4567), BigInteger.valueOf(4583), BigInteger.valueOf(4591), BigInteger.valueOf(4597), BigInteger.valueOf(4603), BigInteger.valueOf(4621), BigInteger.valueOf(4637), BigInteger.valueOf(4639), BigInteger.valueOf(4643), BigInteger.valueOf(4649), BigInteger.valueOf(4651), BigInteger.valueOf(4657), BigInteger.valueOf(4663), BigInteger.valueOf(4673), BigInteger.valueOf(4679), BigInteger.valueOf(4691), BigInteger.valueOf(4703), BigInteger.valueOf(4721), BigInteger.valueOf(4723), BigInteger.valueOf(4729), BigInteger.valueOf(4733), BigInteger.valueOf(4751), BigInteger.valueOf(4759), BigInteger.valueOf(4783), BigInteger.valueOf(4787), BigInteger.valueOf(4789), BigInteger.valueOf(4793), BigInteger.valueOf(4799), BigInteger.valueOf(4801), BigInteger.valueOf(4813), BigInteger.valueOf(4817), BigInteger.valueOf(4831), BigInteger.valueOf(4861), BigInteger.valueOf(4871), BigInteger.valueOf(4877), BigInteger.valueOf(4889), BigInteger.valueOf(4903), BigInteger.valueOf(4909), BigInteger.valueOf(4919), BigInteger.valueOf(4931), BigInteger.valueOf(4933), BigInteger.valueOf(4937), BigInteger.valueOf(4943), BigInteger.valueOf(4951), BigInteger.valueOf(4957), BigInteger.valueOf(4967), BigInteger.valueOf(4969), BigInteger.valueOf(4973), BigInteger.valueOf(4987), BigInteger.valueOf(4993), BigInteger.valueOf(4999) };

        private final ProbabilityTest testType;
        private final float probability;
        private final int keyBitLength;

        public RSAKeyGenerator(ProbabilityTestType testType, float probability, int keyBitLength) {
            this.testType = switch (testType) {
                case Fermat -> new FermatProbabilityTest();
                case SolovayStrassen -> new SolovayStrassen();
                case MillerRabin -> new MillerRabinProbabilityTest();
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

    // есть некоторый текст / картинка / последвательность байтов: каким числом M его представить?
    // представить как массив байт
    // беру такое число, чтобы оно было меньше N и взаимно просто с p и q

    // про перегенерацию ключей: на каждое новое шифрование генерировать заново пару чисел p и q? соответственно с шифротекстом возвращать только открытый и закрытый ключи (e, N), (d, N) из метода не храня в самом объекте RSA?
    // пользователь сам вызывает метод получения ключей. делает с ними что хочет и передает rsa в методы encrypt и decrypt

    // как выбрать такое d, что d >= sqrt[4]{N} / 3?
    // сначала выбрать правильное d и по нему восстановить e

    // кол-во шифротекстов меньше e иначе не давать шифровать

    // [уточнение] задание 5: мы получаем p и q не через generate из задания 3, а просто сами
    // выбираем 2 близких числа, считаем N, для него выбираем некоторое e и d
    // Алгоритму подаем на вход e и N. Он возвращает p, q, phi(N), d
    // phi(N)=(p-1)(q-1)

    // [вопрос] задание 6: как получить функцию Эйлера, не зная p и q, Но зная e, d, N
    // решить квадратное уравнение, корнями которого будут p и q.
    // оно имеет вид: см ссылку в вк

}
