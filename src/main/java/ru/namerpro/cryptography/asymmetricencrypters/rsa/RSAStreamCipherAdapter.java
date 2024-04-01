package ru.namerpro.cryptography.asymmetricencrypters.rsa;

public class RSAStreamCipherAdapter /*implements SymmetricEncrypter, AutoCloseable*/ {

//    private final ExecutorService service = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
//    private final RSA rsa;
//    private final EncryptMode mode;
//
//    public RSAStreamCipherAdapter(RSA rsa, Mode mode, byte[] iv) {
//        if (iv == null && mode != Mode.ECB) {
//            throw new IllegalArgumentException("No initialization vector passed, but it's required for '" + mode.name() + "' encrypt mode!");
//        }
//        this.rsa = rsa;
//        this.mode = switch (mode) {
//            case ECB -> new ECB(service);
//            case CBC -> new CBC(service, iv);
//            case PCBC -> new PCBC(service, iv);
//            case CFB -> new CFB(service, iv);
//            case OFB -> new OFB(iv);
//            case CTR -> new CTR(service, iv);
//            case RD -> new RD(service, iv);
//        };
//    }
//
//    @Override
//    public byte[] encrypt(byte[] block) {
//        String base64String = Base64.getEncoder().encodeToString(block);
//        return mode.apply(block, )
//    }
//
//    @Override
//    public byte[] decrypt(byte[] block) {
//        return new byte[0];
//    }
//
//    @Override
//    public void close() throws Exception {
//        service.shutdown();
//        service.shutdownNow();
//    }

}
