package ru.namerpro.cryptography.context;

import ru.namerpro.cryptography.api.symmetric.modes.SymmetricEncryptMode;
import ru.namerpro.cryptography.api.symmetric.modes.SymmetricPaddingMode;
import ru.namerpro.cryptography.api.symmetric.SymmetricEncrypter;
import ru.namerpro.cryptography.asymmetricencrypters.rsa.RSA;
import ru.namerpro.cryptography.asymmetricencrypters.rsa.SymmetricRSA;
import ru.namerpro.cryptography.context.encrypter.Encrypter;
import ru.namerpro.cryptography.mode.Mode;
import ru.namerpro.cryptography.padding.Padding;
import ru.namerpro.cryptography.padding.impl.ANSIX923;
import ru.namerpro.cryptography.padding.impl.ISO10126;
import ru.namerpro.cryptography.padding.impl.PKCS7;
import ru.namerpro.cryptography.padding.impl.Zeros;
import ru.namerpro.cryptography.encryptionstate.EncryptionState;
import ru.namerpro.cryptography.mode.impl.*;
import ru.namerpro.cryptography.symmetricencrypters.deal.DEAL;
import ru.namerpro.cryptography.symmetricencrypters.des.DES;
import ru.namerpro.cryptography.symmetricencrypters.rijndael.Rijndael;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SymmetricEncrypterContext implements AutoCloseable {

    private final ExecutorService service = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    private final SymmetricEncryptMode mode;
    private final SymmetricPaddingMode padding;
    private final SymmetricEncrypter encrypter;
    private final int blockSize;

    public SymmetricEncrypterContext(Encrypter encrypter, byte[] key, Mode mode, Padding padding, byte[] iv, Object... options) {
        switch (encrypter) {
            case DES -> {
                this.encrypter = new DES(key);
                this.blockSize = 8;
            }
            case DEAL -> {
                this.encrypter = new DEAL(key);
                this.blockSize = 16;
            }
            case RIJNDAEL -> {
                if (options.length != 2 || !(options[0] instanceof Rijndael.RijndaelBlockSize rijndaelBlockSize)
                        || !(options[1] instanceof Integer modulo)) {
                    throw new IllegalArgumentException("Rijndael mode requires these constructor parameters: Encrypter encrypter, byte[] key, Mode mode, Padding padding, byte[] iv, RijndaelBlockSize rijndaelBlockSize, int modulo.");
                }
                this.encrypter = new Rijndael(rijndaelBlockSize, key, modulo.byteValue());
                this.blockSize = switch (rijndaelBlockSize) {
                    case SZ_128_BITS -> 16;
                    case SZ_192_BITS -> 24;
                    case SZ_256_BITS -> 32;
                };
            }
            case RSA -> {
                if (options.length != 3 || !(options[0] instanceof RSA rsa)
                        || !(options[1] instanceof RSA.RSAKeyGenerator.PublicKey publicKey)
                            || !(options[2] instanceof RSA.RSAKeyGenerator.PrivateKey privateKey)) {
                    throw new IllegalArgumentException("Three constructor parameters are required in order to use RSA in symmetric mode: RSA sra, PublicKey publicKey, PrivateKey privateKey, - passed in provided order!");
                }
                this.encrypter = new SymmetricRSA(rsa, publicKey, privateKey);
                this.blockSize = 32;
            }
            default -> throw new IllegalArgumentException("Unexpected error occurred while trying to set encrypter!");
        }

        if (iv == null) {
            if (mode == Mode.ECB) {
                this.mode = new ECB(service);
            } else {
                throw new IllegalArgumentException("No initialization vector passed, but it's required for '" + mode.name() + "' encrypt mode!");
            }
        } else {
            switch (mode) {
                case CBC -> this.mode = new CBC(service, iv);
                case PCBC -> this.mode = new PCBC(service, iv);
                case OFB -> this.mode = new OFB(iv);
                case CFB -> this.mode = new CFB(service, iv);
                case CTR -> this.mode = new CTR(service, iv, this.blockSize);
                case RD -> this.mode = new RD(service, iv);
                default -> throw new IllegalArgumentException("byte[] IV can only be passed in pair with any of the following encrypt modes: CBC, PCBC, OFB, CFB, CTR, RD, - but '" + mode.name() + "' found!");
            }
        }

        this.padding = switch (padding) {
            case PKCS7 -> new PKCS7();
            case ZEROS -> new Zeros();
            case ISO_10126 -> new ISO10126();
            case ANSI_X_923 -> new ANSIX923();
        };
    }

    public CompletableFuture<byte[]> encrypt(byte[] src) {
        return CompletableFuture.supplyAsync(() -> {
            byte[] paddedSrc = padding.add(src, blockSize);
            return mode.apply(paddedSrc, blockSize, encrypter);
        });
    }

    public CompletableFuture<EncryptionState> encrypt(String pathToSrc, String pathToDest) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                byte[] src = Files.readAllBytes(Path.of(pathToSrc));
                var future = encrypt(src);
                OutputStream os = new FileOutputStream(pathToDest);
                os.write(future.get());
                os.flush();
                os.close();
                return new EncryptionState.Success();
            } catch (IOException | ExecutionException | InterruptedException error) {
                Thread.currentThread().interrupt();
                return new EncryptionState.Error(error);
            }
        });
    }

    public CompletableFuture<byte[]> decrypt(byte[] src) {
        return CompletableFuture.supplyAsync(() -> {
            byte[] paddedSrc = mode.reverse(src, blockSize, encrypter);
            return padding.remove(paddedSrc, blockSize);
        });
    }

    public CompletableFuture<EncryptionState> decrypt(String pathToSrc, String pathToDest) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                byte[] src = Files.readAllBytes(Path.of(pathToSrc));
                var future = decrypt(src);
                OutputStream os = new FileOutputStream(pathToDest);
                os.write(future.get());
                os.flush();
                os.close();
                return new EncryptionState.Success();
            } catch (IOException | ExecutionException | InterruptedException error) {
                Thread.currentThread().interrupt();
                return new EncryptionState.Error(error);
            }
        });
    }

    @Override
    public void close() {
        service.shutdown();
        service.shutdownNow();
    }

}
