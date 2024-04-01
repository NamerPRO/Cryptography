package ru.namerpro.cryptography.context;

import ru.namerpro.cryptography.api.EncryptMode;
import ru.namerpro.cryptography.api.PaddingMode;
import ru.namerpro.cryptography.api.SymmetricEncrypter;
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
    private final EncryptMode mode;
    private final PaddingMode padding;
    private final SymmetricEncrypter encrypter;
    private final int blockSize;

    public SymmetricEncrypterContext(Encrypter encrypter, byte[] key, Mode mode, Padding padding, byte[] iv, Object... arguments) {
        switch (encrypter) {
            case DES -> {
                this.encrypter = new DES(key);
                this.blockSize = 8;
            }
            case DEAL -> {
                this.encrypter = new DEAL(key);
                this.blockSize = 16;
            }
            default -> throw new RuntimeException("Unexpected error occurred while trying to set encrypter!");
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
            case Zeros -> new Zeros();
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
