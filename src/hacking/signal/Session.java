package hacking.signal;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.whispersystems.libsignal.DecryptionCallback;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.state.SignalProtocolStore;

public class Session {
    private enum Operation { ENCRYPT, DECRYPT; }
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private final SignalProtocolStore store;
    private final Map<String, SessionCipher> sessions;
    private final Map<String, Entity> entities;
    private volatile Operation lastOp;

    public Session(SignalProtocolStore store) {
        this.store = store;
        this.sessions = new HashMap<>();
        this.entities = new HashMap<>();
    }

    public void introduceTo(Entity entity) {
        entities.put(entity.getAddress(), entity);
    }

    /*default*/ SessionCipher getCipher(Operation operation, String to) {
        Entity toEntity = entities.get(to);

        if (toEntity == null) {
            throw new IllegalStateException();
        }

        if (operation == lastOp) {
            return sessions.get(to);
        }

        SignalProtocolAddress toAddress = new SignalProtocolAddress(to, 1);
        SessionBuilder builder = new SessionBuilder(store, toAddress);

        try {
            builder.process(toEntity.getPreKey());
        } catch (InvalidKeyException | UntrustedIdentityException e) {
            throw new RuntimeException(e);
        }

        SessionCipher cipher = new SessionCipher(store, toAddress);

        sessions.put(to, cipher);
        lastOp = operation;

        return cipher;
    }

    public synchronized PreKeySignalMessage encrypt(String toAddress, String message) {
        SessionCipher cipher = getCipher(Operation.ENCRYPT, toAddress);

        CiphertextMessage ciphertext = cipher.encrypt(message.getBytes(UTF8));
        byte[] rawCiphertext = ciphertext.serialize();

//        System.out.printf("to=%s msg=%s%n", toAddress, byteArrayToString(rawCiphertext));

        PreKeySignalMessage messageToToAddress;
        try {
            messageToToAddress = new PreKeySignalMessage(rawCiphertext);
        } catch (InvalidMessageException | InvalidVersionException e) {
            throw new RuntimeException(e);
        }

        return messageToToAddress;
    }

    public synchronized String decrypt(String fromAddress, PreKeySignalMessage ciphertext) {
        SessionCipher cipher = getCipher(Operation.DECRYPT, fromAddress);

//        System.out.println(byteArrayToString(ciphertext.serialize()));

        byte[] decrypt;
        try {
            decrypt = cipher.decrypt(ciphertext, new DecryptionCallback() {
                @Override
                public void handlePlaintext(byte[] plaintext) {
//                System.out.printf("callback: %s%n", new String(plaintext, UTF8));
                }
            });
        } catch (DuplicateMessageException | LegacyMessageException | InvalidMessageException | InvalidKeyIdException
                | InvalidKeyException | UntrustedIdentityException e) {
            throw new RuntimeException(e);
        }

        return new String(decrypt, UTF8);
    }

    private String byteArrayToString(byte[] rawCiphertext) {
        return IntStream.range(0, rawCiphertext.length)
                .mapToObj(i -> Byte.toString(rawCiphertext[i]))
                .collect(Collectors.joining(", ", "[", "]"));
    }
}
