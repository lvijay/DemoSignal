package hacking.signal;

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
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SignalProtocolStore;

public class Session {
    private final SignalProtocolStore store;
    private final Map<String, SessionCipher> sessions;

    public Session(SignalProtocolStore store) {
        this.store = store;
        this.sessions = new HashMap<>();
    }

    public void introduceTo(String toAddress, PreKeyBundle preKey) {
        sessions.computeIfAbsent(toAddress, ignored -> {
            try {
                SignalProtocolAddress to = new SignalProtocolAddress(toAddress, 1);
                SessionBuilder builder = new SessionBuilder(store, to);

                builder.process(preKey);

                return new SessionCipher(store, to);
            } catch (InvalidKeyException | UntrustedIdentityException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public PreKeySignalMessage encrypt(String toAddress, String message)
            throws InvalidMessageException, InvalidVersionException
    {
        SessionCipher cipher = sessions.getOrDefault(toAddress, null);

        if (cipher == null) {
            throw new IllegalStateException("initiate session first");
        }

        CiphertextMessage ciphertext = cipher.encrypt(message.getBytes(Demo.UTF8));
        byte[] rawCiphertext = ciphertext.serialize();

        System.out.printf("to=%s msg=%s%n", toAddress, byteArrayToString(rawCiphertext));

        PreKeySignalMessage messageToToAddress = new PreKeySignalMessage(rawCiphertext);

        return messageToToAddress;
    }

    public String decrypt(String fromAddress, PreKeySignalMessage ciphertext)
            throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException
    {
        SessionCipher cipher = sessions.getOrDefault(fromAddress, null);

        if (cipher == null) {
            throw new IllegalStateException("unknown sender");
        }

        System.out.println(byteArrayToString(ciphertext.serialize()));

        byte[] decrypt = cipher.decrypt(ciphertext, new DecryptionCallback() {
            @Override
            public void handlePlaintext(byte[] plaintext) {
                System.out.printf("callback: %s%n", new String(plaintext, Demo.UTF8));
            }
        });

        return new String(decrypt, Demo.UTF8);
    }

    private String byteArrayToString(byte[] rawCiphertext) {
        return IntStream.range(0, rawCiphertext.length)
                .mapToObj(i -> Byte.toString(rawCiphertext[i]))
                .collect(Collectors.joining(", ", "[", "]"));
    }
}
