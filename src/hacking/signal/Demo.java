package hacking.signal;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.whispersystems.libsignal.DecryptionCallback;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;

public class Demo {
    static final Charset UTF8 = Charset.forName("UTF-8");

    public static void main(String[] args)
            throws InvalidKeyException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException, DuplicateMessageException, LegacyMessageException, InvalidKeyIdException
    {
        Entity alice = new Entity(1, 314159, "alice");
        Entity bob = new Entity(2, 27182, "bob");

        Session aliceSession = new Session(alice.getStore());

        aliceSession.introduceTo(bob.getAddress(), bob.getPreKey());

        PreKeySignalMessage aliceMsgToBob = aliceSession.encrypt(bob.getAddress(), "hello");

        Session bobSession = new Session(bob.getStore());

        bobSession.introduceTo(alice.getAddress(),  alice.getPreKey());

        String bobMsgFromAlice = bobSession.decrypt(alice.getAddress(), aliceMsgToBob);

        System.out.println("alice sent bob '" + bobMsgFromAlice + "'");
    }
}

class Session {
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

        byte[] decrypt = cipher.decrypt(ciphertext, new DecryptionCallback() {
            @Override
            public void handlePlaintext(byte[] plaintext) {
                System.out.printf("callback: %s%n", new String(plaintext, Demo.UTF8));
            }
        });

        return new String(decrypt, Demo.UTF8);
    }
}

class Entity {
    final SignalProtocolStore store;
    final PreKeyBundle preKey;
    final SignalProtocolAddress address;

    public Entity(int preKeyId, int signedPreKeyId, String address)
            throws InvalidKeyException
    {
        this.address = new SignalProtocolAddress(address, 1);
        this.store = new InMemorySignalProtocolStore(
                KeyHelper.generateIdentityKeyPair(),
                KeyHelper.generateRegistrationId(false));
        IdentityKeyPair identityKeyPair = store.getIdentityKeyPair();
        int registrationId = store.getLocalRegistrationId();

        ECKeyPair preKeyPair = Curve.generateKeyPair();
        ECKeyPair signedPreKeyPair = Curve.generateKeyPair();
        int deviceId = 1;
        long timestamp = System.currentTimeMillis();

        byte[] signedPreKeySignature = Curve.calculateSignature(
                identityKeyPair.getPrivateKey(),
                signedPreKeyPair.getPublicKey().serialize());

        IdentityKey identityKey = identityKeyPair.getPublicKey();
        ECPublicKey preKeyPublic = preKeyPair.getPublicKey();
        ECPublicKey signedPreKeyPublic = signedPreKeyPair.getPublicKey();

        this.preKey = new PreKeyBundle(
                registrationId,
                deviceId,
                preKeyId,
                preKeyPublic,
                signedPreKeyId,
                signedPreKeyPublic,
                signedPreKeySignature,
                identityKey);

        PreKeyRecord preKeyRecord = new PreKeyRecord(preKey.getPreKeyId(), preKeyPair);
        SignedPreKeyRecord signedPreKeyRecord = new SignedPreKeyRecord(
                signedPreKeyId, timestamp, signedPreKeyPair, signedPreKeySignature);

        store.storePreKey(preKeyId, preKeyRecord);
        store.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord);
    }

    public SignalProtocolStore getStore() {
        return store;
    }

    public PreKeyBundle getPreKey() {
        return preKey;
    }

    public String getAddress() {
        return address.getName();
    }
}
