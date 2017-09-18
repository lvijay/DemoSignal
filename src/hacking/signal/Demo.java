package hacking.signal;

import java.nio.charset.Charset;

import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;

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

        for (String message : "one,two,three,four,five,six,seven".split(",")) {
            PreKeySignalMessage encrypt = aliceSession.encrypt(bob.getAddress(), message);
            String decrypt = bobSession.decrypt(alice.getAddress(), encrypt);

            if (!decrypt.equals(message)) {
                throw new IllegalStateException("unexpected message");
            }
            System.out.println("sent and received: '" + message + "'");
        }

        bobSession = new Session(bob.getStore());
        bobSession.introduceTo(alice.getAddress(), alice.getPreKey());
        PreKeySignalMessage encrypt = bobSession.encrypt(alice.getAddress(), "world");

        String decrypt = aliceSession.decrypt(bob.getAddress(), encrypt);

        aliceSession = new Session(alice.getStore());
        aliceSession.introduceTo(bob.getAddress(), bob.getPreKey());
        aliceSession.encrypt(bob.getAddress(), "world");
    }
}
