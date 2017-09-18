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
    }
}
