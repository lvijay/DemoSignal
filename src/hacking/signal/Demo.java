package hacking.signal;

import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.whispersystems.libsignal.protocol.PreKeySignalMessage;

public class Demo {
    public static void main(String[] args) throws Exception {
        /*
         * Create instances of the two parties.
         */
        Entity alice = new Entity(1, 314159, "alice");
        Entity bob = new Entity(2, 271828, "bob");

        /*
         * Establish a session between the two parties.
         */
        Session aliceToBobSession = new Session(alice.getStore(), bob.getPreKey(), bob.getAddress());

        /*
         * alice can now send messages to bob.
         */
        List<PreKeySignalMessage> toBobMessages = Arrays.stream("31,41,59,26,53".split(","))
                .map(msg -> aliceToBobSession.encrypt(msg))
                .collect(Collectors.toList());

        /*
         * For bob to read them, bob must know alice.
         */
        Session bobToAliceSession = new Session(bob.getStore(), alice.getPreKey(), alice.getAddress());

        /*
         * Now bob can decrypt them.
         */
        String fromAliceMessages = toBobMessages.stream()
                .map(encryptedMsg -> bobToAliceSession.decrypt(encryptedMsg))
                .peek(msg -> System.out.printf("Received from alice: '%s'%n", msg))
                .collect(joining(","));

        if (!fromAliceMessages.equals("31,41,59,26,53")) {
            throw new IllegalStateException("No match");
        }

        /*
         * bob, too, can send messages to alice.
         */
        List<PreKeySignalMessage> toAliceMessages = Arrays.stream("the quick brown fox".split(" "))
                .map(msg -> bobToAliceSession.encrypt(msg))
                .collect(toList());

        /*
         * And alice can read bob's messages.
         * Even if they arrive out of order.
         */
        Collections.shuffle(toAliceMessages);
        List<String> fromBobMessages = toAliceMessages.stream()
                .map(encryptedMsg -> aliceToBobSession.decrypt(encryptedMsg))
                .peek(msg -> System.out.printf("Received from bob: '%s'%n", msg))
                .collect(Collectors.toList());

        if (!(fromBobMessages.size() == 4
                && fromBobMessages.contains("the")
                && fromBobMessages.contains("quick")
                && fromBobMessages.contains("brown")
                && fromBobMessages.contains("fox"))) {
            throw new IllegalStateException("No match");
        }
    }
}
