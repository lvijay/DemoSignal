package hacking.signal;

import java.util.Arrays;
import java.util.Iterator;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.whispersystems.libsignal.protocol.PreKeySignalMessage;

public class Demo {
    public static void main(String[] args)
            throws Exception
    {
        Entity alice = new Entity(1, 314159, "alice");
        Entity bob = new Entity(2, 27182, "bob");

        Session aliceSession = new Session(alice.getStore());
        Session bobSession = new Session(bob.getStore());

        aliceSession.introduceTo(bob);
        bobSession.introduceTo(alice);

        Sender bobToAlice = new Sender(
                supplier("10,21,33,42,5d,6c".split(",")),
                plaintext -> aliceSession.encrypt("bob", plaintext),
                m -> System.out.printf("a->b: '%s'%n", bobSession.decrypt("alice", m)));
        Sender aliceToBob = new Sender(
                supplier("a,b,c,d,e,f,g,h,i,j,k".split(",")),
                plaintext -> bobSession.encrypt("alice", plaintext),
                m -> System.out.printf("b->a: '%s'%n", aliceSession.decrypt("bob", m)));

        bobToAlice.run();
        System.out.println("--");
        aliceToBob.run();
    }

    static Supplier<String> supplier(String[] strings) {
        Iterator<String> iter = Arrays.asList(strings).iterator();
        return () -> iter.hasNext() ? iter.next() : null;
    }

    static class Sender implements Runnable {
        private final Supplier<String> messages;
        private final Function<String, PreKeySignalMessage> encrypter;
        private final Consumer<PreKeySignalMessage> sender;

        public Sender(Supplier<String> messages, Function<String, PreKeySignalMessage> encrypter, Consumer<PreKeySignalMessage> sender) {
            this.messages = messages;
            this.encrypter = encrypter;
            this.sender = sender;
        }

        @Override
        public void run() {
            String message;
            while ((message = messages.get()) != null) {
                sender.accept(encrypter.apply(message));
                Thread.yield();
            }
        }
    }
}
