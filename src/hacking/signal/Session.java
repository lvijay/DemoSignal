/*
 * DemoSignal — Demonstrate the signal protocol.
 * Copyright (C) 2017 Vijay Lakshminarayanan <lvijay@gmail.com>.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package hacking.signal;

import java.nio.charset.Charset;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SignalProtocolStore;

public class Session {
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private /* static */ enum Operation { ENCRYPT, DECRYPT; }

    private final SignalProtocolStore self;
    private PreKeyBundle otherKeyBundle;
    private SignalProtocolAddress otherAddress;
    private Operation lastOp;
    private SessionCipher cipher;

    public Session(SignalProtocolStore self,
            PreKeyBundle otherKeyBundle,
            SignalProtocolAddress otherAddress)
    {
        this.self = self;
        this.otherKeyBundle = otherKeyBundle;
        this.otherAddress = otherAddress;
    }

    private synchronized SessionCipher getCipher(Operation operation) {
        if (operation == lastOp) {
            return cipher;
        }

        SignalProtocolAddress toAddress = otherAddress;
        SessionBuilder builder = new SessionBuilder(self, toAddress);

        try {
            builder.process(otherKeyBundle);
        } catch (InvalidKeyException | UntrustedIdentityException e) {
            throw new RuntimeException(e);
        }

        this.cipher = new SessionCipher(self, toAddress);
        this.lastOp = operation;

        return cipher;
    }

    public PreKeySignalMessage encrypt(String message) {
        SessionCipher cipher = getCipher(Operation.ENCRYPT);

        CiphertextMessage ciphertext = cipher.encrypt(message.getBytes(UTF8));
        byte[] rawCiphertext = ciphertext.serialize();

        try {
            PreKeySignalMessage encrypted = new PreKeySignalMessage(rawCiphertext);

            return encrypted;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(PreKeySignalMessage ciphertext) {
        SessionCipher cipher = getCipher(Operation.DECRYPT);

        try {
            byte[] decrypted = cipher.decrypt(ciphertext);

            return new String(decrypted, UTF8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
