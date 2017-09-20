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

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;

public class Entity {
    private final SignalProtocolStore store;
    private final PreKeyBundle preKey;
    private final SignalProtocolAddress address;

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

    public SignalProtocolAddress getAddress() {
        return address;
    }
}
