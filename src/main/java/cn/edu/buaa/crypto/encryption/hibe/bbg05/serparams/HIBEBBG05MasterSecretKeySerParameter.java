package cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2015/11/3.
 * <p>
 * Master Secret Key Paramaters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05MasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element g2Alpha;
    private final byte[] byteArrayG2Alpha;


    public HIBEBBG05MasterSecretKeySerParameter(PairingParameters pairingParameters, Element g2Alpha) {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
        this.byteArrayG2Alpha = this.g2Alpha.toBytes();
    }

    public Element getG2Alpha() {
        return this.g2Alpha.duplicate();
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.g2Alpha = pairing.getG1().newElementFromBytes(this.byteArrayG2Alpha).getImmutable();
    }

}
