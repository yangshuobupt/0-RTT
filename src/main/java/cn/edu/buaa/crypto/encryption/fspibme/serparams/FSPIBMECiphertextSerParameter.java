package cn.edu.buaa.crypto.encryption.fspibme.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class FSPIBMECiphertextSerParameter extends PairingCipherSerParameter {

    private PairingCipherSerParameter W;
    private Element sig;
    private SigPublicParameter sig_pk;


    public FSPIBMECiphertextSerParameter(PairingParameters pairingParameters, PairingCipherSerParameter W, Element sig, SigPublicParameter sig_pk) {
        super(pairingParameters);

        this.W = W;
        this.sig = sig;
        this.sig_pk = sig_pk;
    }

    public PairingCipherSerParameter getW() {
        return W;
    }

    public void setW(PairingCipherSerParameter w) {
        W = w;
    }

    public Element getSig() {
        return sig;
    }

    public void setSig(Element sig) {
        this.sig = sig;
    }

    public SigPublicParameter getSig_pk() {
        return sig_pk;
    }

    public void setSig_pk(SigPublicParameter sig_pk) {
        this.sig_pk = sig_pk;
    }

}
