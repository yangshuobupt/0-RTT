package cn.edu.buaa.crypto.encryption.fspibme.serparams;

import it.unisa.dia.gas.jpbc.Element;

public class SigPublicParameter {
    private Element g;
    private Element B;
    private Element Z;
    private Element sig_sk;

    public Element getG() {
        return g;
    }

    public void setG(Element g) {
        this.g = g;
    }

    public Element getB() {
        return B;
    }

    public void setB(Element b) {
        B = b;
    }

    public Element getZ() {
        return Z;
    }

    public void setZ(Element z) {
        Z = z;
    }

    public Element getSig_sk() {
        return sig_sk;
    }

    public void setSig_sk(Element sig_sk) {
        this.sig_sk = sig_sk;
    }

    public SigPublicParameter(Element g, Element b, Element z, Element sig_sk) {
        this.g = g;
        this.B = b;
        this.Z = z;
        this.sig_sk = sig_sk;
    }
}
