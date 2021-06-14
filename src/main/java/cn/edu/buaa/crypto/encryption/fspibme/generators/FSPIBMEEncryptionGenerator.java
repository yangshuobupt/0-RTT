package cn.edu.buaa.crypto.encryption.fspibme.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.SigPublicParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class FSPIBMEEncryptionGenerator {
    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private HIBEBBG05Engine hibebbg05Engine;
    private String[] tau;
    private Element message;

    public void init(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, Element message, String... tau) {
        this.hibebbg05Engine = hibebbg05Engine;
        this.publicKeyParameter = (HIBEBBG05PublicKeySerParameter) publicKey;
        this.tau = tau;
        this.message = message;
    }


    public FSPIBMECiphertextSerParameter computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        PairingCipherSerParameter ct = hibebbg05Engine.encryption(publicKeyParameter, tau, message);
        HIBEBBG05HeaderSerParameter ciphertextParameters = (HIBEBBG05HeaderSerParameter) ct;

        SigPublicParameter sig_pk = PairingUtils.SigKeyGen(publicKeyParameter);
        Element sig_sk = sig_pk.getSig_sk();
        Element x = pairing.getZr().newElement();
        x.set(10086);
        Element sig = PairingUtils.SigSign(publicKeyParameter, sig_pk, sig_sk, x);

        return new FSPIBMECiphertextSerParameter(publicKeyParameter.getParameters(), ciphertextParameters, sig, sig_pk);
    }

}
