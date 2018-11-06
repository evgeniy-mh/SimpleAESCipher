package com.evgeniy_mh.simpleaescipher.AESEngine.CCM;

import com.evgeniy_mh.simpleaescipher.AESEngine.ECBCEncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.HMACEncryptor;
import com.evgeniy_mh.simpleaescipher.CommonUtils;
import com.evgeniy_mh.simpleaescipher.FileUtils;
import com.evgeniy_mh.simpleaescipher.MACOptions;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;

public class Encrypt_and_MAC extends CCMEncryptor{

    public Encrypt_and_MAC(ProgressIndicator progressIndicator) {
        super(progressIndicator);
    }
    
    @Override
    public Task encrypt(File in, File out, MACOptions options) {
        return new Task<Void>() {
            @Override
            protected Void call() throws IOException {
                mAES_CTREncryptor.encrypt(in, out, options.getKey1()).run();
                Task MACTask = null;
                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        MACTask = ecbce.addECBCToFile(in, out, options.getKey1(), options.getKey2());
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        MACTask = hmace.addHMACToFile(in, out, options.getKey1());
                        break;
                }
                Thread MACThread = new Thread(MACTask);
                MACThread.start();

                try {
                    MACThread.join();
                } catch (InterruptedException ex) {
                    CommonUtils.reportExceptionToMainThread(ex, "MACThread.join();");
                }
                return null;
            }
        };
    }
    
    @Override
    public Task decrypt(File in, File out, MACOptions options) {
        return new Task<Boolean>() {
            @Override
            protected Boolean call() throws IOException {
                byte[] MACFromFile = FileUtils.readBytesFromFile(in, (int) in.length() - 16, (int) in.length());
                File tempFile = new File(in.toPath() + "_temp");
                FileUtils.createFileCopy(in, tempFile, in.length() - 16);
                mAES_CTREncryptor.decrypt(tempFile, out, options.getKey1()).run();

                byte[] MAC = null;
                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        MAC = ecbce.getECBC(out, options.getKey1(), options.getKey2());
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        MAC = hmace.getHMAC(FileUtils.readBytesFromFile(out, (int) out.length()), options.getKey1());
                        break;
                }

                if (MAC != null && Arrays.equals(MACFromFile, MAC)) {
                    tempFile.delete();
                    return true;
                } else {
                    tempFile.delete();
                    return false;
                }
            }
        };
    }
}
