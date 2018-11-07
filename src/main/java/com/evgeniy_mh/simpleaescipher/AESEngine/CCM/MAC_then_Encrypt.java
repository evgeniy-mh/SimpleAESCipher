package com.evgeniy_mh.simpleaescipher.AESEngine.CCM;

import com.evgeniy_mh.simpleaescipher.AESEngine.ECBCEncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.HMACEncryptor;
import com.evgeniy_mh.simpleaescipher.CommonUtils;
import com.evgeniy_mh.simpleaescipher.FileUtils;
import com.evgeniy_mh.simpleaescipher.MACOptions;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;

public class MAC_then_Encrypt extends CCMEncryptor {

    public MAC_then_Encrypt(ProgressIndicator progressIndicator) {
        super(progressIndicator);
    }

    @Override
    public Task encrypt(File in, File out, MACOptions options) {
        return new Task<Void>() {
            @Override
            protected Void call() {
                File tempFile = new File(in.getAbsolutePath() + "_temp");
                FileUtils.createFileCopy(in, tempFile);

                Task MACTask = null;

                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        MACTask = ecbce.addECBCToFile(tempFile, options.getKey1(), options.getKey2());
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        MACTask = hmace.addHMACToFile(tempFile, options.getKey1());
                        break;
                }
                Thread MACThread = new Thread(MACTask);
                MACThread.start();

                try {
                    MACThread.join();
                } catch (InterruptedException ex) {
                    CommonUtils.reportExceptionToMainThread(ex, "MACThread.join();");
                }

                switch (options.getMode()) {
                    case CBC:
                        mAES_CBCEncryptor.encrypt(tempFile, out, options.getKey1()).run();
                        break;
                    case CTR:
                        mAES_CTREncryptor.encrypt(tempFile, out, options.getKey1()).run();
                        break;
                }

                tempFile.delete();
                return null;
            }
        };
    }

    @Override
    public Task decrypt(File in, File out, MACOptions options) {
        return new Task<Boolean>() {
            @Override
            protected Boolean call() throws IOException {
                File tempFile = new File(out.getAbsolutePath() + "_temp");

                switch (options.getMode()) {
                    case CBC:
                        mAES_CBCEncryptor.decrypt(in, tempFile, options.getKey1()).run();
                        break;
                    case CTR:
                        mAES_CTREncryptor.decrypt(in, tempFile, options.getKey1()).run();
                        break;
                }
                
                byte[] MACFromFile = FileUtils.readBytesFromFile(tempFile, (int) tempFile.length() - 16, (int) tempFile.length());

                try (RandomAccessFile OUTraf = new RandomAccessFile(tempFile, "rw")) {
                    OUTraf.setLength(tempFile.length() - 16);
                }

                byte[] MAC = null;
                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        MAC = ecbce.getECBC(tempFile, options.getKey1(), options.getKey2());
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        MAC = hmace.getHMAC(FileUtils.readBytesFromFile(tempFile, (int) tempFile.length()), options.getKey1());
                        break;
                }

                if (MAC != null && Arrays.equals(MACFromFile, MAC)) {
                    FileUtils.createFileCopy(tempFile, out, tempFile.length());
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
