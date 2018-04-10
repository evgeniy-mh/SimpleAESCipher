package com.evgeniy_mh.simpleaescipher.AESEngine.CCM;

import com.evgeniy_mh.simpleaescipher.AESEngine.AES_CTREncryptor;
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

public class MAC_then_Encrypt {
    
    private AES_CTREncryptor mAESEncryptor;
    
    public MAC_then_Encrypt(ProgressIndicator progressIndicator){
        mAESEncryptor=new AES_CTREncryptor(progressIndicator);
    }

    public Task encrypt(File in, File out, MACOptions options) {
        return new Task<Void>() {
            @Override
            protected Void call() throws IOException {
                File tempFile = new File(in.getAbsolutePath() + "_temp");
                FileUtils.createFileCopy(in, tempFile);

                Task MACTask = null;

                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        MACTask = ecbce.getECBC(tempFile, null, options.getKey1(), options.getKey2(), true);
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        MACTask = hmace.getHMAC(tempFile, null, options.getKey1(), true);
                        break;
                }
                Thread MACThread = new Thread(MACTask);
                MACThread.start();

                try {
                    MACThread.join();
                } catch (InterruptedException ex) {
                    CommonUtils.reportExceptionToMainThread(ex, "MACThread.join();");
                }

                mAESEncryptor.encrypt(tempFile, out, options.getKey1()).run();

                tempFile.delete();
                return null;
            }
        };
    }

    public Task decrypt(File in, File out, MACOptions options) {
        return new Task<Boolean>() {
            @Override
            protected Boolean call() throws IOException {
                File tempFile = new File(out.getAbsolutePath() + "_temp");

                mAESEncryptor.decrypt(in, tempFile, options.getKey1()).run();

                System.out.println("tempFile.length()="+tempFile.length());
                byte[] MACFromFile = FileUtils.readBytesFromFile(tempFile, (int) tempFile.length() - 16, (int) tempFile.length());

                try (RandomAccessFile OUTraf = new RandomAccessFile(tempFile, "rw")) {
                    OUTraf.setLength(tempFile.length() - 16);
                }

                byte[] resultMAC = null;
                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        resultMAC = ecbce.getECBC(tempFile, options.getKey1(), options.getKey2());
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        resultMAC = hmace.getHMAC(FileUtils.readBytesFromFile(tempFile, (int) tempFile.length()), options.getKey1());
                        break;
                }

                if (resultMAC != null && Arrays.equals(MACFromFile, resultMAC)) {
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
