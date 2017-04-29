package com.evgeniy_mh.simpleaescipher.AESEngine;

import com.evgeniy_mh.simpleaescipher.MainController;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;

/**
 * Created by evgeniy on 08.04.17.
 */
public class AESEncryptor {

    private AES mAES;
    private ProgressIndicator progressIndicator;

    public AESEncryptor(ProgressIndicator progressIndicator) {
        mAES = new AES();        
        this.progressIndicator=progressIndicator;
    }

    /**
     * Выполняет шифрование файла
     *
     * @param in Файл открытого текста
     * @param out Файл для сохранения результата шифрования (будет перезаписан)
     * @param key Ключ шифрования
     */
    public void encrypt(File in, File out, final byte[] key) {
        Task t = new Task<Void>() {
            @Override
            protected Void call() throws IOException {
                byte[] nonce = ByteBuffer.allocate(8).putInt(getNonce()).array();
                byte[] counter = ByteBuffer.allocate(8).putInt(0).array();
                byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE]; //используется в раундах //nonceAndCounter: 0000nnnn|0000cccc
                byte[] nonceAndCounterInfo = new byte[8]; //8 байт которые добавл в начало сообщения и несут инфу о nonce и counter //nonceAndCounterInfo: nnnncccc
                System.arraycopy(nonce, 0, nonceAndCounterInfo, 0, 4);
                System.arraycopy(counter, 0, nonceAndCounterInfo, 4, 4);

                byte[] tempKey = key;
                if (key.length % AES.BLOCK_SIZE != 0) {
                    tempKey = PKCS7(key);
                }
                mAES.makeKey(tempKey, 128, AES.DIR_BOTH);
                try {
                    RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
                    OUTraf.setLength(8 + in.length());

                    OUTraf.write(nonceAndCounterInfo);

                    RandomAccessFile INraf = new RandomAccessFile(in, "r");

                    int nBlocks = countBlocks(in); //сколько блоков открытого текста
                    byte[] temp = new byte[AES.BLOCK_SIZE];

                    for (int i = 0; i < nBlocks + 1; i++) {
                        INraf.seek(i * 16); //установка указателя для считывания файла

                        if ((i + 1) == nBlocks + 1) { //последняя итерация
                            int deltaToBlock = (int) (in.length() % AES.BLOCK_SIZE);
                            if (deltaToBlock > 0) {
                                temp = new byte[deltaToBlock];
                                INraf.read(temp, 0, deltaToBlock);  //считывание неполного блока в temp
                                temp = PKCS7(temp);
                            } else {
                                temp = new byte[AES.BLOCK_SIZE];
                                for (int t = 0; t < AES.BLOCK_SIZE; t++) {
                                    temp[t] = (byte) AES.BLOCK_SIZE;
                                }
                            }
                        } else {
                            INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp
                        }
                        counter = ByteBuffer.allocate(8).putInt(i).array();
                        System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
                        System.arraycopy(counter, 0, nonceAndCounter, 12, 4);//nonceAndCounter: 0000nnnn|0000cccc

                        byte[] k = new byte[AES.BLOCK_SIZE]; // k_i
                        mAES.encrypt(nonceAndCounter, k);

                        byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
                        for (int j = 0; j < AES.BLOCK_SIZE; j++) { //xor p_i и k_i
                            c[j] = (byte) (temp[j] ^ k[j]);
                        }
                        OUTraf.write(c);
                        progressIndicator.setProgress((double)i / nBlocks);
                    }
                    OUTraf.close();
                    INraf.close();
                } catch (IOException e) {
                    reportExceptionToMainThread(e,"Exception in encrypt thread!");
                }
                progressIndicator.setProgress(0.0);
                return null;
            }
        };
        new Thread(t).start();
    } 

    /**
     * Выполняет дешифрование файла
     *
     * @param in Файл шифрованного текста
     * @param out Файл для сохранения результата расшифрования (будет
     * перезаписан)
     * @param key Ключ шифрования
     */
    public void decrypt(File in, File out, final byte[] key){
        Task t = new Task<Void>() {
            @Override
            protected Void call() throws IOException {
                byte[] nonceAndCounterInfo = new byte[8]; //8 байт которые добавл в начало сообщения и несут инфу о nonce и counter //nonceAndCounterInfo: nnnncccc        
                nonceAndCounterInfo = readBytesFromFile(in, 0, 8);

                byte[] nonce = new byte[8];
                byte[] counter = new byte[8];
                System.arraycopy(nonceAndCounterInfo, 0, nonce, 0, 4);
                System.arraycopy(nonceAndCounterInfo, 4, counter, 0, 4);

                byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE];

                byte[] tempKey = key;
                if (key.length % AES.BLOCK_SIZE != 0) {
                    tempKey = PKCS7(key);
                }
                mAES.makeKey(tempKey, 128, AES.DIR_BOTH);
                try {
                    RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
                    OUTraf.setLength(in.length() - 8);
                    RandomAccessFile INraf = new RandomAccessFile(in, "r");

                    int nBlocks = countBlocks(in); //сколько блоков шифро текста
                    int nToDeleteBytes = 0; //сколько байт нужно удалить с конца сообщения

                    byte[] temp = new byte[AES.BLOCK_SIZE];
                    for (int i = 0; i < nBlocks; i++) {
                        INraf.seek(i * 16 + 8); //установка указателя для считывания файла
                        INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp

                        counter = ByteBuffer.allocate(8).putInt(i).array();
                        System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
                        System.arraycopy(counter, 0, nonceAndCounter, 12, 4);

                        byte[] k = new byte[AES.BLOCK_SIZE]; // k_i

                        mAES.encrypt(nonceAndCounter, k);

                        byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
                        for (int j = 0; j < AES.BLOCK_SIZE; j++) { //xor p_i и k_i
                            c[j] = (byte) (temp[j] ^ k[j]);
                        }
                        OUTraf.write(c);

                        if ((i + 1) == nBlocks) {
                            if (c[AES.BLOCK_SIZE - 1] > 0 && c[AES.BLOCK_SIZE - 1] <= 16) {
                                nToDeleteBytes = c[AES.BLOCK_SIZE - 1]; //на случай дешифрования с неправильным ключем
                            }
                        }
                        progressIndicator.setProgress((double)i / nBlocks);
                    }
                    OUTraf.setLength(OUTraf.length() - nToDeleteBytes);

                    OUTraf.close();
                    INraf.close();
                } catch (IOException e) {
                    reportExceptionToMainThread(e, "Exception in decrypt thread!");
                }
                progressIndicator.setProgress(0.0);
                return null;
            }            
        };
        new Thread(t).start();
    }
    
  

    /**
     * Дополняет массив байт до размера кратного AES.BLOCK_SIZE по стандарту
     * PKCS7
     *
     * @param b-массив байт для которого будет выполнено дополнение PKCS7
     * @return Дополненный массив байт
     */
    private byte[] PKCS7(byte[] b) {
        int n = countDeltaBlocks(b); //сколько байт нужно добавить и какое у них будет значение 
        if (n != 0) {
            byte[] bPadded = new byte[b.length + n];
            for (int i = 0; i < bPadded.length; i++) {
                if (i < b.length) {
                    bPadded[i] = b[i];
                } else {
                    bPadded[i] = (byte) n;
                }
            }
            return bPadded;
        } else {
            return b;
        }
    }

    /**
     * Считывание необходимого количества байт из файла
     *
     * @param f Файл для считывания
     * @param from Начальная позиция для считывания из файла(Номер байта)
     * @param to Конечная позиция для считывания из файла(Номер байта)
     * @return Массив байт которые были считаны из файла
     * @throws FileNotFoundException
     * @throws IOException
     */
    private byte[] readBytesFromFile(File f, int from, int to) throws FileNotFoundException, IOException {
        RandomAccessFile raf = new RandomAccessFile(f, "r");
        raf.seek(from);
        byte[] res = new byte[to - from];
        raf.read(res, 0, to - from);

        raf.close();
        return res;
    }

    /**
     * Получить Nonce
     * @return значение Nonce
     */
    private int getNonce() {
        return Nonce.getInstance().getNonce();
    }

    /**
     * Подсчет скольких байт не хватает до полного блока
     *
     * @param b Массив байт
     */
    private int countDeltaBlocks(byte[] b) {
        return AES.BLOCK_SIZE - b.length % AES.BLOCK_SIZE;
    }

    /**
     * Подсчет количества целых блоков
     * @param f Файл с данными
     * @return Количество блоков
     */
    public int countBlocks(File f) { 
        return (int) (f.length() / AES.BLOCK_SIZE);
    }

    /**
     * Вывод в консоль массива байт
     *
     * @param mes Сообщение для вывода
     * @param array Массив байт содержимое которого нужно вывести
     */
    static public void debugPrintByteArray(String mes, byte[] array) {
        System.out.println(mes);
        for (int i = 0; i < array.length; i++) {
            System.out.print(String.format("0x%08X", array[i]) + " ");
        }
        System.out.println();
    }
    
    /**
     * Отправка сообщения о исключении в Application Thread
     * @param t
     * @param message Дополнительное сообщение для пользователя
     */
    public void reportExceptionToMainThread(final Throwable t, final String message) {
        Platform.runLater(() -> {
            MainController.showExceptionToUser(t,message);
        });
    }
    
}
