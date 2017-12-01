/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 *
 * @author evgeniy
 */
public class CommonTools {
    
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
    public static byte[] readBytesFromFile(File f, int from, int to) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(f, "r");
        raf.seek(from);
        byte[] res = new byte[to - from];
        raf.read(res, 0, to - from);

        raf.close();
        return res;
    }
    
    /**
     * Подсчет количества целых блоков
     * @param f Файл с данными
     * @param blockSize Размер блока
     * @return Количество блоков
     */
    public static int countBlocks(File f, int blockSize) { 
        return (int) (f.length() / blockSize);
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
     * Выполняет конкатенацию двух массивов байт
     * @return конкатенация массивов a и b
     */
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);

        return result;
    }
}
