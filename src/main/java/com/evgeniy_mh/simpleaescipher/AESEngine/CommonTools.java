/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;

/**
 *
 * @author evgeniy
 */
public class CommonTools {
    
    /**
     * Подсчет количества целых блоков
     * @param f Файл с данными
     * @param blockSize Размер блока
     * @return Количество блоков
     */
    public static int countBlocks(File f, int blockSize) { 
        return (int) (f.length() / blockSize);
    }
    
}
