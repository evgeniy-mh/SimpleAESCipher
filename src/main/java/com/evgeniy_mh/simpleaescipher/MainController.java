package com.evgeniy_mh.simpleaescipher;

import com.evgeniy_mh.simpleaescipher.AESEngine.AES_CTREncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.CommonTools;
import com.evgeniy_mh.simpleaescipher.AESEngine.ECBCEncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.HMACEncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.Nonce;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MainController {

    private Stage stage;
    private FileChooser fileChooser = new FileChooser();
    private MainApp mainApp;

    //AES-CTR tab
    private File originalFileAES;
    private File resultFileAES;
    private File keyFileAES;
    private File key2FileECBC;
    
    @FXML
    TextField originalFilePathAES;
    @FXML
    TextArea originalFileTextAreaAES;
    @FXML
    Button createOriginalFileAES;
    @FXML
    Button openOriginalFileAES;
    @FXML
    Button saveOriginalFileAES;
    @FXML
    Button saveAsOriginalFileAES;    
    @FXML
    TextField resultFilePathAES;
    @FXML
    TextArea resultFileTextAreaAES;
    @FXML
    Button createResultFileAES;
    @FXML
    Button openResultFileAES;
    @FXML
    Button saveAsResultFileAES;    
    @FXML
    TextField keyTextFieldAES;
    @FXML
    Button openKeyFileAES;
    @FXML
    Button encryptButtonAES;
    @FXML
    Button decryptButtonAES;
    @FXML
    CheckBox CreateHMACCheckBox;
    @FXML
    CheckBox CreateECBCCheckBox;
    @FXML
    TextField key2TextFieldECBC;
    @FXML
    Button openKey2FileECBC;
    @FXML
    ProgressIndicator CipherProgressIndicator;

    //HMAC tab
    File originalFileAES_HMACTab;
    File originalFileHMAC_HMACTab;
    File keyFileHMAC_HMACTab;

    @FXML
    TextField originalFileAESPath_HMACTab;
    @FXML
    Button openOriginalFileAESPath_HMACTab;
    @FXML
    TextField originalFileHMACPath_HMACTab;
    @FXML
    Button openOriginalFileHMACPath_HMACTab;
    @FXML
    Button openKeyFileHMAC_HMACTab;
    @FXML
    TextField keyTextFieldHMAC_HMACTab;
    @FXML
    Button checkHMACButton_HMACTab;

    //ECBC tab
    File originalFileAES_ECBCTab;
    File originalFileECBC_ECBCTab;
    File keyFileECBC_ECBCTab;
    File key2FileECBC_ECBCTab;

    @FXML
    TextField originalFileAESPath_ECBCTab;
    @FXML
    Button openOriginalFileAESPath_ECBCTab;
    @FXML
    TextField originalFileECBCPath_ECBCTab;
    @FXML
    Button openOriginalFileECBCPath_ECBCTab;
    @FXML
    Button openKeyFileECBC_ECBCTab;
    @FXML
    TextField keyTextFieldECBC_ECBCTab;
    @FXML
    Button openKey2FileECBC_ECBCTab;
    @FXML
    TextField key2TextFieldECBC_ECBCTab;
    @FXML
    Button checkECBCButton_ECBCTab;

    private AES_CTREncryptor mAESEncryptor;
    private boolean canChangeOriginalFile = true;
    private final int MAX_FILE_TO_SHOW_SIZE = 5000;

    private HMACEncryptor mHMACEncryptor;
    private ECBCEncryptor mECBCEncryptor;

    @FXML
    public void initialize() {
        mAESEncryptor = new AES_CTREncryptor(CipherProgressIndicator);
        mHMACEncryptor = new HMACEncryptor();
        mECBCEncryptor = new ECBCEncryptor();

        fileChooser = new FileChooser();
        try {
            fileChooser.setInitialDirectory(new File(MainApp.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()).getParentFile());
        } catch (URISyntaxException ex) {
            showExceptionToUser(ex, "Exception in initialize(). fileChooser.setInitialDirectory failed.");
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }

        //AES-CTR tab
        createOriginalFileAES.setOnAction((event) -> {
            File f = createNewFile("Сохраните новый исходный файл");
            if (f != null) {
                originalFileAES = f;
                updateFileInfo(originalFilePathAES, originalFileTextAreaAES, f);
            }
        });

        openOriginalFileAES.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFileAES = f;
                updateFileInfo(originalFilePathAES, originalFileTextAreaAES, f);
                clearKey();
            }
        });

        saveOriginalFileAES.setOnAction((event) -> {
            if (canChangeOriginalFile) {
                saveFile(originalFileAES, originalFileTextAreaAES.getText().getBytes(StandardCharsets.UTF_8));
                updateFileInfo(originalFilePathAES, originalFileTextAreaAES, originalFileAES);
            }
        });

        saveAsOriginalFileAES.setOnAction((event) -> {
            if (canChangeOriginalFile) {
                byte[] bytesToSave;
                if (!originalFileTextAreaAES.getText().isEmpty()) {
                    bytesToSave = originalFileTextAreaAES.getText().getBytes(StandardCharsets.UTF_8);
                } else {
                    bytesToSave = "".getBytes(StandardCharsets.UTF_8);
                }
                saveAsFile(bytesToSave, "Сохраните новый исходный файл");
            } else {
                saveAsFile(originalFileAES, "Сохраните новый исходный файл");
            }
            updateFileInfo(originalFilePathAES, originalFileTextAreaAES, originalFileAES);
        });

        createResultFileAES.setOnAction((event) -> {
            File f = createNewFile("Сохраните новый файл результата");
            if (f != null) {
                resultFileAES = f;
                updateFileInfo(resultFilePathAES, resultFileTextAreaAES, f);
            }
        });

        openResultFileAES.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                resultFileAES = f;
                updateFileInfo(resultFilePathAES, resultFileTextAreaAES, f);

                clearKey();
            }
        });

        saveAsResultFileAES.setOnAction((event) -> {
            saveAsFile(resultFileAES, "Сохраните новый файл результата");
        });

        openKeyFileAES.setOnAction((event) -> {
            keyFileAES = openFile();
            if (keyFileAES != null) {
                keyTextFieldAES.setText(keyFileAES.getAbsolutePath());
                keyTextFieldAES.setEditable(false);
            }
        });

        keyTextFieldAES.setOnMouseClicked((event) -> {
            if (!keyTextFieldAES.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) {
                    clearKey();
                }
            }
        });

        encryptButtonAES.setOnAction((event) -> {
            encrypt();
            Nonce.getInstance().IncNonce();
        });

        decryptButtonAES.setOnAction((event) -> {
            decrypt();
        });

        CreateECBCCheckBox.setOnAction((event) -> {
            key2TextFieldECBC.setDisable(!CreateECBCCheckBox.isSelected());
            openKey2FileECBC.setDisable(!CreateECBCCheckBox.isSelected());
        });

        openKey2FileECBC.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                key2FileECBC = f;
                key2TextFieldECBC.setText(f.getPath());
            }
        });

        //HMAC tab
        openOriginalFileAESPath_HMACTab.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFileAES_HMACTab = f;
                originalFileAESPath_HMACTab.setText(f.getPath());
            }
        });

        openOriginalFileHMACPath_HMACTab.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFileHMAC_HMACTab = f;
                originalFileHMACPath_HMACTab.setText(f.getPath());
            }
        });

        openKeyFileHMAC_HMACTab.setOnAction((event) -> {
            keyFileHMAC_HMACTab = openFile();
            if (keyFileHMAC_HMACTab != null) {
                keyTextFieldHMAC_HMACTab.setText(keyFileHMAC_HMACTab.getAbsolutePath());
                keyTextFieldHMAC_HMACTab.setEditable(false);
            }
        });

        keyTextFieldHMAC_HMACTab.setOnMouseClicked((event) -> {
            if (!keyTextFieldHMAC_HMACTab.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) {
                    keyTextFieldHMAC_HMACTab.clear();
                    keyTextFieldHMAC_HMACTab.setEditable(true);
                    keyFileHMAC_HMACTab = null;
                }
            }
        });

        checkHMACButton_HMACTab.setOnAction((event) -> {
            checkHMAC();
        });

        //ECBC tab
        openOriginalFileAESPath_ECBCTab.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFileAES_ECBCTab = f;
                originalFileAESPath_ECBCTab.setText(f.getPath());
            }
        });

        openOriginalFileECBCPath_ECBCTab.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFileECBC_ECBCTab = f;
                originalFileECBCPath_ECBCTab.setText(f.getPath());
            }
        });

        openKeyFileECBC_ECBCTab.setOnAction((event) -> {
            keyFileECBC_ECBCTab = openFile();
            if (keyFileECBC_ECBCTab != null) {
                keyTextFieldECBC_ECBCTab.setText(keyFileECBC_ECBCTab.getAbsolutePath());
                keyTextFieldECBC_ECBCTab.setEditable(false);
            }
        });

        keyTextFieldECBC_ECBCTab.setOnMouseClicked((event) -> {
            if (!keyTextFieldECBC_ECBCTab.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) {
                    keyTextFieldECBC_ECBCTab.clear();
                    keyTextFieldECBC_ECBCTab.setEditable(true);
                    keyFileECBC_ECBCTab = null;
                }
            }
        });

        openKey2FileECBC_ECBCTab.setOnAction((event) -> {
            key2FileECBC_ECBCTab = openFile();
            if (key2FileECBC_ECBCTab != null) {
                key2TextFieldECBC_ECBCTab.setText(key2FileECBC_ECBCTab.getAbsolutePath());
                key2TextFieldECBC_ECBCTab.setEditable(false);
            }
        });

        key2TextFieldECBC_ECBCTab.setOnMouseClicked((event) -> {
            if (!key2TextFieldECBC_ECBCTab.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) {
                    key2TextFieldECBC_ECBCTab.clear();
                    key2TextFieldECBC_ECBCTab.setEditable(true);
                    key2FileECBC_ECBCTab = null;
                }
            }
        });

        checkECBCButton_ECBCTab.setOnAction((event) -> {
            checkECBC();
        });
    }

    @FXML
    private File createNewFile(String dialogTitle) {
        fileChooser.setTitle(dialogTitle);
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {
            try {
                file.createNewFile();
            } catch (IOException ex) {
                showExceptionToUser(ex, "Exception in createNewFile");
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return file;
    }

    @FXML
    private File openFile() {
        File file = fileChooser.showOpenDialog(stage);
        return file;
    }

    public void setMainApp(MainApp mainApp) {
        this.mainApp = mainApp;
    }

    private void saveFile(File file, byte[] fileBytes) {
        if (file != null && fileBytes != null) {
            try {
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(fileBytes);
                fos.close();
            } catch (IOException ex) {
                showExceptionToUser(ex, "Exception in saveFile");
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private File saveAsFile(byte[] fileBytes, String dialogTitle) {
        fileChooser.setTitle(dialogTitle);
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {
            saveFile(file, fileBytes);
        }
        return file;
    }

    private File saveAsFile(File fileToSave, String dialogTitle) {
        fileChooser.setTitle(dialogTitle);
        File newFile = fileChooser.showSaveDialog(stage);
        if (newFile != null) {
            try {
                Files.copy(fileToSave.toPath(), newFile.toPath());
            } catch (IOException ex) {
                showExceptionToUser(ex, "Exception in saveAsFile");
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return newFile;
    }

    private void updateFileInfo(TextField pathTextField, TextArea contentTextArea, File file) {
        if (file != null) {
            try {
                pathTextField.setText(file.getCanonicalPath());

                if (file.length() < MAX_FILE_TO_SHOW_SIZE) {
                    canChangeOriginalFile = true;
                    saveOriginalFileAES.setDisable(false);
                    originalFileTextAreaAES.setEditable(true);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ex) {
                        showExceptionToUser(ex, "Exception in updateFileInfo");
                    }
                    String content = new String(Files.readAllBytes(file.toPath()));
                    contentTextArea.setText(content);
                } else {
                    canChangeOriginalFile = false;
                    saveOriginalFileAES.setDisable(true);
                    originalFileTextAreaAES.setEditable(false);
                    contentTextArea.setText("Файл слишком большой для отображения.");
                }

            } catch (IOException ex) {
                showExceptionToUser(ex, "Exception in updateFileInfo");
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            contentTextArea.setText("");
        }
    }

    private byte[] readBytesFromFile(File file, int bytesToRead) {
        try {
            return CommonTools.readBytesFromFile(file, 0, bytesToRead);
        } catch (IOException ex) {
            showExceptionToUser(ex, "Exception in readBytesFromFile");
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private void encrypt() {
        if (originalFileAES != null && resultFileAES != null && getKey(keyTextFieldAES, keyFileAES).length != 0) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Результирующий файл будет перезаписан!");
            alert.setHeaderText("Внимание, это перезапишет результирующий файл " + resultFileAES.getPath());

            Optional<ButtonType> result = alert.showAndWait();
            if (result.get() == ButtonType.OK) {

                Task AESTask = mAESEncryptor.encrypt(originalFileAES, resultFileAES, getKey(keyTextFieldAES, keyFileAES));
                AESTask.setOnSucceeded(value -> {
                    updateFileInfo(resultFilePathAES, resultFileTextAreaAES, resultFileAES);

                    if (CreateHMACCheckBox.isSelected()) {
                        File hmacFile = createNewFile("Создайте или выберите файл для сохранения HMAC");
                        Task HMACTask = mHMACEncryptor.getHMAC(resultFileAES, hmacFile, getKey(keyTextFieldAES, keyFileAES));
                        HMACTask.setOnSucceeded(event -> {
                            Alert alertHMACDone = new Alert(Alert.AlertType.INFORMATION);
                            alertHMACDone.setTitle("HMAC файл создан");
                            alertHMACDone.setHeaderText("HMAC файл создан, путь файла: " + hmacFile.getPath());
                            alertHMACDone.show();
                        });
                        HMACTask.run();
                    }

                    if (CreateECBCCheckBox.isSelected()) {
                        File ecbcFile = createNewFile("Создайте или выберите файл для сохранения ECBC");
                        Task ECBCTasc = mECBCEncryptor.getECBC(resultFileAES, ecbcFile, getKey(keyTextFieldAES, keyFileAES), getKey(key2TextFieldECBC, key2FileECBC));
                        ECBCTasc.setOnSucceeded(event -> {
                            Alert alertECBCDone = new Alert(Alert.AlertType.INFORMATION);
                            alertECBCDone.setTitle("ECBC файл создан");
                            alertECBCDone.setHeaderText("ECBC файл создан, путь файла: " + ecbcFile.getPath());
                            alertECBCDone.show();
                        });
                        ECBCTasc.run();
                    }
                });
                Thread AESThread = new Thread(AESTask);
                AESThread.start();
            }
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (originalFileAES == null) {
                alert.setTitle("Вы не выбрали исходный файл");
                alert.setHeaderText("Пожалуйста, создайте или выберите исходный файл(1).");
            } else if (resultFileAES == null) {
                alert.setTitle("Вы не выбрали файл результата ");
                alert.setHeaderText("Пожалуйста, создайте или выберите файл результата шифрования(2).");
            } else if (getKey(keyTextFieldAES, keyFileAES).length == 0) {
                alert.setTitle("Вы не ввели ключ");
                alert.setHeaderText("Пожалуйста, введите ключ или выберите файл с ключем.");
            }
            alert.showAndWait();
        }
    }

    private void decrypt() {
        if (originalFileAES != null && resultFileAES != null && getKey(keyTextFieldAES, keyFileAES).length != 0) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Оригинальный файл будет перезаписан!");
            alert.setHeaderText("Внимание, это перезапишет исходный файл " + originalFileAES.getPath());

            Optional<ButtonType> result = alert.showAndWait();
            if (result.get() == ButtonType.OK) {
                mAESEncryptor.decrypt(resultFileAES, originalFileAES, getKey(keyTextFieldAES, keyFileAES));
                updateFileInfo(originalFilePathAES, originalFileTextAreaAES, originalFileAES);
            }
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (originalFileAES == null) {
                alert.setTitle("Вы не выбрали исходный файл");
                alert.setHeaderText("Пожалуйста, создайте или выберите исходный файл.");
            } else if (resultFileAES == null) {
                alert.setTitle("Вы не выбрали файл результата");
                alert.setHeaderText("Пожалуйста, создайте или выберите файл результата расшифрования.");
            } else if (getKey(keyTextFieldAES, keyFileAES).length == 0) {
                alert.setTitle("Вы не ввели ключ");
                alert.setHeaderText("Пожалуйста, введите ключ или выберите файл с ключем.");
            }
            alert.showAndWait();
        }
    }

    private void checkHMAC() {
        if (originalFileAES_HMACTab != null && originalFileHMAC_HMACTab != null && getKey(keyTextFieldHMAC_HMACTab, keyFileHMAC_HMACTab).length != 0) {
            try {
                File tempHMAC = new File(originalFileHMAC_HMACTab.getAbsolutePath() + "_temp");
                tempHMAC.createNewFile();

                Task HMACTask = mHMACEncryptor.getHMAC(originalFileAES_HMACTab, tempHMAC, getKey(keyTextFieldHMAC_HMACTab, keyFileHMAC_HMACTab));
                HMACTask.setOnSucceeded(value -> {
                    boolean eq = compareFiles(originalFileHMAC_HMACTab, tempHMAC);
                    Alert alert = new Alert(AlertType.INFORMATION);
                    if (eq) {
                        alert.setTitle("Проверка HMAC пройдена");
                        alert.setHeaderText("Проверка HMAC пройдена");
                    } else {
                        alert.setAlertType(AlertType.WARNING);
                        alert.setTitle("Проверка HMAC НЕ пройдена!");
                        alert.setHeaderText("Проверка HMAC НЕ пройдена!");
                    }
                    alert.showAndWait();
                    tempHMAC.delete();
                });
                Thread HMACThread = new Thread(HMACTask);
                HMACThread.start();

            } catch (IOException ex) {
                showExceptionToUser(ex, "checkHMAC()");
            }
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (originalFileAES_HMACTab == null) {
                alert.setTitle("Вы не выбрали исходный зашифрованный AES файл");
                alert.setHeaderText("Пожалуйста, выберите исходный зашифрованный AES файл.");
            } else if (originalFileHMAC_HMACTab == null) {
                alert.setTitle("Вы не выбрали файл HMAC");
                alert.setHeaderText("Пожалуйста, выберите файл HMAC.");
            } else if (getKey(keyTextFieldHMAC_HMACTab, keyFileHMAC_HMACTab).length == 0) {
                alert.setTitle("Вы не выбрали или не ввели ключ HMAC");
                alert.setHeaderText("Пожалуйста, выберите или введите ключ HMAC.");
            }
            alert.showAndWait();
        }
    }

    private void checkECBC() {
        Alert alert = new Alert(AlertType.WARNING);
        if (originalFileAES_ECBCTab == null) {
            alert.setTitle("Вы не выбрали исходный зашифрованный AES файл");
            alert.setHeaderText("Пожалуйста, выберите исходный зашифрованный AES файл.");
            alert.showAndWait();
        } else if (originalFileECBC_ECBCTab == null) {
            alert.setTitle("Вы не выбрали файл ECBC");
            alert.setHeaderText("Пожалуйста, выберите файл ECBC.");
            alert.showAndWait();
        } else if (getKey(keyTextFieldECBC_ECBCTab, keyFileECBC_ECBCTab).length == 0) {
            alert.setTitle("Вы не выбрали или не ввели ключ ECBC");
            alert.setHeaderText("Пожалуйста, выберите или введите ключ ECBC.");
            alert.showAndWait();
        } else if (getKey(key2TextFieldECBC_ECBCTab, key2FileECBC_ECBCTab).length == 0) {
            alert.setTitle("Вы не выбрали или не ввели дополнительный ключ ECBC");
            alert.setHeaderText("Пожалуйста, выберите или введите дополнительный ключ ECBC.");
            alert.showAndWait();
        } else {
            try {
                File tempECBC = new File(originalFileECBC_ECBCTab.getAbsolutePath() + "_temp");
                tempECBC.createNewFile();

                Task ECBCTask = mECBCEncryptor.getECBC(originalFileAES_ECBCTab, tempECBC,
                        getKey(keyTextFieldECBC_ECBCTab, keyFileECBC_ECBCTab),
                        getKey(key2TextFieldECBC_ECBCTab, key2FileECBC_ECBCTab));

                ECBCTask.setOnSucceeded(value -> {
                    boolean eq = compareFiles(originalFileECBC_ECBCTab, tempECBC);
                    Alert alert2 = new Alert(AlertType.INFORMATION);
                    if (eq) {
                        alert2.setTitle("Проверка ECBC пройдена");
                        alert2.setHeaderText("Проверка ECBC пройдена");
                    } else {
                        alert2.setAlertType(AlertType.WARNING);
                        alert2.setTitle("Проверка ECBC НЕ пройдена!");
                        alert2.setHeaderText("Проверка ECBC НЕ пройдена!");
                    }
                    alert2.showAndWait();
                    tempECBC.delete();
                });
                Thread ECBCThread = new Thread(ECBCTask);
                ECBCThread.start();
                
            } catch (IOException ex) {
                showExceptionToUser(ex, "checkECBC()");
            }
        }     
    };

    private void clearKey() {
        keyTextFieldAES.clear();
        keyTextFieldAES.setEditable(true);
        keyFileAES = null;
    }

    private byte[] getKey(TextField keyTextField, File keyFile) {
        if (keyTextField.isEditable()) {
            return keyTextField.getText().getBytes(StandardCharsets.UTF_8);
        } else {
            return readBytesFromFile(keyFile, 128);
        }
    }

    public static boolean compareFiles(File A, File B) {
        if (A != null && B != null) {
            if (A.length() == B.length()) {
                boolean result = true;
                try (FileInputStream finA = new FileInputStream(A); FileInputStream finB = new FileInputStream(B);) {

                    int iA = -1, iB = -1;
                    while ((iA = finA.read()) != -1 && (iB = finB.read()) != -1) {
                        if (iA != iB) {
                            result = false;
                            break;
                        }
                    }
                    return result;
                } catch (IOException ex) {
                    showExceptionToUser(ex, "compareFiles(File A, File B)");
                }
            }
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            alert.setTitle("Выберите два файла для сравнения");
            alert.setHeaderText("Выберите два файла для сравнения!");
            alert.showAndWait();
        }
        return false;
    }

    public static void showExceptionToUser(Throwable e, String message) {
        Alert errorAlert = new Alert(Alert.AlertType.ERROR);
        errorAlert.setTitle("Exception!");
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        errorAlert.setContentText(message + "\n" + sw.toString());
        errorAlert.showAndWait();
    }

}
