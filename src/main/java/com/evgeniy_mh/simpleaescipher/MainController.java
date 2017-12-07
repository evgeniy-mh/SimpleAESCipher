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
    private File originalFile;
    @FXML
    TextField originalFilePath;
    @FXML
    TextArea originalFileTextArea;
    @FXML
    Button createOriginalFile;
    @FXML
    Button openOriginalFile;
    @FXML
    Button saveOriginalFile;
    @FXML
    Button saveAsOriginalFile;

    private File resultFile;
    @FXML
    TextField resultFilePath;
    @FXML
    TextArea resultFileTextArea;
    @FXML
    Button createResultFile;
    @FXML
    Button openResultFile;
    @FXML
    Button saveAsResultFile;

    private File keyFile;

    @FXML
    TextField keyTextField;
    @FXML
    Button openKeyFile;
    @FXML
    Button encryptButton;
    @FXML
    Button decryptButton;

    @FXML
    ProgressIndicator CipherProgressIndicator;

    //HMAC tab
    private File originalHMACFile;
    private File resultHMACFile;
    private File keyFileHMAC;
    @FXML
    TextField originalFilePathHMAC;
    @FXML
    Button openOriginalFileHMAC;
    @FXML
    Button openKeyFileHMAC;
    @FXML
    TextField keyTextFieldHMAC;
    @FXML
    Button getHMACButton;
    @FXML
    TextField resultFilePathHMAC;
    @FXML
    Button openResultFileHMAC;
    private File compareFileHMAC1, compareFileHMAC2;
    @FXML
    TextField compareFilePathHMAC1;
    @FXML
    Button openCompareFileHMAC1;
    @FXML
    TextField compareFilePathHMAC2;
    @FXML
    Button openCompareFileHMAC2;
    @FXML
    Button compareFilesHMAC;

    //ECBC tab
    private File originalECBCFile;
    private File resultECBCFile;
    private File keyFileECBC;
    @FXML
    TextField originalFilePathECBC;
    @FXML
    Button openOriginalFileECBC;
    @FXML
    Button openKeyFileECBC;
    @FXML
    TextField keyTextFieldECBC;
    @FXML
    Button getECBCButton;
    @FXML
    TextField resultFilePathECBC;
    @FXML
    Button openResultFileECBC;
    private File compareFileECBC1, compareFileECBC2;
    @FXML
    TextField compareFilePathECBC1;
    @FXML
    Button openCompareFileECBC1;
    @FXML
    TextField compareFilePathECBC2;
    @FXML
    Button openCompareFileECBC2;
    @FXML
    Button compareFilesECBC;

    @FXML
    CheckBox CreateHMACCheckBox;

    private AES_CTREncryptor mAESEncryptor;
    private boolean canChangeOriginalFile = true;
    private final int MAX_FILE_TO_SHOW_SIZE = 5000;

    private HMACEncryptor mHMACEncryptor;
    private ECBCEncryptor mECBCEncryptor;

    public MainController() {
    }

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
        createOriginalFile.setOnAction((event) -> {
            File f = createNewFile("Сохраните новый исходный файл");
            if (f != null) {
                originalFile = f;
                updateFileInfo(originalFilePath, originalFileTextArea, f);
            }
        });

        openOriginalFile.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFile = f;
                updateFileInfo(originalFilePath, originalFileTextArea, f);
                clearKey();
            }
        });

        saveOriginalFile.setOnAction((event) -> {
            if (canChangeOriginalFile) {
                saveFile(originalFile, originalFileTextArea.getText().getBytes(StandardCharsets.UTF_8));
                updateFileInfo(originalFilePath, originalFileTextArea, originalFile);
            }
        });

        saveAsOriginalFile.setOnAction((event) -> {
            if (canChangeOriginalFile) {
                byte[] bytesToSave;
                if (!originalFileTextArea.getText().isEmpty()) {
                    bytesToSave = originalFileTextArea.getText().getBytes(StandardCharsets.UTF_8);
                } else {
                    bytesToSave = "".getBytes(StandardCharsets.UTF_8);
                }
                saveAsFile(bytesToSave, "Сохраните новый исходный файл");
            } else {
                saveAsFile(originalFile, "Сохраните новый исходный файл");
            }
            updateFileInfo(originalFilePath, originalFileTextArea, originalFile);
        });

        createResultFile.setOnAction((event) -> {
            File f = createNewFile("Сохраните новый файл результата");
            if (f != null) {
                resultFile = f;
                updateFileInfo(resultFilePath, resultFileTextArea, f);
            }
        });

        openResultFile.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                resultFile = f;
                updateFileInfo(resultFilePath, resultFileTextArea, f);

                clearKey();
            }
        });

        saveAsResultFile.setOnAction((event) -> {
            saveAsFile(resultFile, "Сохраните новый файл результата");
        });

        openKeyFile.setOnAction((event) -> {
            keyFile = openFile();
            if (keyFile != null) {
                keyTextField.setText(keyFile.getAbsolutePath());
                keyTextField.setEditable(false);
            }
        });

        keyTextField.setOnMouseClicked((event) -> {
            if (!keyTextField.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) {
                    clearKey();
                }
            }
        });

        encryptButton.setOnAction((event) -> {
            encrypt();
            Nonce.getInstance().IncNonce();
        });

        decryptButton.setOnAction((event) -> {
            decrypt();
        });

        //HMAC tab
        openOriginalFileHMAC.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalHMACFile = f;
                originalFilePathHMAC.setText(f.getPath());
            }
        });

        openKeyFileHMAC.setOnAction((event) -> {
            keyFileHMAC = openFile();
            if (keyFileHMAC != null) {
                keyTextFieldHMAC.setText(keyFileHMAC.getAbsolutePath());
                keyTextFieldHMAC.setEditable(false);
            }
        });

        keyTextFieldHMAC.setOnMouseClicked((event) -> {
            if (!keyTextFieldHMAC.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) {
                    keyTextFieldHMAC.clear();
                    keyTextFieldHMAC.setEditable(true);
                    keyFileHMAC = null;
                }
            }
        });

        /*getHMACButton.setOnMouseClicked((event) -> {
            try {
                if (originalHMACFile != null && resultHMACFile != null) {
                    mHMACEncryptor.getHMAC(originalHMACFile, resultHMACFile, getKeyHMAC());
                } else {
                    Alert alert = new Alert(AlertType.WARNING);
                    if (originalHMACFile == null) {
                        alert.setTitle("Вы не выбрали исходный файл");
                        alert.setHeaderText("Пожалуйста, выберите исходный файл.");
                    } else if (resultHMACFile == null) {
                        alert.setTitle("Вы не выбрали файл результата");
                        alert.setHeaderText("Пожалуйста, создайте или выберите файл чтобы сохранить результат HMAC.");
                    }
                    alert.showAndWait();
                }
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        });*/
        openResultFileHMAC.setOnMouseClicked((event) -> {
            File f = openFile();
            if (f != null) {
                resultHMACFile = f;
                resultFilePathHMAC.setText(f.getPath());
            }
        });

        openCompareFileHMAC1.setOnMouseClicked((event) -> {
            File f = openFile();
            if (f != null) {
                compareFileHMAC1 = f;
                compareFilePathHMAC1.setText(f.getPath());
            }
        });

        openCompareFileHMAC2.setOnMouseClicked((event) -> {
            File f = openFile();
            if (f != null) {
                compareFileHMAC2 = f;
                compareFilePathHMAC2.setText(f.getPath());
            }
        });

        compareFilesHMAC.setOnMouseClicked((event) -> {
            boolean eq = compareFiles(compareFileHMAC1, compareFileHMAC2);

            Alert alert = new Alert(AlertType.INFORMATION);
            if (eq) {
                alert.setTitle("Файлы одинаковы");
                alert.setHeaderText("Файлы одинаковы");
            } else {
                alert.setTitle("Файлы различны");
                alert.setHeaderText("Файлы различны");
            }
            alert.showAndWait();
        });

        //ECBC tab
        openOriginalFileECBC.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalECBCFile = f;
                originalFilePathECBC.setText(f.getPath());
            }
        });

        openKeyFileECBC.setOnAction((event) -> {
            keyFileECBC = openFile();
            if (keyFileECBC != null) {
                keyTextFieldECBC.setText(keyFileECBC.getAbsolutePath());
                keyTextFieldECBC.setEditable(false);
            }
        });

        keyTextFieldECBC.setOnMouseClicked((event) -> {
            if (!keyTextFieldECBC.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) {
                    keyTextFieldECBC.clear();
                    keyTextFieldECBC.setEditable(true);
                    keyFileECBC = null;
                }
            }
        });

        getECBCButton.setOnMouseClicked((event) -> {
            try {
                if (originalECBCFile != null && resultECBCFile != null) {
                    mECBCEncryptor.getECBC(originalECBCFile, resultECBCFile, getKeyECBC());
                } else {
                    Alert alert = new Alert(AlertType.WARNING);
                    if (originalECBCFile == null) {
                        alert.setTitle("Вы не выбрали исходный файл");
                        alert.setHeaderText("Пожалуйста, выберите исходный файл.");
                    } else if (resultECBCFile == null) {
                        alert.setTitle("Вы не выбрали файл результата");
                        alert.setHeaderText("Пожалуйста, создайте или выберите файл чтобы сохранить результат ECBC.");
                    }
                    alert.showAndWait();
                }
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        });

        openResultFileECBC.setOnMouseClicked((event) -> {
            File f = openFile();
            if (f != null) {
                resultECBCFile = f;
                resultFilePathECBC.setText(f.getPath());
            }
        });

        openCompareFileECBC1.setOnMouseClicked((event) -> {
            File f = openFile();
            if (f != null) {
                compareFileECBC1 = f;
                compareFilePathECBC1.setText(f.getPath());
            }
        });

        openCompareFileECBC2.setOnMouseClicked((event) -> {
            File f = openFile();
            if (f != null) {
                compareFileECBC2 = f;
                compareFilePathECBC2.setText(f.getPath());
            }
        });

        compareFilesECBC.setOnMouseClicked((event) -> {
            boolean eq = compareFiles(compareFileECBC1, compareFileECBC2);

            Alert alert = new Alert(AlertType.INFORMATION);
            if (eq) {
                alert.setTitle("Файлы одинаковы");
                alert.setHeaderText("Файлы одинаковы");
            } else {
                alert.setTitle("Файлы различны");
                alert.setHeaderText("Файлы различны");
            }
            alert.showAndWait();
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
                    saveOriginalFile.setDisable(false);
                    originalFileTextArea.setEditable(true);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ex) {
                        showExceptionToUser(ex, "Exception in updateFileInfo");
                    }
                    String content = new String(Files.readAllBytes(file.toPath()));
                    contentTextArea.setText(content);
                } else {
                    canChangeOriginalFile = false;
                    saveOriginalFile.setDisable(true);
                    originalFileTextArea.setEditable(false);
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
        if (originalFile != null && resultFile != null && getKey().length != 0) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Результирующий файл будет перезаписан!");
            alert.setHeaderText("Внимание, это перезапишет результирующий файл(2).");

            Optional<ButtonType> result = alert.showAndWait();
            if (result.get() == ButtonType.OK) {

                Task AESTask = mAESEncryptor.encrypt(originalFile, resultFile, getKey());
                AESTask.setOnSucceeded(value -> {
                    updateFileInfo(resultFilePath, resultFileTextArea, resultFile);

                    if (CreateHMACCheckBox.isSelected()) {
                        File hmacFile = createNewFile("Создайте файл для сохранения HMAC");
                        Task HMACTask = mHMACEncryptor.getHMAC(resultFile, hmacFile, getKey());
                        HMACTask.setOnSucceeded(value2 -> {
                            Alert alertHMACDone = new Alert(Alert.AlertType.INFORMATION);
                            alertHMACDone.setTitle("HMAC файл создан");
                            alertHMACDone.setHeaderText("HMAC файл создан, путь файла: " + hmacFile.getPath());
                            alertHMACDone.show();
                        });
                        HMACTask.run();
                    }
                });
                Thread AESThread = new Thread(AESTask);
                AESThread.start();
            }
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (originalFile == null) {
                alert.setTitle("Вы не выбрали исходный файл");
                alert.setHeaderText("Пожалуйста, создайте или выберите исходный файл(1).");
            } else if (resultFile == null) {
                alert.setTitle("Вы не выбрали файл результата ");
                alert.setHeaderText("Пожалуйста, создайте или выберите файл результата шифрования(2).");
            } else if (getKey().length == 0) {
                alert.setTitle("Вы не ввели ключ");
                alert.setHeaderText("Пожалуйста, введите ключ или выберите файл с ключем.");
            }
            alert.showAndWait();
        }
    }

    private void decrypt() {
        if (originalFile != null && resultFile != null && getKey().length != 0) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Оригинальный файл будет перезаписан!");
            alert.setHeaderText("Внимание, это перезапишет исходный файл(1).");

            Optional<ButtonType> result = alert.showAndWait();
            if (result.get() == ButtonType.OK) {
                mAESEncryptor.decrypt(resultFile, originalFile, getKey());
                updateFileInfo(originalFilePath, originalFileTextArea, originalFile);
            }
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (originalFile == null) {
                alert.setTitle("Вы не выбрали исходный файл");
                alert.setHeaderText("Пожалуйста, создайте или выберите исходный файл.");
            } else if (resultFile == null) {
                alert.setTitle("Вы не выбрали файл результата");
                alert.setHeaderText("Пожалуйста, создайте или выберите файл результата расшифрования.");
            } else if (getKey().length == 0) {
                alert.setTitle("Вы не ввели ключ");
                alert.setHeaderText("Пожалуйста, введите ключ или выберите файл с ключем.");
            }
            alert.showAndWait();
        }
    }

    /*private void getHMAC(File in, File out, byte[] key) {
        try {
            /*if (originalHMACFile != null && resultHMACFile != null) {
            mHMACEncryptor.getHMAC(originalHMACFile, resultHMACFile, getKeyHMAC());
            } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (originalHMACFile == null) {
            alert.setTitle("Вы не выбрали исходный файл");
            alert.setHeaderText("Пожалуйста, выберите исходный файл.");
            } else if (resultHMACFile == null) {
            alert.setTitle("Вы не выбрали файл результата");
            alert.setHeaderText("Пожалуйста, создайте или выберите файл чтобы сохранить результат HMAC.");
            }
            alert.showAndWait();
            }
            mHMACEncryptor.getHMAC(in, out, key);
        } catch (IOException ex) {
            showExceptionToUser(ex, "getHMAC(File in, File out, byte[] key)");
        }
    }*/
    private void clearKey() {
        keyTextField.clear();
        keyTextField.setEditable(true);
        keyFile = null;
    }

    private byte[] getKey() {
        if (keyTextField.isEditable()) {
            return keyTextField.getText().getBytes(StandardCharsets.UTF_8);
        } else {
            return readBytesFromFile(keyFile, 128);
        }
    }

    private byte[] getKeyHMAC() {
        if (keyTextFieldHMAC.isEditable()) {
            return keyTextFieldHMAC.getText().getBytes(StandardCharsets.UTF_8);
        } else {
            return readBytesFromFile(keyFileHMAC, 128);
        }
    }

    private byte[] getKeyECBC() {
        if (keyTextFieldECBC.isEditable()) {
            return keyTextFieldECBC.getText().getBytes(StandardCharsets.UTF_8);
        } else {
            return readBytesFromFile(keyFileECBC, 128);
        }
    }

    /*private byte[] getKey(TextField field, File keyInputFile){
        if (keyTextFieldECBC.isEditable()) {
            return keyTextFieldECBC.getText().getBytes(StandardCharsets.UTF_8);
        } else {
            return readBytesFromFile(keyFileECBC, 128);
        }
    }*/
    public boolean compareFiles(File A, File B) {
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
