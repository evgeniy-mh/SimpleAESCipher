package com.evgeniy_mh.simpleaescipher;

import com.evgeniy_mh.simpleaescipher.AESEngine.AESEncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.Nonce;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MainController {

    private Stage stage;

    private FileChooser fileChooser = new FileChooser();
    private MainApp mainApp;

    private File originalFile;
    private byte[] originalFileBytes;
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
    private byte[] resultFileBytes;
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
    private byte[] keyBytes;

    @FXML
    TextField keyTextField;
    @FXML
    Button openKeyFile;
    @FXML
    Button encryptButton;
    @FXML
    Button decryptButton;

    AESEncryptor mAESEncryptor;
    private boolean canChangeOriginalFile = true;
    
    private final int MAX_FILE_TO_OPEN_SIZE=5000;

    public MainController() {
    }

    @FXML
    public void initialize() {
        mAESEncryptor = new AESEncryptor();
        fileChooser = new FileChooser();
        try {
            fileChooser.setInitialDirectory(new File(MainApp.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()).getParentFile());
        } catch (URISyntaxException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        createOriginalFile.setOnAction((event) -> {
            File f = createNewFile("Сохраните новый исходный файл");
            if (f != null) {
                originalFile = f;
                originalFileBytes = readBytesFromFile(f);
                updateFileInfo(originalFilePath, originalFileTextArea, f);
            }

        });

        openOriginalFile.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFile = f;
                originalFileBytes = readBytesFromFile(f);
                updateFileInfo(originalFilePath, originalFileTextArea, f);

                clearKey();
            }

        });

        saveOriginalFile.setOnAction((event) -> {
            if (canChangeOriginalFile) {
                originalFileBytes = originalFileTextArea.getText().getBytes(StandardCharsets.UTF_8);
                saveFile(originalFile, originalFileBytes);
                updateFileInfo(originalFilePath, originalFileTextArea, originalFile);
            }

        });

        saveAsOriginalFile.setOnAction((event) -> {
            byte[] bytesToSave;
            if(canChangeOriginalFile){
                if (!originalFileTextArea.getText().isEmpty()) {
                    bytesToSave = originalFileTextArea.getText().getBytes(StandardCharsets.UTF_8);
                } else {
                    bytesToSave = "".getBytes(StandardCharsets.UTF_8);
                }
            }else bytesToSave=originalFileBytes;
            
            
            saveAsfile(bytesToSave, "Сохраните новый исходный файл");
            updateFileInfo(originalFilePath, originalFileTextArea, originalFile);

        });

        createResultFile.setOnAction((event) -> {
            File f = createNewFile("Сохраните новый файл результата");
            if (f != null) {
                resultFile = f;
                resultFileBytes = readBytesFromFile(f);
                updateFileInfo(resultFilePath, resultFileTextArea, f);
            }

        });

        openResultFile.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                resultFile = f;
                resultFileBytes = readBytesFromFile(f);
                updateFileInfo(resultFilePath, resultFileTextArea, f);

                clearKey();
            }

        });

        saveAsResultFile.setOnAction((event) -> {
            saveAsfile(resultFileBytes, "Сохраните новый файл результата");
        });

        openKeyFile.setOnAction((event) -> {
            keyFile = openFile();
            if (keyFile != null) {
                keyTextField.setText(keyFile.getAbsolutePath());
                keyTextField.setEditable(false);

                keyBytes = readBytesFromFile(keyFile);

            }
        });

        keyTextField.setOnMouseClicked((event) -> {
            if (!keyTextField.isEditable()) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Использовать поле ввода ключа?");
                alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) 
                    clearKey();
                
            }
        });

        encryptButton.setOnAction((event) -> {
            encrypt();
            Nonce.getInstance().IncNonce();
        });

        decryptButton.setOnAction((event) -> {
            decrypt();
        });

    }

    @FXML
    private File createNewFile(String dialogTitle) {
        fileChooser.setTitle(dialogTitle);
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {
            try {
                FileWriter fw;////переделать
                fw = new FileWriter(file);
                fw.write("");
                fw.close();

            } catch (IOException ex) {
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
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private File saveAsfile(byte[] fileBytes, String dialogTitle) {
        fileChooser.setTitle(dialogTitle);
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {
            saveFile(file, fileBytes);

        }
        return file;
    }

    private void updateFileInfo(TextField pathTextField, TextArea contentTextArea, File file) {
        if (file != null) {
            try {
                pathTextField.setText(file.getCanonicalPath());

                if (file.length() < MAX_FILE_TO_OPEN_SIZE) {
                    canChangeOriginalFile = true;
                    saveOriginalFile.setDisable(false);
                    originalFileTextArea.setEditable(true);
                    String content = new String(Files.readAllBytes(file.toPath()));
                    contentTextArea.setText(content);
                } else {
                    canChangeOriginalFile = false;
                    saveOriginalFile.setDisable(true);
                    originalFileTextArea.setEditable(false);
                    contentTextArea.setText("Файл слишком большой для отображения.");
                }

            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else contentTextArea.setText("");
    }

    private byte[] readBytesFromFile(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private void encrypt() {
        if (getKey().length != 0 && originalFileBytes != null) {
            resultFileBytes = mAESEncryptor.encrypt(originalFileBytes, getKey());
            if (resultFile != null) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Результирующий файл будет перезаписан!");
                alert.setHeaderText("Внимание, это перезапишет результирующий файл.");

                Optional<ButtonType> result = alert.showAndWait();
                if (result.get() == ButtonType.OK) saveFile(resultFile, resultFileBytes);
            } else {
                resultFile = saveAsfile(resultFileBytes, "Сохраните новый файл результата");
            }
            updateFileInfo(resultFilePath, resultFileTextArea, resultFile);
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (getKey().length == 0) {
                alert.setTitle("Вы не ввели ключ");
                alert.setHeaderText("Пожалуйста, введите ключ или выберите файл с ключем.");
            }
            if (originalFileBytes == null) {
                alert.setTitle("Вы не выбрали исходный файл");
                alert.setHeaderText("Пожалуйста, создайте или выберите исходный файл.");
            }
            alert.showAndWait();
        }
    }

    private void decrypt() {
        if (getKey().length != 0 && resultFileBytes != null) {
            originalFileBytes = mAESEncryptor.decrypt(resultFileBytes, getKey());
            if (originalFile != null) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Оригинальный файл будет перезаписан!");
                alert.setHeaderText("Внимание, это перезапишет оригинальный файл.");

                Optional<ButtonType> result = alert.showAndWait();                
                if(result.get() == ButtonType.OK) saveFile(originalFile, originalFileBytes);
            } else {
                originalFile = saveAsfile(originalFileBytes, "Сохраните новый исходный файл");
            }
            updateFileInfo(originalFilePath, originalFileTextArea, originalFile);
        } else {
            Alert alert = new Alert(AlertType.WARNING);
            if (getKey().length == 0) {
                alert.setTitle("Вы не ввели ключ");
                alert.setHeaderText("Пожалуйста, введите ключ или выберите файл с ключем.");
            }
            if (resultFileBytes == null) {
                alert.setTitle("Вы не выбрали файл результата");
                alert.setHeaderText("Пожалуйста, создайте или выберите файл результата.");
            }
            alert.showAndWait();
        }
    }

    private void clearKey() {
        keyTextField.clear();
        keyTextField.setEditable(true);
        keyBytes = null;
        keyFile = null;
    }

    private byte[] getKey() {
        if (keyTextField.isEditable()) {
            return keyTextField.getText().getBytes(StandardCharsets.UTF_8);
        } else {
            keyBytes = readBytesFromFile(keyFile);
            return keyBytes;
        }        
    }

}
