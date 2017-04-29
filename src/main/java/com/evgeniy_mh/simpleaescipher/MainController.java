package com.evgeniy_mh.simpleaescipher;

import com.evgeniy_mh.simpleaescipher.AESEngine.AESEncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.Nonce;
import java.io.File;
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
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MainController {

    private Stage stage;
    private FileChooser fileChooser = new FileChooser();
    private MainApp mainApp;

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

    private AESEncryptor mAESEncryptor;
    private boolean canChangeOriginalFile = true;
    private final int MAX_FILE_TO_SHOW_SIZE = 5000;

    public MainController() {
    }

    @FXML
    public void initialize() {
        mAESEncryptor = new AESEncryptor(CipherProgressIndicator);
        
        fileChooser = new FileChooser();
        try {
            fileChooser.setInitialDirectory(new File(MainApp.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()).getParentFile());
        } catch (URISyntaxException ex) {
            showExceptionToUser(ex, "Exception in initialize(). fileChooser.setInitialDirectory failed.");
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }

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

    private byte[] readBytesFromFile(File file) {
        try {
            return Files.readAllBytes(file.toPath());
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
                
                    mAESEncryptor.encrypt(originalFile, resultFile, getKey());                    
                    updateFileInfo(resultFilePath, resultFileTextArea, resultFile);     
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

    private void clearKey() {
        keyTextField.clear();
        keyTextField.setEditable(true);
        keyFile = null;
    }

    private byte[] getKey() {
        if (keyTextField.isEditable()) {
            return keyTextField.getText().getBytes(StandardCharsets.UTF_8);
        } else {
            return readBytesFromFile(keyFile);
        }
    }
    
    public static void showExceptionToUser(Throwable e,String message) {  
        Alert errorAlert = new Alert(Alert.AlertType.ERROR);
        errorAlert.setTitle("Exception!");    
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        errorAlert.setContentText(message+"\n"+sw.toString());
        errorAlert.showAndWait();
    }

}
