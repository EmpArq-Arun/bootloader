#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QBuffer>
#include <QDateTime>
#include <QFileInfo>

#include "crypto.h"
#include "utils.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    readKeyFromFile = false;
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_keyGenerateButton_clicked()
{

    //Open the key to a file
    QString keyFileName = ui->KeyFileBox->currentText();
    if(keyFileName.isEmpty()) {
        QMessageBox::warning(this, tr("Bootloader Creator"), tr("Please enter input file name"));
        return;
    }

    QFile keyFile(keyFileName);
    QByteArray newKey;

    if(readKeyFromFile) {
        //Do nothing, generate must be disabled here
        return;
    }
    else {
        //open file as write-only
        if(!keyFile.open(QFile::WriteOnly | QFile::Truncate)) {
            QMessageBox::warning(this, tr("Bootloader Creator"),
                tr("Cannot write to file %1:\n%2.").arg(keyFileName, keyFile.errorString()));
            return;
        }

        //Generate new key and write to the file
        newKey = Crypto::random(Crypto::KEY_LEN);
        //Display it to the key slot
        ui->keyEdit->setText(Utils::toHex(newKey));

        //Write to the file
        QDataStream stream(&keyFile);
        stream.setByteOrder(QDataStream::LittleEndian);
        stream.writeRawData(newKey.data(), newKey.size());
        keyFile.close();
    }
}

void MainWindow::on_keySelectButton_clicked()
{
    //Custom file dialog
    QFileDialog dialog(this);

    dialog.setWindowTitle("Select File");
    dialog.setFileMode(QFileDialog::AnyFile);       //Existing or new file
    dialog.setAcceptMode(QFileDialog::AcceptOpen);  //No overwrite warnings
    dialog.setNameFilter("Binary Files (*.bin);;All Files (*)");

    if(dialog.exec() != QFileDialog::Accepted)
        return;

    QString fileName =  dialog.selectedFiles().constFirst();
    QFileInfo fileInfo(fileName);

    readKeyFromFile = fileInfo.exists() && fileInfo.size() > 0;

    if(readKeyFromFile)
    {
        QFile keyFile(fileName);
        QByteArray newKey;
        //Open file as readonly
        if(!keyFile.open(QFile::ReadOnly)) {
            QMessageBox::warning(this, tr("Bootloader Creator"),
                tr("Cannot read from file %1:\n%2.").arg(fileName, keyFile.errorString()));
            return;
        }
//        QDataStream stream(&keyFile);
//        stream.setByteOrder(QDataStream::LittleEndian);
//        stream.readRawData(newKey.data(), Crypto::KEY_LEN);

         newKey = keyFile.readAll();
        //Display it to the key slot
        ui->keyEdit->setText(Utils::toHex(newKey));

        //Disable generate button
        ui->keyGenerateButton->setEnabled(false);
    }
    else
    {
        ui->keyGenerateButton->setEnabled(true);
    }

    //Set the data on the key filenslot
    ui->KeyFileBox->setCurrentText(QDir::toNativeSeparators(fileName));
}

void MainWindow::on_inputFileButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("Select input file"), "",
        tr("Binary Files (*.bin);;All Files (*)"));
    if(fileName.isEmpty()) return;

    ui->inputFileBox->setCurrentText(QDir::toNativeSeparators(fileName));
}

void MainWindow::on_outputFileButton_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        tr("Select output file"), "",
        tr("Binary Files (*.bin);;All Files (*)"));
    if(fileName.isEmpty()) return;

    ui->outputFileBox->setCurrentText(QDir::toNativeSeparators(fileName));
}

static void addToComboBox(QComboBox& box, const QString& item) {
    int p = box.findText(item, Qt::MatchExactly);
    if(p != 0) {
        box.removeItem(p);
        box.insertItem(0, item);
        box.setCurrentText(item);
    }
}

static const int PAGE_SIZE = 1024;

static int32_t generate(uint32_t productId, uint32_t appVersion, uint32_t protocolVersion, const QByteArray& key, QFile& inputFile, QFile& outputFile) {
    QByteArray iv = Crypto::random(Crypto::IV_LEN);

    //Read from input file to a buffer
    QByteArray input = inputFile.readAll();

    //Pad it to the PAGE_SIZE or 1024 bytes
    if(input.size() % PAGE_SIZE != 0) {
        int pad = PAGE_SIZE - (input.size() % PAGE_SIZE);
        for(int i = 0; i < pad; ++i) input.append('\0');
    }

    //Encrypt the data using key and iv
    QByteArray enc = Crypto::encrypt(input, key, iv);

    //Write a header data to output file stream
    QDataStream stream(&outputFile);
    stream.setByteOrder(QDataStream::LittleEndian);

    stream << protocolVersion;
    stream << productId;
    stream << appVersion;
    stream << (uint32_t)((input.size() / PAGE_SIZE));
    stream.writeRawData(iv.data(), iv.size());
    stream << Utils::crc32(input);

    //write actual encrypted data to the output stream
    stream.writeRawData(enc.data(), enc.size());

    return enc.size();
}

void MainWindow::on_createButton_clicked()
{
    QByteArray key;
    try {
        key = Utils::fromHex(ui->keyEdit->text());
        if(key.size() != Crypto::KEY_LEN) throw "Wrong length";
    }
    catch(char const* msg) {
        (void)msg;
        QMessageBox::warning(this, tr("Bootloader Creator"), tr("The key must be 16 bytes in hex format"));
        return;
    }

    bool ok;
    uint32_t productId = 0;
    if(!ui->productIdEdit->text().isEmpty()) {
        productId = ui->productIdEdit->text().toUInt(&ok, 16);
        if(!ok) {
            QMessageBox::warning(this, tr("Bootloader Creator"), tr("Product ID must be an uint32 in hex format"));
            return;
        }
    }

    uint32_t appVersion = 0;
    if(!ui->appVersionEdit->text().isEmpty()) {
        appVersion = ui->appVersionEdit->text().toUInt(&ok, 16);
        if(!ok) {
            QMessageBox::warning(this, tr("Bootloader Creator"), tr("App version must be an uint32 in hex format"));
            return;
        }
    }

    QString inputName = ui->inputFileBox->currentText();
    if(inputName.isEmpty()) {
        QMessageBox::warning(this, tr("Bootloader Creator"), tr("Please enter input file name"));
        return;
    }
    QString outputName = ui->outputFileBox->currentText();
    if(outputName.isEmpty()) {
        QMessageBox::warning(this, tr("Bootloader Creator"), tr("Please enter output file name"));
        return;
    }

    QFile inputFile(inputName);
    if(!inputFile.open(QFile::ReadOnly)) {
        QMessageBox::warning(this, tr("Bootloader Creator"),
            tr("Cannot read from file %1:\n%2.").arg(inputName, inputFile.errorString()));
        return;
    }

    QFile outputFile(outputName);
    if(!outputFile.open(QFile::WriteOnly | QFile::Truncate)) {
        QMessageBox::warning(this, tr("Bootloader Creator"),
            tr("Cannot write to file %1:\n%2.").arg(outputName, outputFile.errorString()));
        return;
    }

    addToComboBox(*ui->inputFileBox, inputName);
    addToComboBox(*ui->outputFileBox, outputName);

    try {
        encryptedDataSize = generate(productId, appVersion, 1, key, inputFile, outputFile);

        inputFile.close();
        outputFile.close();

        QMessageBox::information(this, tr("Bootloader Creator"), "File created successfully");
    }
    catch(char const* msg) {
        QMessageBox::critical(this, tr("Bootloader Creator"), tr(msg));
        return;
    }
}

void MainWindow::on_actionAbout_triggered()
{
    QMessageBox::about(this, tr("Bootloader Creator"), tr("An creator of input files for the 'Bootloader Control'. Developed by Anatoli Klassen. Public domain."));
}

void MainWindow::on_actionAboutQt_triggered()
{
    QMessageBox::aboutQt(this, tr("Bootloader Creator"));
}

void MainWindow::on_decryptFileButton_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        tr("Select output file"), "",
        tr("Binary Files (*.bin);;All Files (*)"));
    if(fileName.isEmpty()) return;

    ui->decryptFileBox->setCurrentText(QDir::toNativeSeparators(fileName));
}



static bool recover(uint32_t& productId, uint32_t& appVersion, uint32_t& protocolVersion, QByteArray& iv, const QByteArray& key, QFile& inputFile, QFile& outputFile) {
    bool status = true;

    QByteArray input = inputFile.readAll();
    QDataStream streamIn(&input, QIODevice::ReadOnly);
    streamIn.setByteOrder(QDataStream::ByteOrder::LittleEndian);

    QDataStream streamOut(&outputFile);
    streamOut.setByteOrder(QDataStream::LittleEndian);

    uint32_t byteCount;
    uint32_t crc;

    streamIn >> protocolVersion;
    streamIn >> productId;
    streamIn >> appVersion;
    streamIn >> byteCount;
    streamIn.readRawData(iv.data(), iv.size());
    streamIn >> crc;
    byteCount = byteCount * PAGE_SIZE;

    // Allocate buffer for encrypted data based on the received size
    QByteArray encData(byteCount, 0);

    streamIn.readRawData(encData.data(), encData.size());

    //Decrypt the encrypted data
    QByteArray dencryptData = Crypto::decrypt(encData, key, iv);

    //Write to the output file
    streamOut.writeRawData(dencryptData.data(), dencryptData.size());

    //Pad it to the PAGE_SIZE or 1024 bytes
    uint32_t decryptedSize = (uint32_t)dencryptData.size();
    if(decryptedSize % PAGE_SIZE != 0) {
        int pad = PAGE_SIZE - (dencryptData.size() % PAGE_SIZE);
        for(int i = 0; i < pad; ++i) dencryptData.append('\0');
    }

    //Match CRC
    uint32_t crc_now = Utils::crc32(dencryptData);
    if(crc_now != crc)
        status = false;

    return status;
}

void MainWindow::on_decryptButton_clicked()
{
    QByteArray key;
    try {
        key = Utils::fromHex(ui->keyEdit->text());
        if(key.size() != Crypto::KEY_LEN) throw "Wrong length";
    }
    catch(char const* msg) {
        (void)msg;
        QMessageBox::warning(this, tr("Bootloader Creator"), tr("The key must be 16 bytes in hex format"));
        return;
    }

    QString inputName = ui->outputFileBox->currentText();
    if(inputName.isEmpty()) {
        QMessageBox::warning(this, tr("Bootloader Creator"), tr("Please enter input file name"));
        return;
    }
    QString outputName = ui->decryptFileBox->currentText();
    if(outputName.isEmpty()) {
        QMessageBox::warning(this, tr("Bootloader Creator"), tr("Please enter output file name"));
        return;
    }

    QFile inputFile(inputName);
    if(!inputFile.open(QFile::ReadOnly)) {
        QMessageBox::warning(this, tr("Bootloader Creator"),
            tr("Cannot read from file %1:\n%2.").arg(inputName, inputFile.errorString()));
        return;
    }

    QFile outputFile(outputName);
    if(!outputFile.open(QFile::WriteOnly | QFile::Truncate)) {
        QMessageBox::warning(this, tr("Bootloader Creator"),
            tr("Cannot write to file %1:\n%2.").arg(outputName, outputFile.errorString()));
        return;
    }

    addToComboBox(*ui->outputFileBox, inputName);
    addToComboBox(*ui->decryptFileBox, outputName);

    uint32_t productId, appVersion, protocolVersion;
    QByteArray iv(16, Qt::Uninitialized);

    bool status = recover(productId, appVersion, protocolVersion, iv, key, inputFile, outputFile);

    inputFile.close();
    outputFile.close();

    //Update the display
    ui->productIdEdit->setText(QString::number(productId, 16));
    ui->appVersionEdit->setText(QString::number(appVersion, 16));

    QString msg;
    if(status) {
        msg = tr("Decrypted ") + /*inputName + */ tr(" to file ") + outputName;
    }
    else {
        msg = tr("Decrypted(CRC mismatch) ") + /*inputName + */ tr(" to file ") + outputName;
    }
        QMessageBox::information(this, "Decryption Info", msg);
}
