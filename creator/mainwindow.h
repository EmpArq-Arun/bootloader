#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_keyGenerateButton_clicked();

    void on_keySelectButton_clicked();

    void on_inputFileButton_clicked();

    void on_outputFileButton_clicked();

    void on_createButton_clicked();

    void on_actionAbout_triggered();

    void on_actionAboutQt_triggered();

    void on_decryptFileButton_clicked();

    void on_decryptButton_clicked();

private:
    Ui::MainWindow *ui;
    bool readKeyFromFile;
    int32_t encryptedDataSize;
};

#endif // MAINWINDOW_H
