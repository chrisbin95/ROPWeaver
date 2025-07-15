// qt_gui.h
#ifndef QT_GUI_H
#define QT_GUI_H

#include <QWidget>

class QPushButton;

class QtGUI : public QWidget {
    Q_OBJECT
public:
    explicit QtGUI(QWidget* parent = nullptr);

private slots:
    void onRunAnalysisClicked();

private:
    void setupUI();
    QPushButton* runButton;
};

#endif // QT_GUI_H
