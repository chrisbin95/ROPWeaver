// qt_gui.h
#ifndef QT_GUI_H
#define QT_GUI_H

#include <QWidget>

class QtGUI : public QWidget {
    Q_OBJECT

public:
    QtGUI(QWidget* parent = nullptr);
    void setupUI();
};

#endif // QT_GUI_H