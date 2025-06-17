// qt_gui.cpp
#include "qt_gui.h"
#include <QVBoxLayout>
#include <QPushButton>

QtGUI::QtGUI(QWidget* parent) : QWidget(parent) {
    setupUI();
}

void QtGUI::setupUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    QPushButton* button = new QPushButton("Run Analysis", this);
    layout->addWidget(button);
    setLayout(layout);
}