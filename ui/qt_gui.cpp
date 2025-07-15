// qt_gui.cpp
#include "qt_gui.h"
#include <QVBoxLayout>
#include <QPushButton>
#include <QMessageBox>

QtGUI::QtGUI(QWidget* parent) : QWidget(parent) {
    setupUI();
}

void QtGUI::setupUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    
    runButton = new QPushButton("Run Analysis", this);
    layout->addWidget(runButton);

    setLayout(layout);

    connect(runButton, &QPushButton::clicked, this, &QtGUI::onRunAnalysisClicked);
}

void QtGUI::onRunAnalysisClicked() {
    QMessageBox::information(this, "Info", "Analysis started!");
}
