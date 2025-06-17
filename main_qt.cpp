// main_qt.cpp (GUI)
#include <QApplication>
#include "ui/qt_gui.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    QtROPWeaver window;
    window.setWindowTitle("ROPWeaver - GUI Mode");
    window.resize(900, 600);
    window.show();

    return app.exec();
}
