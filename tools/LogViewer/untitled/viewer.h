#ifndef VIEWER_H
#define VIEWER_H

#include <QWidget>
#include <QFile>
#include <QString>
#include <QList>
#include <QTextStream>
#include <QDebug>
#include "logmessage.h"

namespace Ui {
class Viewer;
}

class Viewer : public QWidget
{
    Q_OBJECT

public:
    explicit Viewer(QWidget *parent = 0);
    ~Viewer();

public slots:
    void updateOutput(void);
    void loadFile(void);
    void updateEarly(void);
    void updateLate(void);

private:
    Ui::Viewer *ui;
    QList<LogMessage*> messages;

    int early_index;
    int late_index;

    const QString dateformat = "ddd h:mm:ss";

};

#endif // VIEWER_H
