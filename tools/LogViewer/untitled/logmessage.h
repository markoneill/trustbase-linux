#ifndef LOGMESSAGE_H
#define LOGMESSAGE_H

#include <QFile>
#include <QString>
#include <QDateTime>

class LogMessage
{
public:
    LogMessage(QString input_string);
    QString getHTML(void);
    bool is_kernel(void);

    typedef enum level {LOG_DEBUG=0, LOG_INFO=1, LOG_WARNING=2, LOG_ERROR=3} level;
    LogMessage::level message_level; // The messages level
    QDateTime time; // The time when the message happened

    QString message; // The actual recorded message
    bool kernel_message; // If the message originated from the kernel

};

#endif // LOGMESSAGE_H
