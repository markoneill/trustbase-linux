#include "logmessage.h"

LogMessage::LogMessage(QString input_string)
{
    QString time_piece = input_string.section(':', 0, 2);
    if (time_piece.at(8) == ' ') {
        time_piece.replace(8,1,'0');
    }
    if (time_piece.at(11) == ' ') {
        time_piece.replace(11,1,'0');
    }
    // Parse the string
    // It should be a time date string followed by a log level (with or without a k in front) then the message

    time = QDateTime::fromString(time_piece, "ddd MMM dd HH:mm:ss yyyy ");

    QString level_piece = input_string.section(':', 3, 3);

    this->kernel_message = false;
    if (QString::compare(level_piece,"KDBG") == 0) {
        this->kernel_message = true;
        this->message_level = LogMessage::LOG_DEBUG;
    } else if (QString::compare(level_piece,"KINF") == 0) {
        this->kernel_message = true;
        this->message_level = LogMessage::LOG_INFO;
    } else if (QString::compare(level_piece,"KWRN") == 0) {
        this->kernel_message = true;
        this->message_level = LogMessage::LOG_WARNING;
    } else if (QString::compare(level_piece,"KERR") == 0) {
        this->kernel_message = true;
        this->message_level = LogMessage::LOG_ERROR;
    } else if (QString::compare(level_piece,"DBG") == 0) {
        this->message_level = LogMessage::LOG_DEBUG;
    } else if (QString::compare(level_piece,"INF") == 0) {
        this->message_level = LogMessage::LOG_INFO;
    } else if (QString::compare(level_piece,"WRN") == 0) {
        this->message_level = LogMessage::LOG_WARNING;
    } else if (QString::compare(level_piece,"ERR") == 0) {
        this->message_level = LogMessage::LOG_ERROR;
    } else {
        // Really shouldn't happen
        this->message_level = LogMessage::LOG_DEBUG;
    }

    this->message = input_string.section(':',4);
}

QString LogMessage::getHTML() {
    QString response = "<p title=\"%1\" class=\"%2\">%3</p>";
    QString msg_class;
    if (this->message_level == LogMessage::LOG_DEBUG) {
        msg_class = "debug";
    } else if (this->message_level == LogMessage::LOG_INFO) {
        msg_class = "info";
    } else if (this->message_level == LogMessage::LOG_WARNING) {
        msg_class = "warning";
    } else if (this->message_level == LogMessage::LOG_ERROR) {
        msg_class = "error";
    }
    return response.arg(this->time.toString("ddd MMM d h:mm:ss yyyy")).arg(msg_class).arg(this->message);
}

bool LogMessage::is_kernel() {
    return this->kernel_message;
}
