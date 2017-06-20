#include "viewer.h"
#include "ui_viewer.h"

Viewer::Viewer(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Viewer)
{
    ui->setupUi(this);

    /*Slots and stuff*/
    connect(ui->RefreshButton, SIGNAL(clicked(bool)), this, SLOT(loadFile()));

    connect(ui->KButton, SIGNAL(clicked(bool)), this, SLOT(updateOutput()));
    connect(ui->PButton, SIGNAL(clicked(bool)), this, SLOT(updateOutput()));

    connect(ui->DButton, SIGNAL(clicked(bool)), this, SLOT(updateOutput()));
    connect(ui->IButton, SIGNAL(clicked(bool)), this, SLOT(updateOutput()));
    connect(ui->WButton, SIGNAL(clicked(bool)), this, SLOT(updateOutput()));
    connect(ui->EButton, SIGNAL(clicked(bool)), this, SLOT(updateOutput()));

    connect(ui->EarlySlider, SIGNAL(sliderReleased()), this, SLOT(updateEarly()));
    connect(ui->LateSlider, SIGNAL(sliderReleased()), this, SLOT(updateLate()));
    connect(ui->EarlySlider, SIGNAL(sliderMoved(int)), this, SLOT(updateEarly()));
    connect(ui->LateSlider, SIGNAL(sliderMoved(int)), this, SLOT(updateLate()));

    connect(ui->CloseButton, SIGNAL(clicked(bool)), this, SLOT(close()));

    connect(ui->SearchButton, SIGNAL(clicked(bool)), this, SLOT(updateOutput()));

    this->loadFile();
    this->ctrl_pressed = false;
}

Viewer::~Viewer()
{
    for (int i=0; i<this->messages.size(); i++) {
        delete(this->messages.at(i));
    }
    delete ui;
}

void Viewer::loadFile()
{
    // Clear the log so far
    for (int i=0; i<this->messages.size(); i++) {
        delete(this->messages.at(i));
    }
    this->messages.clear();

    // Get file from the ui
    QString path = ui->Path->text();
    if (path.isEmpty()) {
        path = "/var/log/trustbase.log";
    }
    QFile logfile(path);
    if (!logfile.open(QFile::ReadOnly | QFile::Text)) {
        this->early_index = 0;
        this->late_index = 0;
        ui->EarlySlider->setMaximum(0);
        ui->LateSlider->setMaximum(0);
        ui->EarlyLabel->setText("No Log");
        ui->LateLabel->setText("No Log");
        this->updateOutput();
        return;
    }
    QTextStream in(&logfile);
    while (!in.atEnd()) {
        QString line = in.readLine();
        if (line.isEmpty()) {
            continue;
        } else if (line.section(':',4).isEmpty()) {
            // Add it to the previous one
            this->messages.last()->message.append('\n');
            this->messages.last()->message.append(line);
        }
        // Process the hexdump
        if (line.endsWith(":HEX START:")) {
            QString hexdump;
            while (!in.atEnd()) {
                line = in.readLine();
                if (line.endsWith(":HEX END:")) {
                    line.replace("HEX END:", hexdump.prepend("KDBG:\n"));
                    break;
                }
                //Gather the hex dump
                hexdump.append(line.section(':', 3));
                hexdump.append("\n");
            }
        }
        // Add it to our messages structure
        LogMessage* message = new LogMessage(line);
        this->messages.append(message);
    }

    this->early_index = 0;
    this->late_index = this->messages.size() - 1;
    ui->EarlySlider->setMaximum(this->messages.size() - 1);
    ui->LateSlider->setMaximum(this->messages.size() - 1);
    ui->LateSlider->setSliderPosition(late_index);
    ui->EarlyLabel->setText(this->messages[this->early_index]->time.toString(this->dateformat));
    ui->LateLabel->setText(this->messages[this->late_index]->time.toString(this->dateformat));

    ui->SearchGroup->setHidden(true);

    this->updateOutput();
    return;
}

void Viewer::updateOutput() {
    // Clear and reset the browser
    ui->View->clear();
    QString output;
    /* Debug Color = #22EE0E
     * Info Color = #FFFFFF
     * Warning Color = #4090EE
     * Error Color = #F00000
     */
    output.append("<style>.debug{color: #22EE0E;} .info{color: #FFFFFF;} .warning{color: #4090EE;} .error{color:#F00000;} table{border:0px;width:100%;cellspacing:0px;cellpadding:2px;}</style>");
    output.append("<table>");
    for (int i=this->early_index; i<this->late_index; i++) {
        LogMessage* message = this->messages[i];
        // Check if this is part of a log we aren't showing
        if ((message->is_kernel() && !ui->KButton->isChecked()) || (!message->is_kernel() && !ui->PButton->isChecked())){
            continue;
        }
        // Check if this is a level we aren't showing
        if ((message->message_level == LogMessage::LOG_DEBUG && !ui->DButton->isChecked()) ||
            (message->message_level == LogMessage::LOG_INFO && !ui->IButton->isChecked()) ||
            (message->message_level == LogMessage::LOG_WARNING && !ui->WButton->isChecked()) ||
            (message->message_level == LogMessage::LOG_ERROR && !ui->EButton->isChecked())) {
            continue;
        }

        // Show rows with the search stuff lines
        if (ui->SearchGroup->isVisible() && !ui->SearchLine->text().isEmpty()) {
            if (!message->message.contains(ui->SearchLine->text())) {
                continue;
            }
        }

        output.append("<tr>");
        if (ui->PButton->isChecked()) {
            if (ui->KButton->isChecked() && ui->PButton->isChecked()) {
                output.append("<td width=\"50%\">");
            } else {
                output.append("<td width=\"100%\">");
            }
            if (!message->is_kernel()) {
                output.append(message->getHTML());
            }
            output.append("</td>");
        }
        if (ui->KButton->isChecked()) {
            if (ui->KButton->isChecked() && ui->PButton->isChecked()) {
                output.append("<td width=\"50%\">");
            } else {
                output.append("<td width=\"100%\">");
            }
            if (message->is_kernel()) {
                output.append(message->getHTML());
            }
            output.append("</td>");
        }
        output.append("</tr>");
    }
    output.append("</table>");
    ui->View->setHtml(output);
}

void Viewer::updateEarly() {
    this->early_index = ui->EarlySlider->sliderPosition();
    if (this->early_index > this->late_index) {
        this->late_index = this->early_index;
        ui->LateSlider->setSliderPosition(this->late_index);
        ui->LateLabel->setText(this->messages[this->late_index]->time.toString(this->dateformat));
    }
    ui->EarlyLabel->setText(this->messages[this->early_index]->time.toString(this->dateformat));
    this->updateOutput();
}

void Viewer::updateLate() {
    this->late_index = ui->LateSlider->sliderPosition();
    if (this->late_index < this->early_index) {
        this->early_index = this->late_index;
        ui->EarlySlider->setSliderPosition(this->early_index);
        ui->EarlyLabel->setText(this->messages[this->early_index]->time.toString(this->dateformat));
    }
    ui->LateLabel->setText(this->messages[this->late_index]->time.toString(this->dateformat));
    this->updateOutput();
}

void Viewer::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_Control) {
        this->ctrl_pressed = true;
    }
    if (event->key() == Qt::Key_F && this->ctrl_pressed) {
        //Show or hide the finding thing
        ui->SearchGroup->setHidden(ui->SearchGroup->isVisible());
        this->updateOutput();
    }
}

void Viewer::keyReleaseEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_Control) {
        this->ctrl_pressed = false;
    }
}
