from PyQt5 import QtCore, QtGui, QtWidgets
from datetime import datetime
from PyQt5.QtWidgets import QLineEdit, QLabel, QMessageBox, QDialog, QVBoxLayout, QWidget, QScrollArea
from scapy.layers.inet import IP, ICMP
from uuid import uuid4
from main import *

# you should replace these with your local dirver and server name
driver_name = '{SQL Server}'
server_name = 'MSI\SQLEXPRESS'
stopping = False
thread = None
thread2 = None



class Ui_Form(object):

    def setupUi(self, Form):
        Form.setStyleSheet("background-color: rgba(228, 241, 254, 1);")
        Form.setObjectName("Sniffer")
        Form.resize(810, 555)
        self.tableWidget = QtWidgets.QTableWidget(Form)
        self.tableWidget.setGeometry(QtCore.QRect(60, 80, 601, 401))
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(6)
        self.tableWidget.itemClicked.connect(self.test)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(5, item)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        ip_src_label = QLabel(Form)
        ip_src_label.setText('IP src:')
        ip_src_line = QLineEdit(Form)
        ip_src_line.move(60, 20)
        ip_src_line.resize(100, 32)
        ip_src_label.move(20, 20)

        ip_dst_label = QLabel(Form)
        ip_dst_label.setText('IP dst:')
        ip_dst_line = QLineEdit(Form)
        ip_dst_line.move(220, 20)
        ip_dst_line.resize(100, 32)
        ip_dst_label.move(180, 20)

        protocol_label = QLabel(Form)
        protocol_label.setText('Protocol: $')
        protocol_line = QLineEdit(Form)
        protocol_line.move(385, 20)
        protocol_line.resize(100, 32)
        protocol_label.move(340, 20)

        count_button = QtWidgets.QPushButton(Form)
        count_button.setText("Packets Count")
        count_button.setGeometry(QtCore.QRect(680, 140, 81, 21))
        count_button.move(700, 101)
        count_button.setStyleSheet("QPushButton {\n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(107, 185, 240, 1), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "border-radius:10px;\n"
                                   "color: rgba(255,255,255,255);\n"
                                   "}\n"
                                   "QPushButton:pressed {\n"
                                   "   \n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(228, 241, 254, 255), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "    border-style: inset;\n"
                                   "}\n"
                                   "")
        count_button.clicked.connect(lambda: ui.msg_count())

        traceroute_label = QLabel(Form)
        traceroute_label.setText('Traceroute IP')
        traceroute_line = QLineEdit(Form)
        traceroute_line.move(690, 250)
        traceroute_line.resize(100, 32)
        traceroute_label.move(705, 221)

        traceroute_button = QtWidgets.QPushButton(Form)
        traceroute_button.setText("Traceroute")
        traceroute_button.setGeometry(QtCore.QRect(680, 140, 71, 21))
        traceroute_button.move(700, 301)
        traceroute_button.setStyleSheet("QPushButton {\n"
                                        "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                        "stop:0 rgba(107, 185, 240, 1), stop:0.960227 rgba(176, 241, 143, 255), "
                                        "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                        "border-radius:10px;\n"
                                        "color: rgba(255,255,255,255);\n"
                                        "}\n"
                                        "QPushButton:pressed {\n"
                                        "   \n"
                                        "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                        "stop:0 rgba(228, 241, 254, 255), stop:0.960227 rgba(176, 241, 143, 255), "
                                        "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                        "    border-style: inset;\n"
                                        "}\n"
                                        "")
        traceroute_button.clicked.connect(lambda: ui.traceroute_thread(traceroute_line.text()))

        start_button = QtWidgets.QPushButton(Form)
        start_button.setText("Start Sniffing")
        start_button.setGeometry(QtCore.QRect(680, 140, 71, 21))
        start_button.move(700, 401)
        start_button.setStyleSheet("QPushButton {\n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(107, 185, 240, 1), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "border-radius:10px;\n"
                                   "color: rgba(255,255,255,255);\n"
                                   "}\n"
                                   "QPushButton:pressed {\n"
                                   "   \n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(228, 241, 254, 255), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "    border-style: inset;\n"
                                   "}\n"
                                   "")
        start_button.clicked.connect(lambda: ui.loaddata(ip_src_line.text(), ip_dst_line.text(), protocol_line.text()))

        stop_button = QtWidgets.QPushButton(Form)
        stop_button.setText("Stop")
        stop_button.setGeometry(QtCore.QRect(680, 140, 71, 21))
        stop_button.move(700, 451)
        stop_button.setStyleSheet("QPushButton {\n"
                                  "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                  "stop:0 rgba(107, 185, 240, 1), stop:0.960227 rgba(176, 241, 143, 255), "
                                  "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                  "border-radius:10px;\n"
                                  "color: rgba(255,255,255,255);\n"
                                  "}\n"
                                  "QPushButton:pressed {\n"
                                  "   \n"
                                  "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                  "stop:0 rgba(228, 241, 254, 255), stop:0.960227 rgba(176, 241, 143, 255), "
                                  "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                  "    border-style: inset;\n"
                                  "}\n"
                                  "")
        stop_button.clicked.connect(ui.stop)

        clear_button = QtWidgets.QPushButton(Form)
        clear_button.setText("Clear")
        clear_button.setGeometry(QtCore.QRect(680, 140, 71, 21))
        clear_button.move(700, 351)
        clear_button.setStyleSheet("QPushButton {\n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(107, 185, 240, 1), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "border-radius:10px;\n"
                                   "color: rgba(255,255,255,255);\n"
                                   "}\n"
                                   "QPushButton:pressed {\n"
                                   "   \n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(228, 241, 254, 255), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "    border-style: inset;\n"
                                   "}\n"
                                   "")
        clear_button.clicked.connect(ui.clear_data)

        apply_button = QtWidgets.QPushButton(Form)
        apply_button.setGeometry(QtCore.QRect(680, 140, 71, 21))
        apply_button.setText("Apply")
        apply_button.move(700, 20)
        apply_button.setStyleSheet("QPushButton {\n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(107, 185, 240, 1), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "border-radius:10px;\n"
                                   "color: rgba(255,255,255,255);\n"
                                   "}\n"
                                   "QPushButton:pressed {\n"
                                   "   \n"
                                   "background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:0, "
                                   "stop:0 rgba(228, 241, 254, 255), stop:0.960227 rgba(176, 241, 143, 255), "
                                   "stop:0.971591 rgba(198, 245, 175, 255), stop:1 rgba(255, 255, 255, 255));\n "
                                   "    border-style: inset;\n"
                                   "}\n"
                                   "")
        apply_button.clicked.connect(
            lambda: ui.loaddata(ip_src_line.text(), ip_dst_line.text(), protocol_line.text(), True))

    def clear_data(self):
        conn = connect_db(driver_name, server_name)
        cursor = use_table(conn)
        self.tableWidget.setRowCount(0)
        cursor.execute("DELETE FROM PacketCapture;")

    def loaddata(self, ip_src, ip_dst, protocol, apply=False):
        pcapture = None
        conn = connect_db(driver_name, server_name)
        cursor = use_table(conn)
        count = self.tableWidget.rowCount()
        self.tableWidget.setRowCount(count)
        if not apply:
            from threading import Thread
            global stopping
            global thread
            stopping = False
            if (thread is None) or (not thread.is_alive()):
                thread = threading.Thread(target=lambda: self.sniffing(cursor))
                thread.start()

        else:
            # TO DO: check if it's a correct ip address form
            self.stop()
            self.tableWidget.setRowCount(0)
            sqlquery = ''
            if (ip_src != '') & (ip_dst != '') & (protocol != ''):
                if is_ipv4_address(ip_src) and is_ipv4_address(ip_dst):
                    sqlquery = f"SELECT * from PacketCapture WHERE Source='{ip_src}' AND Destination='{ip_dst}' AND " \
                               f"PortName='{protocol}'; "
                else:
                    self.msg_error()
                    return
            elif (ip_src != '') & (ip_dst != '') & (protocol == ''):
                if is_ipv4_address(ip_src) and is_ipv4_address(ip_dst):
                    sqlquery = f"SELECT * from PacketCapture WHERE Source='{ip_src}' AND Destination='{ip_dst}';"
                else:
                    self.msg_error()
                    return
            elif (ip_src != '') & (ip_dst == '') & (protocol == ''):
                if is_ipv4_address(ip_src):
                    sqlquery = f"SELECT * from PacketCapture WHERE Source='{ip_src}';"
                else:
                    self.msg_error()
                    return
            elif (ip_src != '') & (ip_dst == '') & (protocol != ''):
                if is_ipv4_address(ip_src):
                    sqlquery = f"SELECT * from PacketCapture WHERE Source='{ip_src}' AND PortName='{protocol}';"
                else:
                    self.msg_error()
                    return
            elif (ip_src == '') & (ip_dst != '') & (protocol == ''):
                if is_ipv4_address(ip_dst):
                    sqlquery = f"SELECT * from PacketCapture WHERE Destination='{ip_dst}';"
                else:
                    self.msg_error()
                    return
            elif (ip_src == '') & (ip_dst != '') & (protocol != ''):
                if is_ipv4_address(ip_dst):
                    sqlquery = f"SELECT * from PacketCapture WHERE Destination='{ip_dst}' AND PortName='{protocol}';"
                else:
                    self.msg_error()
                    return
            elif (ip_src == '') & (ip_dst == '') & (protocol != ''):
                sqlquery = f"SELECT * from PacketCapture WHERE PortName='{protocol}';"
            else:
                sqlquery = "SELECT * from PacketCapture"

            colonnes = cursor.execute(sqlquery)

            # print("len des colonnes:",len(list(colonnes)))
            for ligne in colonnes:
                count = self.tableWidget.rowCount()
                self.tableWidget.insertRow(count)
                self.tableWidget.setItem(count, 0, QtWidgets.QTableWidgetItem(ligne[0]))
                self.tableWidget.setItem(count, 1, QtWidgets.QTableWidgetItem(ligne[1]))
                self.tableWidget.setItem(count, 2, QtWidgets.QTableWidgetItem(ligne[2]))
                self.tableWidget.setItem(count, 3, QtWidgets.QTableWidgetItem(ligne[3]))
                self.tableWidget.setItem(count, 4, QtWidgets.QTableWidgetItem(ligne[4]))
                self.tableWidget.setItem(count, 5, QtWidgets.QTableWidgetItem(ligne[5]))

    def add_to_database(self, pkt, cursor):
        if 'IP' in pkt:
            packet_uid = str(uuid4())
            count = self.tableWidget.rowCount()
            self.tableWidget.insertRow(count)
            self.tableWidget.setItem(count, 0, QtWidgets.QTableWidgetItem(packet_uid))
            self.tableWidget.setItem(count, 2, QtWidgets.QTableWidgetItem(str(pkt["IP"].src)))
            self.tableWidget.setItem(count, 3, QtWidgets.QTableWidgetItem(str(pkt["IP"].dst)))
            self.tableWidget.setItem(count, 4, QtWidgets.QTableWidgetItem(pkt["IP"].get_field(
                'proto').i2s[
                                                                              pkt.proto]))
            self.tableWidget.setItem(count, 5, QtWidgets.QTableWidgetItem(pkt.summary()))
            self.tableWidget.setItem(count, 1, QtWidgets.QTableWidgetItem(datetime.now().strftime(
                "%d/%m/%Y %H:%M:%S")))

            cursor.execute(
                r"INSERT INTO PacketCapture VALUES('{}', '{}', '{}', '{}', '{}','{}','{}','{}')".format(packet_uid,
                                                                                                        datetime.now().strftime(
                                                                                                  "%d/%m/%Y %H:%M:%S"),
                                                                                                        str(pkt["IP"].src),
                                                                                                        str(pkt["IP"].dst),
                                                                                                        pkt["IP"].get_field(
                                                                                                  'proto').i2s[
                                                                                                  pkt.proto],
                                                                                                        pkt.summary().replace("'",
                                                                                                                    "''"),
                                                                                                        pkt.show(dump=True).replace(
                                                                                                            "'",
                                                                                                            "''"), hexdump(pkt, dump=True).replace(
                                                                                                            "'",
                                                                                                            "''")))
        if 'ARP' in pkt:
            packet_uid = str(uuid4())
            count = self.tableWidget.rowCount()
            self.tableWidget.insertRow(count)
            self.tableWidget.setItem(count, 0, QtWidgets.QTableWidgetItem(packet_uid))
            self.tableWidget.setItem(count, 2, QtWidgets.QTableWidgetItem(str(pkt["Ethernet"].src)))
            self.tableWidget.setItem(count, 3, QtWidgets.QTableWidgetItem(str(pkt["Ethernet"].dst)))
            self.tableWidget.setItem(count, 4, QtWidgets.QTableWidgetItem("arp"))
            self.tableWidget.setItem(count, 5, QtWidgets.QTableWidgetItem(pkt.summary()))
            self.tableWidget.setItem(count, 1, QtWidgets.QTableWidgetItem(datetime.now().strftime(
                "%d/%m/%Y %H:%M:%S")))
            cursor.execute(
                "INSERT INTO PacketCapture VALUES('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(packet_uid,
                                                                                                          datetime.now().strftime(
                                                                                                             "%d/%m"
                                                                                                             "/%Y "
                                                                                                             "%H:%M:%S"),
                                                                                                          str(pkt[
                                                                                                                 "Ethernet"].src),
                                                                                                          str(pkt[
                                                                                                                 "Ethernet"].dst),
                                                                                                         "arp",
                                                                                                          pkt.summary(), pkt.show(dump=True), hexdump(pkt, dump=True)))

    def sniffing(self, cursor):
        return sniff(prn=lambda x: self.add_to_database(x, cursor), stop_filter=self.stop_sniffing)

    def stop_sniffing(self, p):
        global stopping
        return stopping

    def stop(self):
        global stopping
        stopping = True

    def msg_error(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("Error")
        msg.setInformativeText('IP adress is not valid')
        msg.setWindowTitle("Error")
        msg.exec_()

    def msg_count(self):
        conn = connect_db(driver_name, server_name)
        cursor = use_table(conn)
        cursor.execute("SELECT COUNT (*) FROM PacketCapture WHERE PortName='tcp'")
        tcp_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT (*) FROM PacketCapture WHERE PortName='udp'")
        udp_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT (*) FROM PacketCapture WHERE PortName='icmp'")
        icmp_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT (*) FROM PacketCapture WHERE PortName='arp'")
        arp_count = cursor.fetchone()[0]
        msg = QMessageBox()
        msg.setInformativeText(f'TCP = {tcp_count};\n UDP = {udp_count};\n ICMP = {icmp_count};\n ARP = {arp_count}')
        msg.setWindowTitle("Packets Count")
        msg.exec_()

    def traceroute(self, ip_dst):
        ttl = 1
        i = 1
        global thread2
        while 1:
            print('started traceroute')
            p = sr1(IP(dst=ip_dst, ttl=ttl) / ICMP(id=os.getpid()),
                    verbose=0)
            # if time exceeded due to TTL exceeded
            if p[ICMP].type == 11 and p[ICMP].code == 0:
                print(ttl, '->', p.src)
                count = self.tableWidget.rowCount()
                self.tableWidget.insertRow(count)
                self.tableWidget.setItem(count, 3, QtWidgets.QTableWidgetItem(p.src))
                ttl += 1
                i += 1
            elif p[ICMP].type == 0:
                print(ttl, '->', p.src)
                count = self.tableWidget.rowCount()
                self.tableWidget.insertRow(count)
                self.tableWidget.setItem(count, 3, QtWidgets.QTableWidgetItem(p.src))
                thread2.terminate()
                break
            else:
                thread2.terminate()
                break

    def traceroute_thread(self, ip_dst):
        self.stop()
        self.clear_data()
        global thread2
        if (thread2 is None) or (not thread2.is_alive()):
            thread2 = threading.Thread(target=lambda: self.traceroute(ip_dst))
            thread2.start()
            print('started thread')

    def test(self, item):
        print(item.text())
        if item.column() == 0:
            conn = connect_db(driver_name, server_name)
            cursor = use_table(conn)
            cursor.execute("SELECT Show FROM PacketCapture WHERE PacketUID='{}'".format(item.text()))
            dump = cursor.fetchone()[0]
            cursor.execute("SELECT Hexdump FROM PacketCapture WHERE PacketUID='{}'".format(item.text()))
            hexd = cursor.fetchone()[0]
            msg = QMessageBox()
            msg.setStyleSheet("QLabel{min-width: 700px;}")
            msg.setInformativeText(hexd)
            msg.setDetailedText(dump)
            msg.setWindowTitle("Packets Info")
            msg.exec_()

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Sniffing App"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("Form", "ID"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("Form", "Time"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("Form", "Source"))
        item = self.tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("Form", "Destination"))
        item = self.tableWidget.horizontalHeaderItem(4)
        item.setText(_translate("Form", "Protocol"))
        item = self.tableWidget.horizontalHeaderItem(5)
        item.setText(_translate("Form", "Infos"))


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
