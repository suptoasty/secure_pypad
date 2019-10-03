#!/usr/bin/env python3
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QButtonGroup, QLabel, QMenuBar, QProgressBar, QFileDialog, QTextEdit, QVBoxLayout, QGridLayout, QMenu, QAction, QMessageBox, QLineEdit, QDialog, QDialogButtonBox, QInputDialog
from PyQt5.QtGui import QIcon, QTextOption
from PyQt5.Qt import QCryptographicHash as crypto
import sys
import types
import io

class password_dialog(QDialog):
	layout: QVBoxLayout = None
	password: QLineEdit = None
	confirm: QPushButton = None
	cancel: QPushButton = None

	def __init__(self):
		QMessageBox.__init__(self)

		self.layout = QVBoxLayout()
		self.password = QLineEdit()
		self.confirm = QPushButton()
		self.cancel = QPushButton()

		self.password.setText("")
		self.confirm.setText("Confirm")
		self.cancel.setText("Cancel")

		self.layout.addWidget(self.password)
		self.layout.addWidget(self.confirm)
		self.layout.addWidget(self.cancel)
		self.setLayout(self.layout)

		self.password.setEchoMode(QLineEdit.Password)

		self.setModal(True)
		

class app(QApplication):
	menu: QMenuBar = None
	window: QWidget = None
	layout: QGridLayout = None
	text_edit: QTextEdit = None
	file_chooser: QFileDialog = None
	password_dialog: password_dialog = None

	word_wrap: bool = False

	def getWindow(self) -> QWidget:
		return self.window

	def getMenu(self) -> QMenuBar:
		return self.menu

	def getLayout(self) -> QGridLayout:
		return self.layout

	def getTextEdit(self) -> QTextEdit:
		return self.text_edit

	def getFile(self):
		return self.file

	def openFile(self):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		file_name, _ = QFileDialog.getOpenFileName(self.window,"QFileDialog.getOpenFileName()", "","All Files (*);;Text Files (*.txt)", options=options)
		if(file_name):
			print(file_name)
			file = open(file_name, 'rb')
			self.text_edit.setText(file.read().decode("utf-8"))
			file.close()

	def saveFile(self):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		file_name, _ = QFileDialog.getSaveFileName(self.window,"QFileDialog.getSaveFileName()","","All Files (*);;Text Files (*.txt)", options=options)
		if(file_name):
			print(file_name)
			file = open(file_name, 'wb')
			file.write(bytes(self.text_edit.toPlainText(), "utf-8"))
			file.close()
	
	def saveFileEncrpted(self):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		file_name, _ = QFileDialog.getSaveFileName(self.window,"QFileDialog.getSaveFileName()","","All Files (*);;Text Files (*.txt)", options=options)
		if(file_name):
			# self.password_dialog.show()
			self.password_dialog.exec()
			print(file_name)
			file = open(file_name, 'wb')
			file.write(bytes(self.text_edit.toPlainText(), "utf-8"))
			file.close()
	
	def toggleWordWrap(self):
		self.word_wrap != self.word_wrap
		if(self.word_wrap):
			# self.text_edit.setLineWrapMode(self, QTextOption.WrapAnywhere)
			self.text_edit.setLineWrapColumnOrWidth(1)
		else:
			self.text_edit.setLineWrapColumnOrWidth(0)

	def __init__(self, args, title=None):
		QApplication.__init__(self, args)
		print("Arguments-> ", args)

		# initialize members
		self.window = QWidget()
		self.layout = QGridLayout()
		self.menu = QMenuBar()
		self.password_dialog = QLineEdit()
		self.text_edit = QTextEdit()
		self.file_chooser = QFileDialog()
		
		self.window.setWindowTitle(title)
		self.password_dialog = password_dialog()

		# add menu
		self.layout.addWidget(self.menu, 0, 0)
		actionFile = self.menu.addMenu("&File")

		newAction = QAction(QIcon(), "&New", self)
		newAction.setShortcut("Ctrl+N")
		newAction.triggered.connect(self.text_edit.clear)
		actionFile.addAction(newAction)

		openAction = QAction(QIcon(), "&Open", self)
		openAction.setShortcut("Ctrl+O")
		openAction.triggered.connect(self.openFile)
		actionFile.addAction(openAction)

		saveAction = QAction(QIcon(), "&Save", self)
		saveAction.setShortcut("Ctrl+S")
		saveAction.triggered.connect(self.saveFile)
		actionFile.addAction(saveAction)

		saveAction = QAction(QIcon(), "&Save Encrypted", self)
		saveAction.setShortcut("Ctrl+Alt+S")
		saveAction.triggered.connect(self.saveFileEncrpted)
		actionFile.addAction(saveAction)

		actionFile.addSeparator()

		exitAction = QAction(QIcon(), "&Exit", self)
		exitAction.setShortcut("Ctrl+Q")
		exitAction.triggered.connect(self.quit)
		actionFile.addAction(exitAction)

		actionFormat = self.menu.addMenu("&Format")

		wordWrapAction = QAction(QIcon(), "&WordWrap", self)
		wordWrapAction.setShortcut("Ctrl+W")
		wordWrapAction.triggered.connect(self.toggleWordWrap)
		actionFormat.addAction(wordWrapAction)

		self.layout.addWidget(self.text_edit, 1, 0)

		self.window.setLayout(self.layout)
		self.window.show()
