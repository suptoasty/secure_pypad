#!/usr/bin/env python3
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QMenuBar, QProgressBar, QFileDialog, QTextEdit, QVBoxLayout, QGridLayout, QMenu, QAction, QMessageBox
from PyQt5.QtGui import QIcon
import sys
import types
import io

class app(QApplication):
	menu: QMenuBar = None
	window: QWidget = None
	layout: QGridLayout = None
	text_edit: QTextEdit = None
	file_chooser: QFileDialog = None

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
			file = open(file_name, 'r')
			self.text_edit.setText(file.read())
			file.close()

	def saveFile(self):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		file_name, _ = QFileDialog.getSaveFileName(self.window,"QFileDialog.getSaveFileName()","","All Files (*);;Text Files (*.txt)", options=options)
		if(file_name):
			print(file_name)
			file = open(file_name, 'wb')
			file.write(bin(self.text_edit.toPlainText()))
			file.close()

	def __init__(self, args, title=None):
		QApplication.__init__(self, args)
		print("Arguments-> ", args)

		# initialize members
		self.window = QWidget()
		self.layout = QGridLayout()
		self.menu = QMenuBar()
		self.text_edit = QTextEdit()
		self.file_chooser = QFileDialog()

		self.window.setWindowTitle(title)
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

		actionFile.addSeparator()

		exitAction = QAction(QIcon(), "&Exit", self)
		exitAction.setShortcut("Ctrl+Q")
		exitAction.triggered.connect(self.quit)
		actionFile.addAction(exitAction)

		self.layout.addWidget(self.text_edit, 1, 0)

		self.window.setLayout(self.layout)
		self.window.show()
