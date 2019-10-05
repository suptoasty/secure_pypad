#!/usr/bin/env python3
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QButtonGroup, QLabel, QMenuBar, QProgressBar, QFileDialog, QTextEdit, QVBoxLayout, QGridLayout, QMenu, QAction, QMessageBox, QLineEdit, QDialog, QDialogButtonBox, QInputDialog
from PyQt5.QtGui import QIcon, QTextOption
from PyQt5.Qt import QCryptographicHash, QByteArray
import io
from os import stat, remove
import types
import sys
import json
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class password_dialog(QDialog):
	layout: QVBoxLayout = None
	password: QLineEdit = None
	confirm: QPushButton = None
	cancel: QPushButton = None
	pas: str = ""
	encryption_mode = AES.MODE_CBC

	def getEncryptionMode(self):
		return self.encryption_mode

	def hash_pass(self, pas)-> bytes:
		sha = SHA256.new()
		sha.update(bytes(pas, 'utf-8'))
		return sha.digest()

	def getPassword(self)-> str:
		return self.pas

	def on_confirm(self):
		if(self.password.text() == ""):
			warn: QMessageBox = QMessageBox(parent=self)
			warn.setText("Password Invalid")
			warn.show()
			return
		self.pas = self.hash_pass(self.password.text())

		self.password.setText("")
		self.accept()
		print("Accepted")

	def on_cancel(self):
		self.password.setText("")
		self.reject()
		print("Rejected")

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
		self.confirm.clicked.connect(self.on_confirm)
		self.cancel.clicked.connect(self.on_cancel)


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
		filename, _ = QFileDialog.getOpenFileName(
			self.window, "QFileDialog.getOpenFileName()", "", "All Files (*);;Text Files (*.txt)", options=options)
		open_encrypt = False
		if(filename):
			print(filename)
			file = open(filename, 'rb')
			data = file.read()
			try:
				result = json.loads(data)
				open_encrypt = result["encrypt"]
			except ValueError:
				open_encrypt = False

			if(open_encrypt):
				file.close()
				self.openEncryptedFile(filename)
			else:
				self.text_edit.setText(data.decode('utf-8'))
				file.close()		

	def openFileEncrypted(self, password):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		filename, _ = QFileDialog.getOpenFileName(
			self.window, "QFileDialog.getOpenFileName()", "", "All Files (*);;Text Files (*.txt)", options=options)
		if(filename):
			print(filename)
			self.openEncryptedFile(filename)

	def saveFile(self):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		filename, _ = QFileDialog.getSaveFileName(
			self.window, "QFileDialog.getSaveFileName()", "", "All Files (*);;Text Files (*.txt)", options=options)
		if(filename):
			print(filename)
			file = open(filename, 'wb')
			file.write(bytes(self.text_edit.toPlainText(), "utf-8"))
			file.close()

	def saveFileEncrpted(self):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		filename, _ = QFileDialog.getSaveFileName(
			self.window, "QFileDialog.getSaveFileName()", "", "All Files (*);;Text Files (*.txt)", options=options)
		if(filename):
			# self.password_dialog.show()
			err = self.password_dialog.exec()
			if(err):
				print("write encrpted")
				self.writeEncrptedFile(filename, self.password_dialog.getPassword())
			else:
				print("canceled")
			filename = ""

	def toggleWordWrap(self):
		self.word_wrap != self.word_wrap
		if(self.word_wrap):
			# self.text_edit.setLineWrapMode(self, QTextOption.WrapAnywhere)
			self.text_edit.setLineWrapColumnOrWidth(1)
		else:
			self.text_edit.setLineWrapColumnOrWidth(0)

	def writeEncrptedFile(self, filename, password=None):
		#comment out as hash_pass is being used "foo" will not work
		# if(password is None):
		# 	password = "foo"
		print("Encrpteded: ", filename)

		data = bytes(self.text_edit.toPlainText(), 'utf-8')
		key = password
		cipher = AES.new(key , AES.MODE_CBC)
		ct_bytes = cipher.encrypt(pad(data, AES.block_size))
		iv = b64encode(cipher.iv).decode('utf-8')
		ct = b64encode(ct_bytes).decode('utf-8')
		mode = self.password_dialog.getEncryptionMode()
		result = json.dumps({'iv':iv, 'ciphertext':ct, 'encrypt': True, 'mode': mode})

		file_out = open(filename, "wb")
		file_out.write(bytes(result, 'utf-8'))
		file_out.close()

		mode = 0
		key = None
		data = None
		password = ""
		filename = ""
		iv = None
		ct = None
		result = None

	def openEncryptedFile(self, filename, password=None):
		err = self.password_dialog.exec()
		if(err):
			try:
				file_in = open(filename, 'rb')
				key = self.password_dialog.getPassword()
				# key = pad(bytes(password, 'utf-8'), 16)
				# key = password
				b64 = json.loads(file_in.read())
				iv = b64decode(b64['iv'])
				ct = b64decode(b64['ciphertext'])
				cipher = AES.new(key, AES.MODE_CBC, iv)
				pt = unpad(cipher.decrypt(ct), AES.block_size)
				pt = pt.decode('utf-8')
				self.text_edit.setText(pt)
				file_in.close()
			except KeyError:
				print("Key Error")
			except ValueError:
				print("Inccorrect Decrypt")
			password = ""
			key = None
			b64 = None
			iv = None
			ct = None
			cipher = None
			pt = None
			self.password_dialog.pas = ""
			filename = ""
		password = ""
		filename = ""

	def hash_pass(self, pas)-> bytes:
		sha = SHA256.new()
		sha.update(bytes(pas, 'utf-8'))
		return sha.digest()

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

		openAction = QAction(QIcon(), "&Open Encrypted", self)
		openAction.setShortcut("Ctrl+Alt+O")
		openAction.triggered.connect(self.openFileEncrypted)
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
