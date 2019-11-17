# secure_pypad

Currently only AES is used and 5 modes are selectable

###Install Instructions

* get python 3
* get pip
* run pip install -r requirements.txt
  * if this fails these are the indivdual packages (pip install PyQt5) and (pip install pycryptodome)
* python notepad_ui.py

###Notes
* opening an encrypted file with normal open, checks if file is encrypted
  * if it is encrypted it will use the same function open encryted file does...no need to close out and use the other file chooser
* save encrypted is not as nice as opening. You will need to use the save encrypted file, file chooser. This is because opening a file and asking for a password is less obtrusive as always asking if you want to encrypt a file while saving...sometimes you just need to save a file.
* **Keep in mind selecting an encrpytion mode is only for saving.....when opening a file, the mode used to save will be called to decrypt the file regardless of what mode is selected.**
