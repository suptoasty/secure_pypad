#!/usr/bin/env python3
import sys
from utils import app

if __name__ == "__main__":
	m_app = app(sys.argv, "Secure NotePad")

	sys.exit(m_app.exec_())
