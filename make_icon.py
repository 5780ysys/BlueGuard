# -*- coding: utf-8 -*-
from PIL import Image
import os
HERE = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(HERE, "icon.png")
ico = os.path.join(HERE, "icon.ico")
img = Image.open(src).convert("RGBA")
# PyInstaller/Windows icon: include common sizes
sizes = [(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)]
img.save(ico, format="ICO", sizes=sizes)
print("ICO:", ico, os.path.getsize(ico))
