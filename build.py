#!/bin/python3

from md2pdf.doc import Document
from datetime import datetime

name = "document-" + datetime.now().isoformat(sep='-', timespec='minutes') + ".pdf"

doc = Document.from_markdown("source.md")
doc.save_to_pdf(pdf_file_name="out/" + name)
