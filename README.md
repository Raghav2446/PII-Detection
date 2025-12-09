# 🔒 PII Guardian — Indian PII Detection & Redaction Tool

PII Guardian is a privacy-first Python tool that detects, classifies, and redacts **Indian PII (Personally Identifiable Information)** from text, PDFs, and images. It combines multiple AI-powered techniques — including [Microsoft Presidio](https://github.com/microsoft/presidio), spaCy, custom regex rules, and OCR (with Hindi script support) — to scan data and mask sensitive content effectively.

> ⚡ Designed for Indian formats like Aadhaar, PAN, mobile numbers, emails, names, and more.  
> 🖥️ Comes with a full **Streamlit-based UI** for easy interaction.  
> 📄 Works on plain text, scanned documents (PDFs), and images using OCR.  
> 🔐 Supports smart redaction, severity scoring (Critical / Medium / Low), and customizable masking.

---

## 🚀 Features

- ✅ **Multi-source support**: Detect PII in text files, PDFs, and images (JPEG, PNG).
- 🌐 **Streamlit Web UI**: Intuitive interface to upload and process documents without CLI.
- 🔍 **High accuracy detection**: Uses spaCy NER, Microsoft Presidio, regex, and OCR in layers.
- 🇮🇳 **Indian PII focus**: Aadhaar, PAN, Voter ID, Indian phone numbers, emails, names, and addresses.
- 🧠 **Multi-language OCR**: Hindi and English document support via Tesseract.
- 🎯 **Risk classification**: Tags detected PII as Critical / Medium / Low.
- 🛡️ **Smart masking & redaction**: Mask sensitive parts only, retain context.
- 🧱 Modular architecture: Easily extend with custom PII recognizers or new formats.

---

## 📁 Supported PII Entities

| Entity Type | Format/Pattern | Risk Level |
|-------------|----------------|------------|
| Aadhaar     | 12-digit format with optional spaces | Critical |
| PAN         | 10-character alphanumeric (e.g. ABCDE1234F) | Critical |
| Mobile No.  | Indian mobile number formats | Medium |
| Email       | Standard email regex | Medium |
| Voter ID    | Varies by region | Critical |
| Name        | Detected via spaCy NER | Low |
| Address     | Extracted using NLP chunking | Medium |

---

## 🧠 AI Assistant Technologies Used

This project uses several AI/NLP libraries and models:

- 🤖 **Microsoft Presidio** — entity detection using ML + pattern recognizers.
- 🧠 **spaCy NLP** — Named Entity Recognition for names, places, etc.
- 👁️‍🗨️ **Tesseract OCR** — for text extraction from scanned documents/images in Hindi + English.
- 🧩 **Regex + AI-based tagging** — to improve accuracy and handle region-specific patterns.

---

## 🧰 Tech Stack

- **Python 3.8+**
- [Streamlit](https://streamlit.io/) — for building the UI
- [Microsoft Presidio](https://github.com/microsoft/presidio)
- [spaCy](https://spacy.io/)
- [pytesseract](https://github.com/madmaze/pytesseract)
- [pdf2image](https://github.com/Belval/pdf2image)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- Regex-based detection layer

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/ShauravBhatt/pii-detection-cipherx.git
cd pii-detection-cipherx

# Create a virtual environment (optional)
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Tesseract OCR (required for PDFs/images)
# Ubuntu:
sudo apt install tesseract-ocr
# Mac:
brew install tesseract

## 🧪 Usage

### ▶️ Run Streamlit Web UI

```bash
streamlit run app.py
