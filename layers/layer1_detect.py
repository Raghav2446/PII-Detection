# layers/layer1_detect.py — OPTIMIZED Multi-AI PII Detection Engine
# Enhanced accuracy + performance, same API for seamless integration

from io import BytesIO
from typing import Dict, Any, List, Optional, Tuple
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import fitz  # PyMuPDF
from PIL import Image, ImageOps, ImageFilter, ImageEnhance

# Optional dependencies with fallbacks
try:
    import pytesseract
    from pytesseract import Output
    OCR_AVAILABLE = True
except Exception:
    pytesseract = None
    Output = None
    OCR_AVAILABLE = False

try:
    import spacy
    SPACY_AVAILABLE = True
except Exception:
    spacy = None
    SPACY_AVAILABLE = False

try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
    PRESIDIO_AVAILABLE = True
except Exception:
    AnalyzerEngine = None
    Pattern = None
    PatternRecognizer = None
    PRESIDIO_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Thread-safe globals
_analyzer = None
_nlp_model = None
_lock = threading.Lock()

# Comprehensive Indic digit normalization
INDIC_DIGIT_MAPS = [
    str.maketrans("०१२३४५६७८९", "0123456789"),  # Devanagari
    str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789"),  # Bengali
    str.maketrans("૦૧૨૩૪૫૬૭૮૯", "0123456789"),  # Gujarati
    str.maketrans("௦௧௨௩௪௫௬௭௮௯", "0123456789"),  # Tamil
    str.maketrans("౦౧౨౩౪౫౬౭౮౯", "0123456789"),  # Telugu
    str.maketrans("೦೧೨೩೪೫೬೭೮೯", "0123456789"),  # Kannada
    str.maketrans("੦੧੨੩੪੫੬੭੮੯", "0123456789"),  # Gurmukhi
    str.maketrans("୦୧୨୩୪୫୬୭୮୯", "0123456789"),  # Odia
]

# Enhanced & compiled patterns for better performance
ENTITY_PATTERNS = {
    "AADHAAR": [
        re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", re.IGNORECASE),
        re.compile(r"\b(?:\d{4}|[Xx*#•]{4})[-\s]?(?:\d{4}|[Xx*#•]{4})[-\s]?(?:\d{4}|[Xx*#•]{4})\b", re.IGNORECASE),
        re.compile(r"(?:aadhaar?|aadhar|आधार|uid)\s*(?:no\.?|number|संख्या|नंबर)?\s*:?\s*\d{4}[-\s]?\d{4}[-\s]?\d{4}", re.IGNORECASE | re.UNICODE),
        re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
    ],
    "PAN": [
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        re.compile(r"(?:pan|पैन)\s*(?:no\.?|number|card|संख्या|नंबर)?\s*:?\s*[A-Z]{5}[0-9]{4}[A-Z]", re.IGNORECASE | re.UNICODE),
        re.compile(r"\b[A-Z]{3}[ABCFGHLJPTF][A-Z]\d{4}[A-Z]\b"),
    ],
    "PASSPORT": [
        re.compile(r"\b[A-Z][0-9]{7}\b"),
        re.compile(r"passport\s*(?:no\.?|number)?\s*:?\s*[A-Z][0-9]{7}", re.IGNORECASE),
        re.compile(r"(?:पासपोर्ट)\s*(?:संख्या|नंबर)?\s*:?\s*[A-Z][0-9]{7}", re.UNICODE),
    ],
    "DRIVING_LICENSE": [
        re.compile(r"\b[A-Z]{2}[-\s]?[0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{7}\b"),
        re.compile(r"\b[A-Z]{2}\d{13}\b"),
        re.compile(r"(?:driving\s*licen[sc]e|dl)\s*(?:no\.?|number)?\s*:?\s*[A-Z]{2}[-\s]?[0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{7}", re.IGNORECASE),
    ],
    "VOTER_ID": [
        re.compile(r"\b[A-Z]{3}[0-9]{7}\b"),
        re.compile(r"(?:voter\s*id|epic|election)\s*(?:no\.?|number)?\s*:?\s*[A-Z]{3}[0-9]{7}", re.IGNORECASE),
        re.compile(r"(?:मतदाता)\s*(?:पहचान|आईडी)\s*(?:संख्या|नंबर)?\s*:?\s*[A-Z]{3}[0-9]{7}", re.UNICODE),
    ],
    "BANK_ACCOUNT": [
        re.compile(r"\b\d{9,18}\b"),
        re.compile(r"(?:account\s*no\.?|a/?c\s*no\.?|bank\s*account)\s*:?\s*\d{9,18}", re.IGNORECASE),
        re.compile(r"(?:खाता)\s*संख्या\s*:?\s*\d{9,18}", re.UNICODE),
    ],
    "IFSC": [
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        re.compile(r"ifsc\s*(?:code)?\s*:?\s*[A-Z]{4}0[A-Z0-9]{6}", re.IGNORECASE),
        re.compile(r"(?:आईएफएससी)\s*(?:कोड)?\s*:?\s*[A-Z]{4}0[A-Z0-9]{6}", re.UNICODE),
    ],
    "MOBILE_NUMBER": [
        re.compile(r"\b[6-9]\d{9}\b"),
        re.compile(r"\b\+91[-\s]?[6-9]\d{9}\b"),
        re.compile(r"(?:mobile|phone|contact|cell)\s*(?:no\.?|number)?\s*:?\s*\+?91?[-\s]?[6-9]\d{9}", re.IGNORECASE),
    ],
    "EMAIL_ADDRESS": [
        re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        re.compile(r"e?mail\s*(?:id|address)?\s*:?\s*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
    ],
    "CREDIT_CARD": [
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
        re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    ],
}

# Context keywords for enhanced detection
ENTITY_CONTEXTS = {
    "AADHAAR": ["aadhaar", "aadhar", "uidai", "आधार", "uid", "identification", "unique"],
    "PAN": ["pan", "पैन", "income", "tax", "permanent", "account", "card"],
    "PASSPORT": ["passport", "पासपोर्ट", "travel", "document", "republic", "india"],
    "DRIVING_LICENSE": ["driving", "license", "licence", "dl", "rto", "transport"],
    "VOTER_ID": ["voter", "epic", "election", "eci", "मतदाता"],
    "BANK_ACCOUNT": ["account", "bank", "खाता", "saving", "current", "deposit"],
    "IFSC": ["ifsc", "आईएफएससी", "branch", "code", "swift"],
    "MOBILE_NUMBER": ["mobile", "phone", "फोन", "contact", "cell"],
    "EMAIL_ADDRESS": ["email", "mail", "ईमेल", "address", "id"],
}

def _normalize_indic_digits(text: str) -> str:
    if not text:
        return ""
    normalized = text
    for digit_map in INDIC_DIGIT_MAPS:
        normalized = normalized.translate(digit_map)
    normalized = re.sub(r"[\u200B-\u200F\uFEFF\u00AD]", "", normalized)
    normalized = re.sub(r"[ \t]+", " ", normalized)
    return normalized.strip()

def _sanitize_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _normalize_indic_digits(text)
    lines = text.split("\n")
    cleaned_lines = []
    for line in lines:
        cleaned_line = re.sub(r"[ \t]{2,}", " ", line.strip())
        if cleaned_line or (cleaned_lines and cleaned_lines[-1]):
            cleaned_lines.append(cleaned_line)
    return "\n".join(cleaned_lines)

def _load_spacy_model():
    global _nlp_model
    if _nlp_model is not None:
        return _nlp_model
    if not SPACY_AVAILABLE:
        logger.warning("spaCy not available")
        return None
    with _lock:
        if _nlp_model is not None:
            return _nlp_model
        for model_name in ["en_core_web_sm", "en_core_web_md", "en_core_web_lg"]:
            try:
                _nlp_model = spacy.load(model_name)
                _nlp_model.disable_pipes(["parser", "tagger", "lemmatizer"])
                logger.info(f"Loaded spaCy model: {model_name}")
                return _nlp_model
            except Exception as e:
                logger.debug(f"Failed to load {model_name}: {e}")
                continue
        logger.warning("Could not load any spaCy model")
        return None

def _get_analyzer():
    global _analyzer
    if _analyzer is not None:
        return _analyzer
    if not PRESIDIO_AVAILABLE:
        logger.warning("Presidio not available")
        return None
    with _lock:
        if _analyzer is not None:
            return _analyzer
        try:
            analyzer = AnalyzerEngine()
            for entity_type, compiled_patterns in ENTITY_PATTERNS.items():
                pattern_objects = []
                for i, compiled_pattern in enumerate(compiled_patterns):
                    pattern_objects.append(Pattern(
                        name=f"{entity_type.lower()}_{i}",
                        regex=compiled_pattern.pattern,
                        score=0.95 if i == 0 else 0.85
                    ))
                recognizer = PatternRecognizer(
                    supported_entity=entity_type,
                    patterns=pattern_objects,
                    context=ENTITY_CONTEXTS.get(entity_type, []),
                )
                analyzer.registry.add_recognizer(recognizer)
            _analyzer = analyzer
            logger.info("Enhanced Presidio analyzer initialized")
            return _analyzer
        except Exception as e:
            logger.error(f"Failed to initialize Presidio analyzer: {e}")
            return None

def _luhn_check(number: str) -> bool:
    try:
        digits = [int(d) for d in re.sub(r"[\s-]", "", number) if d.isdigit()]
        if not digits:
            return False
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        return sum(digits) % 10 == 0
    except Exception:
        return False

def detect_filetype(file_bytes: bytes) -> str:
    if not file_bytes:
        return "unknown"
    signatures = [
        (b"%PDF", "pdf"),
        (b"\x89PNG\r\n\x1a\n", "image"),
        (b"\xff\xd8\xff", "image"),
        (b"GIF8", "image"),
        (b"RIFF", "image"),
        (b"BM", "image"),
        (b"\x00\x00\x01\x00", "image"),
        (b"PK\x03\x04", "document"),
    ]
    for signature, ftype in signatures:
        if file_bytes.startswith(signature):
            return ftype
    try:
        with Image.open(BytesIO(file_bytes)) as img:
            img.verify()
        return "image"
    except Exception:
        pass
    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        doc.close()
        return "pdf"
    except Exception:
        pass
    for encoding in ["utf-8", "utf-16", "latin-1"]:
        try:
            file_bytes.decode(encoding)
            return "text"
        except Exception:
            continue
    return "unknown"

def _prepare_image_for_ocr(img: Image.Image) -> Image.Image:
    try:
        img = ImageOps.exif_transpose(img)
        if img.mode != 'L':
            img = img.convert('L')
        width, height = img.size
        max_dimension = max(width, height)
        if max_dimension < 1000:
            scale_factor = 1000 / max_dimension
            new_size = (int(width * scale_factor), int(height * scale_factor))
            img = img.resize(new_size, Image.LANCZOS)
        elif max_dimension > 4000:
            scale_factor = 4000 / max_dimension
            new_size = (int(width * scale_factor), int(height * scale_factor))
            img = img.resize(new_size, Image.LANCZOS)
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(1.5)
        img = img.filter(ImageFilter.UnsharpMask(radius=1.0, percent=150, threshold=3))
        try:
            histogram = img.histogram()
            total_pixels = sum(histogram)
            sum_total = sum(i * histogram[i] for i in range(256))
            sum_background = 0
            weight_background = 0
            var_max = 0
            threshold = 0
            for i in range(256):
                weight_background += histogram[i]
                if weight_background == 0:
                    continue
                weight_foreground = total_pixels - weight_background
                if weight_foreground == 0:
                    break
                sum_background += i * histogram[i]
                mean_background = sum_background / weight_background
                mean_foreground = (sum_total - sum_background) / weight_foreground
                var_between = weight_background * weight_foreground * (mean_background - mean_foreground) ** 2
                if var_between > var_max:
                    var_max = var_between
                    threshold = i
            threshold = max(100, min(200, threshold))
            img = img.point(lambda p: 255 if p > threshold else 0)
        except Exception:
            img = img.point(lambda p: 255 if p > 140 else 0)
        return img
    except Exception as e:
        logger.debug(f"Image preprocessing failed: {e}")
        return img

def _ocr_with_config(image: Image.Image, config: str, lang: str = "eng+hin") -> Tuple[str, List[Dict[str, Any]]]:
    if not OCR_AVAILABLE:
        return "", []
    try:
        text = pytesseract.image_to_string(image, config=config, lang=lang)
        data = pytesseract.image_to_data(image, output_type=Output.DICT, config=config, lang=lang)
        words = []
        text_list = data.get("text", [])
        conf_list = data.get("conf", [])
        left_list = data.get("left", [])
        top_list = data.get("top", [])
        width_list = data.get("width", [])
        height_list = data.get("height", [])
        for i in range(len(text_list)):
            word_text = (text_list[i] or "").strip()
            if not word_text or len(word_text) < 2:
                continue
            try:
                confidence = float(conf_list[i])
                if confidence < 25:
                    continue
                words.append({
                    "text": _normalize_indic_digits(word_text),
                    "left": int(left_list[i]),
                    "top": int(top_list[i]),
                    "width": int(width_list[i]),
                    "height": int(height_list[i]),
                    "conf": confidence,
                })
            except (ValueError, IndexError):
                continue
        return _sanitize_text(text), words
    except Exception as e:
        logger.debug(f"OCR failed with config {config}: {e}")
        return "", []

def _ocr_image_bytes(image_bytes: bytes) -> Tuple[str, List[Dict[str, Any]]]:
    if not OCR_AVAILABLE:
        return "", []
    try:
        img = Image.open(BytesIO(image_bytes))
        img = _prepare_image_for_ocr(img)
        configs = [
            "--oem 3 --psm 6 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@.-+# ",
            "--oem 3 --psm 4",
            "--oem 3 --psm 3",
            "--oem 1 --psm 6",
        ]
        best_text, best_words = "", []
        best_score = 0
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_config = {
                executor.submit(_ocr_with_config, img, config): config
                for config in configs[:2]
            }
            for future in as_completed(future_to_config):
                try:
                    text, words = future.result(timeout=10)
                    score = len(text.strip()) if text else 0
                    if score > best_score:
                        best_text, best_words, best_score = text, words, score
                except Exception:
                    continue
        if best_score < 50:
            for config in configs[2:]:
                text, words = _ocr_with_config(img, config)
                score = len(text.strip()) if text else 0
                if score > best_score:
                    best_text, best_words, best_score = text, words, score
        return best_text, best_words
    except Exception as e:
        logger.error(f"OCR processing failed: {e}")
        return "", []

def _spacy_ner_detection(text: str) -> List[Dict[str, Any]]:
    nlp = _load_spacy_model()
    if not nlp:
        return []
    try:
        detections = []
        max_length = 800_000
        if len(text) > max_length:
            offset = 0
            chunk_size = max_length
            while offset < len(text):
                chunk = text[offset:offset + chunk_size]
                doc = nlp(chunk)
                for ent in doc.ents:
                    entity_type = _map_spacy_label(ent.label_)
                    if entity_type:
                        detections.append({
                            "entity": entity_type,
                            "start": ent.start_char + offset,
                            "end": ent.end_char + offset,
                            "score": _calculate_spacy_confidence(ent),
                            "snippet": ent.text,
                            "source": "spaCy",
                        })
                offset += chunk_size
        else:
            doc = nlp(text)
            for ent in doc.ents:
                entity_type = _map_spacy_label(ent.label_)
                if entity_type:
                    detections.append({
                        "entity": entity_type,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "score": _calculate_spacy_confidence(ent),
                        "snippet": ent.text,
                        "source": "spaCy",
                    })
        return detections
    except Exception as e:
        logger.warning(f"spaCy NER failed: {e}")
        return []

def _map_spacy_label(label: str) -> Optional[str]:
    mapping = {
        "PERSON": "NAME",
        "ORG": "ORGANIZATION",
        "GPE": "LOCATION",
        "LOC": "LOCATION",
        "DATE": "DATE_TIME",
        "TIME": "DATE_TIME",
        "MONEY": "FINANCIAL_INFO",
    }
    return mapping.get(label)

def _calculate_spacy_confidence(ent) -> float:
    base_confidence = 0.75
    if len(ent.text) > 10:
        base_confidence += 0.05
    if ent.text.istitle():
        base_confidence += 0.05
    return min(0.95, base_confidence)

def _custom_pattern_detection(text: str) -> List[Dict[str, Any]]:
    detections = []
    custom_patterns = {
        "NAME": [
            re.compile(r"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Shri|Smt\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b"),
            re.compile(r"\b[A-Z][a-z]+\s+(?:Singh|Kumar|Sharma|Gupta|Agarwal|Jain|Patel|Shah|Reddy|Nair|Iyer|Rao|Das|Devi)\b"),
            re.compile(r"\b(?:श्री|श्रीमती|डॉ\.?|प्रो\.?)\s+[\u0900-\u097F]+(?:\s+[\u0900-\u097F]+)*\b", re.UNICODE),
        ],
        "DATE_TIME": [
            re.compile(r"\b\d{1,2}[-/\.]\d{1,2}[-/\.]\d{4}\b"),
            re.compile(r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b", re.IGNORECASE),
            re.compile(r"\b(?:जनवरी|फरवरी|मार्च|अप्रैल|मई|जून|जुलाई|अगस्त|सितंबर|अक्टूबर|नवंबर|दिसंबर)\s+\d{1,2},?\s+\d{4}\b", re.UNICODE),
        ],
        "LOCATION": [
            re.compile(r"\b\d{6}\b"),
            re.compile(r"\b(?:New\s+Delhi|Mumbai|Bangalore|Bengaluru|Chennai|Kolkata|Hyderabad|Pune|Ahmedabad|Jaipur|Lucknow|Kanpur|Nagpur|Indore|Thane|Bhopal|Visakhapatnam|Patna|Vadodara|Ghaziabad|Ludhiana|Agra|Nashik|Faridabad|Meerut|Rajkot|Surat|Coimbatore)\b", re.IGNORECASE),
        ],
    }
    for entity_type, patterns in custom_patterns.items():
        for pattern in patterns:
            try:
                for match in pattern.finditer(text):
                    matched_text = match.group().strip()
                    if len(matched_text) < 2:
                        continue
                    confidence = 0.7
                    if entity_type == "LOCATION" and matched_text.isdigit() and len(matched_text) == 6:
                        confidence = 0.85
                    elif entity_type == "NAME" and any(title in matched_text for title in ["Mr.", "Dr.", "Prof.", "श्री"]):
                        confidence = 0.8
                    detections.append({
                        "entity": entity_type,
                        "start": match.start(),
                        "end": match.end(),
                        "score": confidence,
                        "snippet": matched_text,
                        "source": "Custom",
                    })
            except Exception as e:
                logger.debug(f"Custom pattern failed for {entity_type}: {e}")
                continue
    return detections

def _merge_detections(presidio_results: List[Any], spacy_results: List[Dict[str, Any]], custom_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_detections = []
    for result in presidio_results or []:
        try:
            entity_type = "NAME" if getattr(result, "entity_type", "") == "PERSON" else getattr(result, "entity_type", "")
            all_detections.append({
                "entity": entity_type,
                "start": int(getattr(result, "start", 0)),
                "end": int(getattr(result, "end", 0)),
                "score": float(getattr(result, "score", 0.5)),
                "source": "Presidio",
            })
        except Exception:
            continue
    all_detections.extend(spacy_results or [])
    all_detections.extend(custom_results or [])
    if not all_detections:
        return []
    all_detections.sort(key=lambda x: (x["start"], -x["score"]))
    unique_detections = []
    for detection in all_detections:
        should_add = True
        for i, existing in enumerate(unique_detections):
            if detection["start"] < existing["end"] and detection["end"] > existing["start"]:
                overlap_start = max(detection["start"], existing["start"])
                overlap_end = min(detection["end"], existing["end"])
                overlap_length = overlap_end - overlap_start
                detection_length = detection["end"] - detection["start"]
                existing_length = existing["end"] - existing["start"]
                detection_overlap_pct = overlap_length / detection_length if detection_length > 0 else 0
                existing_overlap_pct = overlap_length / existing_length if existing_length > 0 else 0
                if detection_overlap_pct > 0.5 or existing_overlap_pct > 0.5:
                    if detection["score"] > existing["score"]:
                        unique_detections[i] = detection
                    should_add = False
                    break
        if should_add:
            unique_detections.append(detection)
    return sorted(unique_detections, key=lambda x: x["start"])

def _validate_detection(detection: Dict[str, Any], text: str) -> Dict[str, Any]:
    start = detection.get("start", 0)
    end = detection.get("end", 0)
    entity = detection.get("entity", "")
    if start >= end or end > len(text):
        detection["score"] = 0.0
        return detection
    detected_text = text[start:end].strip()
    if not detected_text:
        detection["score"] = 0.0
        return detection
    original_score = detection.get("score", 0.5)
    if entity == "AADHAAR":
        clean_text = re.sub(r"[\s-]", "", detected_text)
        if len(clean_text) != 12 or not clean_text.isdigit():
            detection["score"] = original_score * 0.3
        else:
            detection["score"] = min(0.95, original_score * 1.1)
    elif entity == "PAN":
        clean_text = re.sub(r"[\s-]", "", detected_text.upper())
        if not re.match(r"^[A-Z]{5}\d{4}[A-Z]$", clean_text):
            detection["score"] = original_score * 0.3
        else:
            detection["score"] = min(0.95, original_score * 1.1)
    elif entity == "MOBILE_NUMBER":
        clean_text = re.sub(r"[\s\-\+]", "", detected_text)
        if clean_text.startswith("91"):
            clean_text = clean_text[2:]
        if not (len(clean_text) == 10 and clean_text in "6789"):
            detection["score"] = original_score * 0.4
        else:
            detection["score"] = min(0.95, original_score * 1.1)
    elif entity == "CREDIT_CARD":
        if not _luhn_check(detected_text):
            detection["score"] = original_score * 0.2
        else:
            detection["score"] = min(0.98, original_score * 1.2)
    elif entity == "EMAIL_ADDRESS":
        if "@" not in detected_text or "." not in detected_text:
            detection["score"] = original_score * 0.3
    elif entity == "IFSC":
        clean_text = detected_text.upper().replace(" ", "")
        if not re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", clean_text):
            detection["score"] = original_score * 0.4
    context_start = max(0, start - 60)
    context_end = min(len(text), end + 60)
    context = text[context_start:context_end].lower()
    context_keywords = ENTITY_CONTEXTS.get(entity, [])
    context_boost = 0
    for keyword in context_keywords:
        if keyword.lower() in context:
            context_boost += 0.03
            if context_boost >= 0.15:
                break
    detection["score"] = min(0.98, detection["score"] + context_boost)
    return detection

# Main API
def analyze_document(
    file_bytes: bytes,
    filename: Optional[str] = None,
    force_ocr: bool = False,
    allowed_entities: Optional[List[str]] = None,
    score_threshold: float = 0.0,
    use_advanced_ai: bool = True,
) -> Dict[str, Any]:
    if not file_bytes:
        return {
            "filetype": "unknown", "text": "", "page_infos": [],
            "raw_results": [], "detections": [],
            "ocr_used": False, "ocr_note": "No file provided"
        }
    try:
        filetype = detect_filetype(file_bytes)
        analyzer = _get_analyzer()
        if filetype == "text":
            return _process_text(file_bytes, analyzer, allowed_entities, score_threshold, use_advanced_ai)
        elif filetype == "pdf":
            return _process_pdf(file_bytes, analyzer, allowed_entities, score_threshold, use_advanced_ai, force_ocr)
        elif filetype == "image":
            return _process_image(file_bytes, analyzer, allowed_entities, score_threshold, use_advanced_ai)
        else:
            return {
                "filetype": filetype, "text": "", "page_infos": [],
                "raw_results": [], "detections": [],
                "ocr_used": False, "ocr_note": f"Unsupported file type: {filetype}"
            }
    except Exception as e:
        logger.error(f"Document analysis failed: {e}")
        return {
            "filetype": "unknown", "text": "", "page_infos": [],
            "raw_results": [], "detections": [],
            "ocr_used": False, "ocr_note": f"Analysis failed: {str(e)}"
        }

def _process_text(file_bytes: bytes, analyzer, allowed_entities, score_threshold: float, use_advanced_ai: bool) -> Dict[str, Any]:
    text = ""
    encodings = ["utf-8", "utf-16", "utf-16-be", "utf-16-le", "latin-1", "cp1252", "iso-8859-1"]
    for encoding in encodings:
        try:
            text = file_bytes.decode(encoding, errors="ignore")
            if text.strip():
                break
        except Exception:
            continue
    if not text.strip():
        return {
            "filetype": "text", "text": "", "page_infos": [],
            "raw_results": [], "detections": [],
            "ocr_used": False, "ocr_note": "Empty or unreadable text"
        }
    text = _sanitize_text(text)
    presidio_results, spacy_results, custom_results = [], [], []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        if analyzer:
            # FIX: Use named arguments so Presidio always receives language="en"
            futures.append(executor.submit(analyzer.analyze, text=text, entities=allowed_entities, language="en"))
        if use_advanced_ai:
            futures.append(executor.submit(_spacy_ner_detection, text))
            futures.append(executor.submit(_custom_pattern_detection, text))
        for i, future in enumerate(futures):
            try:
                result = future.result(timeout=30)
                if analyzer and i == 0:
                    presidio_results = result
                elif (analyzer and i == 1) or (not analyzer and i == 0):
                    spacy_results = result
                else:
                    custom_results = result
            except Exception as e:
                logger.warning(f"Detection method {i} failed: {e}")
    merged_detections = _merge_detections(presidio_results, spacy_results, custom_results)
    detections = []
    for detection in merged_detections:
        v = _validate_detection(detection, text)
        if v.get("score", 0) >= score_threshold:
            s, e = v["start"], v["end"]
            v["snippet"] = text[max(0, s-30):min(len(text), e+30)].replace("\n", " ").strip()
            detections.append(v)
    return {
        "filetype": "text", "text": text, "page_infos": [],
        "raw_results": presidio_results, "detections": detections,
        "ocr_used": False, "ocr_note": None
    }

def _process_pdf(file_bytes: bytes, analyzer, allowed_entities, score_threshold: float, use_advanced_ai: bool, force_ocr: bool) -> Dict[str, Any]:
    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
    except Exception as ex:
        return {
            "filetype": "pdf", "text": "", "page_infos": [],
            "raw_results": [], "detections": [],
            "ocr_used": False, "ocr_note": f"Failed to open PDF: {ex}"
        }
    texts: List[str] = []
    pages_to_ocr: List[int] = []
    per_page_words: List[List[Dict[str, Any]]] = []
    ocr_used = False
    ocr_note = None
    for i, page in enumerate(doc):
        try:
            ptext = page.get_text("text") or ""
        except Exception:
            ptext = ""
        needs_ocr = (not ptext.strip() or len(ptext.strip()) < 50 or force_ocr)
        if needs_ocr:
            pages_to_ocr.append(i)
        ptext = _sanitize_text(ptext)
        texts.append(ptext)
        per_page_words.append([])
    if pages_to_ocr:
        if not OCR_AVAILABLE:
            ocr_note = "OCR required but pytesseract not available"
        else:
            failed_pages = []
            with ThreadPoolExecutor(max_workers=2) as executor:
                future_to_page = {}
                for i in pages_to_ocr:
                    try:
                        pix = doc[i].get_pixmap(dpi=300)
                        img_bytes = pix.tobytes("png")
                        future = executor.submit(_ocr_image_bytes, img_bytes)
                        future_to_page[future] = i
                    except Exception:
                        failed_pages.append(i + 1)
                for future in as_completed(future_to_page):
                    page_idx = future_to_page[future]
                    try:
                        o_text, o_words = future.result(timeout=60)
                        if o_text:
                            texts[page_idx] = o_text
                            per_page_words[page_idx] = o_words
                            ocr_used = True
                        else:
                            failed_pages.append(page_idx + 1)
                    except Exception:
                        failed_pages.append(page_idx + 1)
            if failed_pages:
                ocr_note = f"OCR failed on pages: {', '.join(map(str, failed_pages))}"
    cursor = 0
    page_infos = []
    for i, t in enumerate(texts):
        t = t or ""
        page_infos.append({
            "index": i, "text": t, "start": cursor, "end": cursor + len(t),
            "ocr_words": per_page_words[i]
        })
        cursor += len(t) + 1
    full_text = "\n".join(texts)
    doc.close()
    if not full_text.strip():
        return {
            "filetype": "pdf", "text": "", "page_infos": page_infos,
            "raw_results": [], "detections": [],
            "ocr_used": ocr_used, "ocr_note": "No text extracted from PDF"
        }
    presidio_results, spacy_results, custom_results = [], [], []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        if analyzer:
            # FIX: Use named arguments so Presidio always receives language="en"
            futures.append(executor.submit(analyzer.analyze, text=full_text, entities=allowed_entities, language="en"))
        if use_advanced_ai:
            futures.append(executor.submit(_spacy_ner_detection, full_text))
            futures.append(executor.submit(_custom_pattern_detection, full_text))
        for i, future in enumerate(futures):
            try:
                result = future.result(timeout=45)
                if analyzer and i == 0:
                    presidio_results = result
                elif (analyzer and i == 1) or (not analyzer and i == 0):
                    spacy_results = result
                else:
                    custom_results = result
            except Exception as e:
                logger.warning(f"Detection method {i} failed: {e}")
    merged_detections = _merge_detections(presidio_results, spacy_results, custom_results)
    detections = []
    for d in merged_detections:
        v = _validate_detection(d, full_text)
        if v.get("score", 0) >= score_threshold:
            s, e = v["start"], v["end"]
            v["snippet"] = full_text[max(0, s-30):min(len(full_text), e+30)].replace("\n", " ").strip()
            detections.append(v)
    return {
        "filetype": "pdf", "text": full_text, "page_infos": page_infos,
        "raw_results": presidio_results, "detections": detections,
        "ocr_used": ocr_used, "ocr_note": ocr_note
    }

def _process_image(file_bytes: bytes, analyzer, allowed_entities, score_threshold: float, use_advanced_ai: bool) -> Dict[str, Any]:
    if not OCR_AVAILABLE:
        return {
            "filetype": "image", "text": "", "page_infos": [],
            "raw_results": [], "detections": [],
            "ocr_used": False, "ocr_note": "OCR not available for image processing"
        }
    text, words = _ocr_image_bytes(file_bytes)
    text = _sanitize_text(text)
    if not text.strip():
        return {
            "filetype": "image", "text": "", "page_infos": [],
            "raw_results": [], "detections": [],
            "ocr_used": True, "ocr_note": "No text extracted from image"
        }
    presidio_results, spacy_results, custom_results = [], [], []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        if analyzer:
            # FIX: Use named arguments so Presidio always receives language="en"
            futures.append(executor.submit(analyzer.analyze, text=text, entities=allowed_entities, language="en"))
        if use_advanced_ai:
            futures.append(executor.submit(_spacy_ner_detection, text))
            futures.append(executor.submit(_custom_pattern_detection, text))
        for i, future in enumerate(futures):
            try:
                result = future.result(timeout=30)
                if analyzer and i == 0:
                    presidio_results = result
                elif (analyzer and i == 1) or (not analyzer and i == 0):
                    spacy_results = result
                else:
                    custom_results = result
            except Exception as e:
                logger.warning(f"Detection method {i} failed: {e}")
    merged_detections = _merge_detections(presidio_results, spacy_results, custom_results)
    detections = []
    for detection in merged_detections:
        v = _validate_detection(detection, text)
        if v.get("score", 0) >= score_threshold:
            s, e = v["start"], v["end"]
            v["snippet"] = text[max(0, s-30):min(len(text), e+30)].replace("\n", " ").strip()
            detections.append(v)
    return {
        "filetype": "image", "text": text,
        "page_infos": [{"index": 0, "text": text, "start": 0, "end": len(text), "ocr_words": words}],
        "raw_results": presidio_results, "detections": detections,
        "ocr_used": True, "ocr_note": None
    }
