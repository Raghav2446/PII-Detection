# layers/layer3_act.py — OPTIMIZED Multi-Modal Masking & Redaction Engine
# Enhanced accuracy + performance, same API for seamless integration

from typing import List, Dict, Tuple, Optional, Union, Any
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import math

import fitz  # PyMuPDF
from PIL import Image, ImageDraw, ImageFilter, ImageEnhance
from io import BytesIO

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Type definitions
Span = Dict[str, Union[int, str]]

# Enhanced masking styles
MASK_STYLES = {
    "standard": {"char": "X", "placeholder": "[MASKED]"},
    "redacted": {"char": "█", "placeholder": "[REDACTED]"},
    "smart": {"char": "*", "placeholder": "[PROTECTED]"},
    "minimal": {"char": "•", "placeholder": "[HIDDEN]"},
}

# Optimized smart masking patterns
SMART_MASK_PATTERNS = {
    "AADHAAR": {
        "pattern": "XXXX-XXXX-{last4}",
        "description": "Shows last 4 digits (UIDAI compliant)",
        "regex": re.compile(r"\d{4}[-\s]?\d{4}[-\s]?(\d{4})"),
    },
    "PAN": {
        "pattern": "XXXXX{middle4}X", 
        "description": "Shows middle 4 digits",
        "regex": re.compile(r"[A-Z]{5}(\d{4})[A-Z]"),
    },
    "BANK_ACCOUNT": {
        "pattern": "XXXXXXX{last4}",
        "description": "Shows last 4 digits",
        "regex": re.compile(r"\d+(\d{4})$"),
    },
    "MOBILE_NUMBER": {
        "pattern": "XXXXX{last5}",
        "description": "Shows last 5 digits",
        "regex": re.compile(r"[\+91\s\-]*[6-9]\d{4}(\d{5})"),
    },
    "EMAIL_ADDRESS": {
        "pattern": "{first2}***@{domain}",
        "description": "Shows first 2 chars and domain",
        "regex": re.compile(r"([a-zA-Z0-9]{1,2})[a-zA-Z0-9._%-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
    },
    "IFSC": {
        "pattern": "{first4}0XXX{last3}",
        "description": "Shows bank code and last 3 chars",
        "regex": re.compile(r"([A-Z]{4})0[A-Z0-9]{3}([A-Z0-9]{3})"),
    },
    "PASSPORT": {
        "pattern": "X{last6}",
        "description": "Shows last 6-7 digits",
        "regex": re.compile(r"[A-Z](\d{6,7})"),
    },
    "DRIVING_LICENSE": {
        "pattern": "{state}XX-XXXX-XXXX",
        "description": "Shows only state code",
        "regex": re.compile(r"([A-Z]{2})[-\s]?\d{2}[-\s]?\d{4}[-\s]?\d{7}"),
    },
    "VOTER_ID": {
        "pattern": "XXX{last4}",
        "description": "Shows last 4 digits",
        "regex": re.compile(r"[A-Z]{3}(\d{4,7})"),
    },
}

def _apply_smart_mask(content: str, entity: str, mask_style: str = "standard") -> str:
    """Enhanced smart masking with better pattern matching"""
    if not content or entity not in SMART_MASK_PATTERNS:
        return _get_placeholder(mask_style, entity)
    
    mask_char = MASK_STYLES.get(mask_style, MASK_STYLES["standard"])["char"]
    
    try:
        if entity == "AADHAAR":
            clean_content = re.sub(r"[-\s]", "", content)
            if len(clean_content) >= 4 and clean_content.isdigit():
                return f"{mask_char*4}-{mask_char*4}-{clean_content[-4:]}"
                
        elif entity == "PAN":
            clean_content = re.sub(r"[\s-]", "", content.upper())
            if len(clean_content) == 10 and re.match(r"^[A-Z]{5}\d{4}[A-Z]$", clean_content):
                return f"{mask_char*5}{clean_content[5:9]}{mask_char}"
                
        elif entity == "BANK_ACCOUNT":
            clean_content = re.sub(r"[\s-]", "", content)
            if len(clean_content) >= 4 and clean_content.isdigit():
                mask_length = max(3, len(clean_content) - 4)
                return f"{mask_char*mask_length}{clean_content[-4:]}"
                
        elif entity == "MOBILE_NUMBER":
            clean_content = re.sub(r"[\s\-\+]", "", content)
            if clean_content.startswith("91"):
                clean_content = clean_content[2:]
            if len(clean_content) == 10 and clean_content[0] in "6789":
                return f"{mask_char*5}{clean_content[-5:]}"
                
        elif entity == "EMAIL_ADDRESS":
            if "@" in content:
                local_part, domain_part = content.split("@", 1)
                if len(local_part) >= 2:
                    masked_local = local_part[:2] + mask_char * max(1, len(local_part) - 2)
                    return f"{masked_local}@{domain_part}"
                elif len(local_part) == 1:
                    return f"{local_part}{mask_char*3}@{domain_part}"
                    
        elif entity == "IFSC":
            clean_content = content.upper().replace(" ", "")
            if len(clean_content) == 11 and re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", clean_content):
                return f"{clean_content[:4]}0{mask_char*3}{clean_content[-3:]}"
                
        elif entity == "PASSPORT":
            match = re.search(r"[A-Z](\d{6,7})", content.upper())
            if match:
                digits = match.group(1)
                return f"{mask_char}{digits}"
                
        elif entity == "DRIVING_LICENSE":
            match = re.match(r"([A-Z]{2})[-\s]*\d+", content.upper())
            if match:
                state_code = match.group(1)
                return f"{state_code}-{mask_char*2}-{mask_char*4}-{mask_char*7}"
                
        elif entity == "VOTER_ID":
            match = re.search(r"[A-Z]{3}(\d{4,7})", content.upper())
            if match:
                digits = match.group(1)
                return f"{mask_char*3}{digits[-4:]}"
                
    except Exception as e:
        logger.debug(f"Smart masking failed for {entity}: {e}")
    
    return _get_placeholder(mask_style, entity)

def _apply_standard_mask(content: str, entity: str, mask_style: str = "standard") -> str:
    """Apply standard masking based on style"""
    if not content:
        return _get_placeholder(mask_style, entity)
        
    style_config = MASK_STYLES.get(mask_style, MASK_STYLES["standard"])
    
    if mask_style == "redacted":
        return style_config["char"] * min(len(content), 10)
    elif mask_style == "smart":
        return f"[{entity}]"
    elif mask_style == "minimal":
        return style_config["char"] * min(len(content), 6)
    else:
        return style_config["placeholder"]

def _get_placeholder(mask_style: str, entity: str) -> str:
    """Get appropriate placeholder for masking style"""
    style_config = MASK_STYLES.get(mask_style, MASK_STYLES["standard"])
    if mask_style == "smart":
        return f"[{entity}_PROTECTED]"
    return style_config["placeholder"]

def mask_text_output(
    text: str,
    detections: List[Span],
    use_smart_masking: bool = True,
    mask_style: str = "standard"
) -> Tuple[str, Dict[str, Any]]:
    """Enhanced text masking - same API for seamless integration"""
    if not text:
        return text, {"error": "Empty text provided", "masked_count": 0}
    
    if not detections:
        return text, {"message": "No detections to mask", "masked_count": 0}
    
    # Validate spans
    valid_spans = []
    invalid_count = 0
    
    for detection in detections:
        try:
            start = int(detection.get("start", 0))
            end = int(detection.get("end", 0))
            entity = detection.get("entity", "")
            
            if 0 <= start < end <= len(text):
                valid_spans.append({
                    "start": start,
                    "end": end,
                    "entity": entity,
                    "original_text": text[start:end],
                })
            else:
                invalid_count += 1
        except (ValueError, TypeError):
            invalid_count += 1
    
    if not valid_spans:
        return text, {"error": "No valid spans to mask", "masked_count": 0}
    
    # Sort in reverse order to avoid index shifting
    valid_spans.sort(key=lambda x: x["start"], reverse=True)
    
    # Apply masking
    masked_text = text
    stats = {"successful_masks": 0, "failed_masks": 0, "entity_counts": {}}
    
    for span in valid_spans:
        try:
            start, end = span["start"], span["end"]
            entity = span["entity"]
            original_content = span["original_text"]
            
            # Choose masking method
            if use_smart_masking and entity in SMART_MASK_PATTERNS:
                masked_content = _apply_smart_mask(original_content, entity, mask_style)
            else:
                masked_content = _apply_standard_mask(original_content, entity, mask_style)
            
            # Apply mask
            masked_text = masked_text[:start] + masked_content + masked_text[end:]
            stats["successful_masks"] += 1
            stats["entity_counts"][entity] = stats["entity_counts"].get(entity, 0) + 1
            
        except Exception as e:
            logger.warning(f"Masking failed: {e}")
            stats["failed_masks"] += 1
            
            # Fallback
            try:
                fallback = _get_placeholder(mask_style, span["entity"])
                masked_text = masked_text[:start] + fallback + masked_text[end:]
                stats["successful_masks"] += 1
            except Exception:
                continue
    
    stats["masked_count"] = stats["successful_masks"]
    return masked_text, stats

def _page_index_for_pos(page_infos: List[Dict], start: int) -> Optional[int]:
    """Find which page contains the given text position"""
    for page_info in page_infos:
        page_start = page_info.get("start", 0)
        page_end = page_info.get("end", 0)
        if page_start <= start < page_end:
            return page_info.get("index")
    return None

def _calculate_text_similarity(s1: str, s2: str) -> float:
    """Enhanced text similarity calculation"""
    if not s1 or not s2:
        return 0.0
    
    s1, s2 = s1.lower().strip(), s2.lower().strip()
    
    # Jaccard similarity
    set1, set2 = set(s1), set(s2)
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    jaccard_sim = intersection / union if union > 0 else 0.0
    
    # Length similarity
    len_sim = min(len(s1), len(s2)) / max(len(s1), len(s2)) if max(len(s1), len(s2)) > 0 else 0.0
    
    # Substring similarity
    substr_sim = 0.0
    if len(s1) >= 3 and len(s2) >= 3:
        if s1 in s2 or s2 in s1:
            substr_sim = 0.8
    
    return max(substr_sim, (jaccard_sim * 0.6) + (len_sim * 0.4))

def _find_rects_from_ocr_words(snippet: str, ocr_words: List[Dict], fuzzy_match: bool = True) -> List[fitz.Rect]:
    """Enhanced OCR word matching with better performance"""
    if not snippet or not ocr_words:
        return []
    
    tokens = [token.strip().lower() for token in re.split(r"\s+", snippet) 
             if token.strip() and len(token.strip()) > 1]
    
    if not tokens:
        return []
    
    # Pre-process OCR words
    word_data = []
    for word_info in ocr_words:
        try:
            word_text = (word_info.get("text", "") or "").strip().lower()
            if not word_text or len(word_text) < 2:
                continue
                
            confidence = float(word_info.get("conf", 0))
            if confidence < 20:
                continue
            
            left = max(0, int(word_info.get("left", 0)))
            top = max(0, int(word_info.get("top", 0)))
            width = max(1, int(word_info.get("width", 0)))
            height = max(1, int(word_info.get("height", 0)))
            
            rect = fitz.Rect(left, top, left + width, top + height)
            if rect.is_valid and not rect.is_empty:
                word_data.append({
                    "text": word_text,
                    "rect": rect,
                    "confidence": confidence,
                    "used": False,
                })
        except Exception:
            continue
    
    if not word_data:
        return []
    
    # Enhanced matching algorithm
    matched_rects = []
    
    for token in tokens:
        best_match = None
        best_score = 0.0
        
        for word_info in word_data:
            if word_info["used"]:
                continue
                
            word_text = word_info["text"]
            confidence = word_info["confidence"]
            
            # Calculate match score
            match_score = 0.0
            
            if token == word_text:
                match_score = confidence * 1.0
            elif token in word_text or word_text in token:
                overlap_ratio = len(set(token) & set(word_text)) / len(set(token) | set(word_text))
                match_score = confidence * overlap_ratio * 0.85
            elif fuzzy_match and len(token) > 3:
                similarity = _calculate_text_similarity(token, word_text)
                if similarity > 0.65:
                    match_score = confidence * similarity * 0.75
            elif len(token) <= 3 and len(word_text) <= 3:
                if abs(len(token) - len(word_text)) <= 1:
                    common_chars = len(set(token) & set(word_text))
                    if common_chars >= len(token) - 1:
                        match_score = confidence * 0.6
            
            if match_score > best_score and match_score > 15:
                best_score = match_score
                best_match = word_info
        
        if best_match:
            matched_rects.append(best_match["rect"])
            best_match["used"] = True
    
    return matched_rects

def _find_text_rectangles(page, snippet: str, page_infos: List[Dict], page_idx: int, stats: Dict) -> List[fitz.Rect]:
    """Enhanced text rectangle finding with multiple strategies"""
    rects = []
    
    # Strategy 1: Direct text search
    try:
        direct_rects = page.search_for(snippet)
        if direct_rects:
            rects.extend(direct_rects)
            stats["text_search_success"] += 1
            return rects
    except Exception:
        pass
    
    # Strategy 2: Partial phrase search
    if len(snippet) > 15:
        words = snippet.split()
        if len(words) > 2:
            phrases = [
                " ".join(words[:len(words)//2]),
                " ".join(words[len(words)//2:]),
                " ".join(words[:3]) if len(words) > 3 else None,
                " ".join(words[-3:]) if len(words) > 3 else None,
            ]
            
            for phrase in phrases:
                if phrase and len(phrase.strip()) > 4:
                    try:
                        phrase_rects = page.search_for(phrase)
                        if phrase_rects:
                            rects.extend(phrase_rects)
                            stats["partial_matches"] += 1
                    except Exception:
                        continue
            
            if rects:
                return rects
    
    # Strategy 3: Individual word search
    words = snippet.split()
    important_words = [w for w in words if len(w) > 4 and not w.lower() in ['the', 'and', 'or', 'but', 'for']]
    
    for word in important_words[:3]:
        try:
            word_rects = page.search_for(word)
            if word_rects:
                rects.extend(word_rects[:2])
        except Exception:
            continue
    
    if rects:
        stats["partial_matches"] += 1
        return rects
    
    # Strategy 4: OCR fallback
    if page_idx < len(page_infos):
        ocr_words = page_infos[page_idx].get("ocr_words", [])
        if ocr_words:
            try:
                ocr_rects = _find_rects_from_ocr_words(snippet, ocr_words, fuzzy_match=True)
                if ocr_rects:
                    rects.extend(ocr_rects)
                    stats["ocr_fallback_used"] += 1
            except Exception:
                pass
    
    return rects

def redact_pdf_output(
    file_bytes: bytes,
    full_text: str,
    page_infos: List[Dict],
    spans: List[Dict[str, int]],
    redaction_color: Tuple[float, float, float] = (0, 0, 0)
) -> Tuple[Optional[bytes], str]:
    """Enhanced PDF redaction - same API for seamless integration"""
    if not file_bytes:
        return None, "Error: No PDF content provided"
    
    if not spans:
        return None, "Info: No content to redact"
    
    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        
        redaction_stats = {
            "total_spans": len(spans),
            "text_search_success": 0,
            "ocr_fallback_used": 0,
            "partial_matches": 0,
            "failed_redactions": 0,
            "pages_processed": set(),
            "redaction_boxes": 0,
        }
        
        successful_redactions = []
        
        # Process each span
        for span_idx, span in enumerate(spans):
            try:
                start = span.get("start", 0)
                end = span.get("end", 0)
                
                if start >= end or end > len(full_text):
                    redaction_stats["failed_redactions"] += 1
                    continue
                
                snippet = full_text[start:end].strip()
                if not snippet:
                    redaction_stats["failed_redactions"] += 1
                    continue
                
                page_idx = _page_index_for_pos(page_infos, start)
                if page_idx is None or page_idx >= len(doc):
                    redaction_stats["failed_redactions"] += 1
                    continue
                
                page = doc[page_idx]
                redaction_stats["pages_processed"].add(page_idx)
                
                # Find rectangles with multiple strategies
                rects = _find_text_rectangles(page, snippet, page_infos, page_idx, redaction_stats)
                
                if rects:
                    successful_redactions.append({
                        "page": page,
                        "rects": rects,
                        "snippet": snippet,
                        "entity": span.get("entity", "")
                    })
                else:
                    redaction_stats["failed_redactions"] += 1
                    
            except Exception as e:
                logger.error(f"Error processing span {span_idx}: {e}")
                redaction_stats["failed_redactions"] += 1
        
        # Apply redactions with smart padding
        for redaction in successful_redactions:
            page = redaction["page"]
            rects = redaction["rects"]
            
            for rect in rects:
                try:
                    if not (rect.is_valid and not rect.is_empty):
                        continue
                    
                    # Smart padding based on text size
                    padding = min(3, max(1, int(rect.height * 0.1)))
                    
                    padded_rect = fitz.Rect(
                        max(0, rect.x0 - padding),
                        max(0, rect.y0 - padding),
                        rect.x1 + padding,
                        rect.y1 + padding
                    )
                    
                    # Clip to page bounds
                    page_rect = page.rect
                    clipped_rect = padded_rect & page_rect
                    
                    if not clipped_rect.is_empty:
                        page.add_redact_annot(clipped_rect, fill=redaction_color)
                        redaction_stats["redaction_boxes"] += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to add redaction annotation: {e}")
        
        # Apply redactions
        for page_num in redaction_stats["pages_processed"]:
            try:
                page = doc[page_num]
                page.apply_redactions()
            except Exception as e:
                logger.warning(f"Failed to apply redactions on page {page_num + 1}: {e}")
        
        # Generate output
        try:
            output_bytes = doc.write()
            doc.close()
        except Exception as e:
            doc.close()
            return None, f"Error generating redacted PDF: {str(e)}"
        
        # Status report
        success_rate = 0
        if redaction_stats["total_spans"] > 0:
            successful_spans = (redaction_stats["text_search_success"] + 
                              redaction_stats["ocr_fallback_used"] + 
                              redaction_stats["partial_matches"])
            success_rate = (successful_spans / redaction_stats["total_spans"]) * 100
        
        status_report = (
            f"PDF Redaction Complete: {redaction_stats['redaction_boxes']} redaction boxes applied. "
            f"Success rate: {success_rate:.1f}% "
            f"({redaction_stats['text_search_success']} direct, "
            f"{redaction_stats['ocr_fallback_used']} OCR fallback, "
            f"{redaction_stats['partial_matches']} partial matches). "
            f"Failed: {redaction_stats['failed_redactions']}. "
            f"Pages processed: {len(redaction_stats['pages_processed'])}"
        )
        
        return output_bytes, status_report
        
    except Exception as e:
        logger.error(f"PDF redaction failed: {e}")
        return None, f"PDF redaction failed: {str(e)}"

def _find_image_regions(snippet: str, ocr_words: List[Dict], stats: Dict) -> List[Tuple[int, int, int, int]]:
    """Find regions in image corresponding to text snippet"""
    regions = []
    
    if not ocr_words:
        return regions
    
    tokens = [token.strip().lower() for token in re.split(r"\s+", snippet) if token.strip()]
    if not tokens:
        return regions
    
    matched_words = []
    used_indices = set()
    
    for token in tokens:
        best_match_idx = None
        best_score = 0.0
        
        for i, word_data in enumerate(ocr_words):
            if i in used_indices:
                continue
                
            try:
                word_text = (word_data.get("text", "") or "").strip().lower()
                if not word_text:
                    continue
                    
                confidence = float(word_data.get("conf", 0))
                if confidence < 25:
                    continue
                    
                stats["words_processed"] += 1
                
                # Calculate match score
                score = 0.0
                if token == word_text:
                    score = confidence * 1.0
                elif token in word_text or word_text in token:
                    similarity = _calculate_text_similarity(token, word_text)
                    score = confidence * similarity * 0.8
                elif len(token) > 3:
                    similarity = _calculate_text_similarity(token, word_text)
                    if similarity > 0.7:
                        score = confidence * similarity * 0.6
                
                if score > best_score and score > 20:
                    best_score = score
                    best_match_idx = i
                    
            except Exception:
                continue
        
        if best_match_idx is not None:
            matched_words.append(ocr_words[best_match_idx])
            used_indices.add(best_match_idx)
    
    # Convert to regions
    for word_data in matched_words:
        try:
            left = max(0, int(word_data.get("left", 0)))
            top = max(0, int(word_data.get("top", 0)))
            width = max(1, int(word_data.get("width", 0)))
            height = max(1, int(word_data.get("height", 0)))
            
            padding = 3
            region = (
                left - padding,
                top - padding,
                left + width + padding,
                top + height + padding
            )
            
            regions.append(region)
            
        except Exception:
            continue
    
    return regions

def _apply_image_redaction(img: Image.Image, draw: ImageDraw.Draw, img_blurred: Optional[Image.Image], regions: List[Tuple[int, int, int, int]], redaction_style: str) -> int:
    """Apply redaction to image regions"""
    regions_redacted = 0
    
    for region in regions:
        try:
            left, top, right, bottom = region
            left = max(0, left)
            top = max(0, top)
            right = min(img.width, right)
            bottom = min(img.height, bottom)
            
            if left >= right or top >= bottom:
                continue
            
            region = (left, top, right, bottom)
            
            if redaction_style == "black_box":
                draw.rectangle(region, fill=(0, 0, 0))
                regions_redacted += 1
                
            elif redaction_style == "blur" and img_blurred:
                try:
                    blurred_region = img_blurred.crop(region)
                    img.paste(blurred_region, (left, top))
                    regions_redacted += 1
                except Exception:
                    draw.rectangle(region, fill=(0, 0, 0))
                    regions_redacted += 1
                    
            elif redaction_style == "pixelate":
                try:
                    region_img = img.crop(region)
                    small_size = (max(1, region_img.width // 12), max(1, region_img.height // 12))
                    small_img = region_img.resize(small_size, Image.NEAREST)
                    pixelated = small_img.resize(region_img.size, Image.NEAREST)
                    img.paste(pixelated, (left, top))
                    regions_redacted += 1
                except Exception:
                    draw.rectangle(region, fill=(0, 0, 0))
                    regions_redacted += 1
            else:
                draw.rectangle(region, fill=(0, 0, 0))
                regions_redacted += 1
                
        except Exception:
            continue
    
    return regions_redacted

def redact_image_output(
    image_bytes: bytes,
    page_info: Dict,
    spans: List[Dict[str, int]],
    redaction_style: str = "black_box"
) -> Tuple[Optional[bytes], str]:
    """Enhanced image redaction - same API for seamless integration"""
    if not image_bytes:
        return None, "Error: No image content provided"
    
    if not spans:
        return None, "Info: No content to redact"
    
    try:
        img = Image.open(BytesIO(image_bytes))
        if img.mode != "RGB":
            img = img.convert("RGB")
        
        draw = ImageDraw.Draw(img)
        
        # Pre-create blurred version if needed
        img_blurred = None
        if redaction_style == "blur":
            img_blurred = img.filter(ImageFilter.GaussianBlur(radius=12))
        
        text = page_info.get("text", "") or ""
        ocr_words = page_info.get("ocr_words", []) or []
        
        redaction_stats = {
            "total_spans": len(spans),
            "successful_redactions": 0,
            "failed_redactions": 0,
            "words_processed": 0,
            "regions_redacted": 0,
            "redaction_method": redaction_style,
        }
        
        # Process each span
        for span in spans:
            try:
                start = span.get("start", 0)
                end = span.get("end", 0)
                
                if start >= len(text) or end > len(text) or start >= end:
                    redaction_stats["failed_redactions"] += 1
                    continue
                
                snippet = text[start:end].strip()
                if not snippet:
                    redaction_stats["failed_redactions"] += 1
                    continue
                
                regions = _find_image_regions(snippet, ocr_words, redaction_stats)
                
                if regions:
                    regions_redacted = _apply_image_redaction(
                        img, draw, img_blurred, regions, redaction_style
                    )
                    redaction_stats["regions_redacted"] += regions_redacted
                    
                    if regions_redacted > 0:
                        redaction_stats["successful_redactions"] += 1
                    else:
                        redaction_stats["failed_redactions"] += 1
                else:
                    redaction_stats["failed_redactions"] += 1
                    
            except Exception as e:
                logger.error(f"Error processing span for image redaction: {e}")
                redaction_stats["failed_redactions"] += 1
        
        # Save optimized image
        output_buffer = BytesIO()
        
        img_format = "PNG"
        save_kwargs = {"optimize": True}
        
        # Detect original format
        try:
            original_img = Image.open(BytesIO(image_bytes))
            if hasattr(original_img, 'format') and original_img.format == 'JPEG':
                img_format = "JPEG"
                save_kwargs = {"quality": 95, "optimize": True}
        except Exception:
            pass
        
        img.save(output_buffer, format=img_format, **save_kwargs)
        output_bytes = output_buffer.getvalue()
        
        # Status report
        success_rate = 0
        if redaction_stats["total_spans"] > 0:
            success_rate = (redaction_stats["successful_redactions"] / redaction_stats["total_spans"]) * 100
        
        status_report = (
            f"Image redaction complete: {redaction_stats['regions_redacted']} regions redacted using {redaction_style}. "
            f"Success rate: {success_rate:.1f}% "
            f"({redaction_stats['successful_redactions']}/{redaction_stats['total_spans']} spans). "
            f"Words processed: {redaction_stats['words_processed']}"
        )
        
        return output_bytes, status_report
        
    except Exception as e:
        logger.error(f"Image redaction failed: {e}")
        return None, f"Image redaction failed: {str(e)}"

def create_redaction_report(spans: List[Dict], purpose: str) -> Dict[str, Any]:
    """Generate comprehensive redaction report - same API for seamless integration"""
    if not spans:
        return {
            "total_redacted": 0,
            "entities_redacted": {},
            "purpose": purpose or "unknown",
            "recommendation": "No redactions applied - document may be safe for sharing",
            "privacy_score": 100,
            "compliance_status": "Unknown - no PII detected"
        }
    
    entity_counts = {}
    risk_levels = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    # Enhanced entity categorization
    critical_entities = ["AADHAAR", "PAN", "PASSPORT", "BANK_ACCOUNT", "IFSC", "CREDIT_CARD"]
    high_risk_entities = ["DRIVING_LICENSE", "VOTER_ID", "MOBILE_NUMBER", "EMAIL_ADDRESS"]
    medium_risk_entities = ["NAME", "LOCATION", "DATE_TIME"]
    low_risk_entities = ["ORGANIZATION", "FINANCIAL_INFO"]
    
    for span in spans:
        entity = span.get("entity", "Unknown")
        entity_counts[entity] = entity_counts.get(entity, 0) + 1
        
        if entity in critical_entities:
            risk_levels["Critical"] += 1
        elif entity in high_risk_entities:
            risk_levels["High"] += 1
        elif entity in medium_risk_entities:
            risk_levels["Medium"] += 1
        else:
            risk_levels["Low"] += 1
    
    total_redacted = len(spans)
    
    # Enhanced privacy score calculation
    critical_protected = risk_levels["Critical"]
    high_protected = risk_levels["High"]
    medium_protected = risk_levels["Medium"]
    
    base_score = 60
    critical_bonus = min(30, critical_protected * 8)
    high_bonus = min(20, high_protected * 4)
    medium_bonus = min(10, medium_protected * 2)
    
    privacy_score = min(100, base_score + critical_bonus + high_bonus + medium_bonus)
    
    # Compliance status
    if critical_protected >= 3 or (critical_protected >= 1 and high_protected >= 2):
        compliance_status = "Excellent - Strong PII protection applied"
    elif critical_protected >= 1 or high_protected >= 3:
        compliance_status = "Good - Adequate protection for sensitive data"
    elif high_protected >= 1 or medium_protected >= 3:
        compliance_status = "Fair - Basic protection applied"
    else:
        compliance_status = "Limited - Consider additional masking"
    
    # Generate recommendations
    recommendations = []
    
    if critical_protected > 0:
        recommendations.append(f"✅ {critical_protected} critical PII entities protected (complies with Indian privacy laws)")
    
    if high_protected > 0:
        recommendations.append(f"🔒 {high_protected} high-risk entities masked for enhanced privacy")
    
    if total_redacted >= 5:
        recommendations.append("🛡️ Comprehensive protection - document should be safe for intended use")
    elif total_redacted >= 2:
        recommendations.append("📋 Moderate protection - review for additional masking needs")
    else:
        recommendations.append("⚠️ Minimal redaction - consider masking more entities")
    
    # Purpose-specific recommendations
    if purpose:
        purpose_lower = purpose.lower()
        if "public" in purpose_lower or "social" in purpose_lower:
            recommendations.append("🌐 For public sharing: Consider maximum protection")
        elif any(keyword in purpose_lower for keyword in ["loan", "kyc", "banking", "financial"]):
            recommendations.append("💰 For financial use: Ensure regulatory compliance")
        elif "job" in purpose_lower or "resume" in purpose_lower:
            recommendations.append("💼 For employment: Keep only necessary contact info")
    
    main_recommendation = " | ".join(recommendations) if recommendations else "Review redaction completeness based on intended use"
    
    return {
        "total_redacted": total_redacted,
        "entities_redacted": entity_counts,
        "risk_levels_protected": risk_levels,
        "purpose": purpose or "unknown",
        "recommendation": main_recommendation,
        "privacy_score": privacy_score,
        "compliance_status": compliance_status,
        "critical_entities_protected": critical_protected,
        "sensitive_entities_protected": high_protected
    }