# app.py — PII Guardian SIMPLIFIED | Clean Professional UI - FIXED VERSION
# All UI issues resolved - clean, consistent, and professional
import streamlit as st
from pathlib import Path
import logging
from typing import Dict, List, Any
import plotly.graph_objects as go
import plotly.express as px
# Import enhanced layers
from layers.layer1_detect import analyze_document, detect_filetype
from layers.layer2_decide import (
    assess_entity_risk,
    get_risk_summary,
    get_masking_recommendations,
    get_entity_display_info,
    ENTITY_LABELS
)
from layers.layer3_act import (
    mask_text_output,
    redact_pdf_output,
    redact_image_output,
    create_redaction_report
)
# Configure logging
logging.basicConfig(level=logging.INFO)
# ================ PAGE CONFIGURATION ================
st.set_page_config(
    page_title="PII Guardian | CipherX",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'About': "Advanced PII Detection & Protection System"
    }
)
# ================ CONSTANTS & STYLING ================
RISK_COLORS = {
    "Critical": "#FF4B4B",
    "High": "#FF6B35", 
    "Medium": "#FFA726",
    "Low": "#4CAF50"
}
# 🎯 CLEAN PROFESSIONAL DARK THEME - FIXED VERSION
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    .block-container {
        padding-top: 1rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }
    .stFileUploader > div::before,
    .stFileUploader > div::after {
        display: none !important;
    }
    /* Fix upload box - solid red border */
    .stFileUploader > div {
        border-radius: 8px !important;
        text-align: left !important;
	border-bottom: 2px grey solid;
	margin-bottom: 12px;
    }

    /* Center metrics */
    [data-testid="metric-container"] {
        background-color: #262730;
        border: 1px solid #404040;
        border-radius: 8px;
        padding: 1.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center !important;
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
        justify-content: center !important;
    }  
    [data-testid="metric-container"] [data-testid="metric-value"] {
        color: #fafafa;
        font-size: 2.2rem !important;
        font-weight: 700 !important;
        text-align: center !important;
        margin-bottom: 0.3rem !important;
    }  
    [data-testid="metric-container"] [data-testid="metric-label"] {
        color: #b3b3b3;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        text-align: center !important;
        white-space: nowrap !important;
    }
    /* Risk right side formatting */
    .risk-metric-card {
        background-color: #262730;
        border: 1px solid #404040;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .risk-metric-value {
        font-size: 2rem !important;
        font-weight: 700 !important;
        margin-bottom: 0.3rem !important;
    }
    .risk-metric-label {
        font-size: 0.9rem !important;
        font-weight: 600 !important;
        color: #b3b3b3 !important;
    }
    /* Sidebar styling */
    .css-1d391kg {
        background-color: #262730;
        border-right: 1px solid #404040;
    }
    .css-1d391kg .stMarkdown h3 {
        color: #fafafa;
        font-weight: 600;
        font-size: 1.1rem;
        margin-bottom: 1rem;
    }
    .css-1d391kg .stMarkdown, 
    .css-1d391kg .stSelectbox label,
    .css-1d391kg .stSlider label,
    .css-1d391kg .stCheckbox label {
        color: #fafafa !important;
        font-weight: 500;
    }
    /* Headers & subheaders */
    h1 {
        color: #fafafa;
        font-weight: 700;
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
        text-align: center;
    }
    h3 {
        color: #fafafa;
        font-weight: 600;
        font-size: 1.3rem;
        margin: 1.5rem 0 1rem 0;
        border-bottom: 2px solid #404040;
        padding-bottom: 0.5rem;
    }
    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #262730;
        border-radius: 8px;
        padding: 0.25rem;
        border: 1px solid #404040;
        gap: 0.25rem;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        color: #b3b3b3;
        border-radius: 6px;
        font-weight: 500;
        padding: 0.5rem 1rem;
        border: none;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        background-color: #1f4e79;
        color: #fafafa;
        font-weight: 600;
    }
    .stTabs [data-baseweb="tab"]:hover {
        background-color: #404040;
        color: #fafafa;
    }
    /* Inputs */
    .stTextInput input, .stTextArea textarea {
        background-color: #262730 !important;
        color: #fafafa !important;
        border: 1px solid #404040 !important;
        border-radius: 6px !important;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #1f4e79 !important;
        box-shadow: 0 0 0 1px #1f4e79 !important;
    }
    /* Button fix: centered and sized */
    .stButton button {
        background-color: #1f4e79 !important;
        color: #fafafa !important;
        border: 1px solid #1f4e79 !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        padding: 0.7rem 2rem !important;
        transition: all 0.2s ease !important;
        min-width: 200px !important;
        max-width: 400px !important;
        width: auto !important;
        margin: 0 auto !important;
        display: block !important;
    }
    .stButton button:hover {
        background-color: #2d5aa0 !important;
        border-color: #2d5aa0 !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 8px rgba(31, 78, 121, 0.3) !important;
    }
    .stButton {
        text-align: center !important;
        display: flex !important;
        justify-content: center !important;
    }
    /* Checkbox styling for protection selection */
    .protection-checkbox {
        background-color: #262730;
        border: 1px solid #404040;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        transition: all 0.2s ease;
    }
    .protection-checkbox:hover {
        border-color: #1f4e79;
        background-color: #2a2d3a;
    }
    .protection-checkbox.selected {
        border-color: #1f4e79;
        background-color: #1a3a4d;
    }
    /* Rest styling for selects, sliders, alerts, expander and footer as previously described */
    .stCheckbox label, .stSelectbox > div > div, .stSlider .thumb, .stSlider .track, .stAlert, .stSuccess, .stError, .stWarning, .stInfo, .streamlit-expanderHeader, .streamlit-expanderContent, .stDownloadButton button, .js-plotly-plot, .stSpinner > div, .stProgress .st-bo, #MainMenu, footer, .stDeployButton, ::-webkit-scrollbar, ::-webkit-scrollbar-track, ::-webkit-scrollbar-thumb, ::-webkit-scrollbar-thumb:hover, .detection-card, .detection-card:hover, .detection-card.risk-critical, .detection-card.risk-high, .detection-card.risk-medium, .detection-card.risk-low, .stMarkdown p, .stMarkdown strong, .stMarkdown em, .stCode, .footer-content, .footer-heart { /* same as prior css */ }\n</style>\n""", unsafe_allow_html=True)
# ================ HEADER ================
st.title("🛡️ PII Guardian — Detect • Decide • Act")
st.markdown("---")
# ================ SIDEBAR SETTINGS ================
with st.sidebar:
    st.markdown("## 🔧 Detection Settings")
    score_threshold = st.slider(
        "Detection Sensitivity",
        min_value=0.0, max_value=1.0, value=0.2, step=0.05,
        help="Lower = more detections, Higher = only high-confidence matches"
    )
    force_ocr = st.checkbox(
        "Force OCR for Images/PDFs", 
        value=False,
        help="Force OCR processing for scanned documents"
    )
    st.markdown('---')
    st.markdown("## 🎨 Advanced Options")
    with st.expander("Masking Settings", expanded=True):
        use_smart_masking = st.checkbox(
            "Smart Partial Masking", 
            value=True,
            help="Show last few digits (e.g., XXXX-XXXX-1234)"
        )
        mask_style = st.selectbox(
            "Masking Style",
            ["standard", "redacted", "smart", "minimal"],
            help="Visual style for masked content"
        )
        redaction_color = st.color_picker(
            "Redaction Color", 
            "#000000",
            help="Color for PDF/image redactions"
        )
# ================ MAIN INTERFACE ================
st.markdown("## 📤 Upload Document or Enter Text")
tab_upload, tab_text = st.tabs(["📄 Upload File", "📝 Paste Text"])
uploaded_file = None
text_input = None
with tab_upload:
    uploaded_file = st.file_uploader(
        "Choose a file to analyze for PII",
        type=['pdf', 'png', 'jpg', 'jpeg', 'txt', 'docx'],
        help="Supports PDF, images, text files, and Word documents"
    )
    if uploaded_file:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("📄 File", uploaded_file.name.split('.')[0][:20] + "...")
        with col2:
            st.metric("📋 Type", uploaded_file.type.split('/')[-1].upper())
        with col3:
            st.metric("📏 Size", f"{uploaded_file.size / 1024:.1f} KB")
with tab_text:
    text_input = st.text_area(
        "Paste your text content here",
        height=200,
        placeholder="Paste content to scan for Indian PII (Aadhaar, PAN, Passport, Mobile, Email, etc.)",
        help="Supports English and Hindi text"
    )
# ================ INFORMATION PANEL ================
with st.expander("🇮🇳 What We Detect - Indian PII Catalog"):
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        **🚨 Critical Risk**
        - Aadhaar Numbers
        - PAN Numbers  
        - Passport Numbers
        - Bank Account Numbers
        - Credit Card Numbers
        """)
    with col2:
        st.markdown("""
        **⚠️ High Risk**
        - Driving License Numbers
        - Voter ID Numbers
        - IFSC Codes
        - Mobile Numbers
        - Email Addresses
        """)
    with col3:
        st.markdown("""
        **📊 Medium/Low Risk**
        - Person Names
        - Addresses & Locations
        - Date/Time Information
        - Organization Names
        
        **🤖 AI:** Presidio + spaCy + Custom
        """)
# ================ PROCESSING LOGIC ================
if not uploaded_file and not (text_input and text_input.strip()):
    st.info("💡 Upload a file or paste text to start AI-powered PII scanning")
    st.stop()
if uploaded_file:
    filename = uploaded_file.name
    file_bytes = uploaded_file.read()
    filetype = detect_filetype(file_bytes)
    st.info(f"📄 Detected file type: **{filetype.upper()}**")
else:
    filename = "pasted_text.txt"
    file_bytes = text_input.encode("utf-8")
    filetype = "text"
with st.spinner("🤖 Analyzing with Multi-AI engines..."):
    try:
        analysis_result = analyze_document(
            file_bytes=file_bytes,
            filename=filename,
            force_ocr=force_ocr,
            allowed_entities=None,
            score_threshold=score_threshold,
            use_advanced_ai=True
        )
    except Exception as e:
        st.error(f"❌ Analysis failed: {str(e)}")
        st.stop()
detections = analysis_result.get("detections", [])
full_text = analysis_result.get("text", "")
page_infos = analysis_result.get("page_infos", [])
ocr_used = analysis_result.get("ocr_used", False)
filtered_detections = [d for d in detections if d.get("score", 0) >= score_threshold]
st.markdown("### 📊 AI Detection Results")
if not filtered_detections:
    st.success("✅ No PII detected! Document appears safe for sharing.")
    st.balloons()
    st.stop()
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🔍 Total Detections", len(filtered_detections))
with col2:
    unique_types = len(set(d["entity"] for d in filtered_detections))
    st.metric("📋 Entity Types", unique_types)
with col3:
    ai_sources = set(d.get("source", "Unknown") for d in filtered_detections)
    st.metric("🤖 AI Models Used", len(ai_sources))
with col4:
    st.metric("🔬 OCR Used", "Yes" if ocr_used else "No")
assessed_detections = []
for detection in filtered_detections:
    entity = detection.get("entity", "")
    assessment = assess_entity_risk(entity)
    
    assessed_detections.append({
        **detection,
        "risk": assessment.get("risk", "Medium"),
        "explanation": assessment.get("explanation", ""),
    })
risk_summary = get_risk_summary(filtered_detections)
st.markdown("### 🎯 Risk Assessment")
risk_counts = risk_summary.get("risk_counts", {})
col1, col2 = st.columns([3, 1])
with col1:
    if any(risk_counts.values()):
        fig = go.Figure(data=[
            go.Bar(
                x=list(risk_counts.keys()),
                y=list(risk_counts.values()),
                marker_color=[RISK_COLORS.get(risk, "#888888") for risk in risk_counts.keys()],
                text=list(risk_counts.values()),
                textposition="outside"
            )
        ])
        fig.update_layout(
            title="Risk Level Distribution",
            xaxis_title="Risk Level",
            yaxis_title="Count",
            height=300,
            showlegend=False,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#fafafa'
        )
        st.plotly_chart(fig, use_container_width=True)
with col2:
    for risk_level, count in risk_counts.items():
        if count > 0:
            border_color = RISK_COLORS.get(risk_level, '#888888')
            st.markdown(f"""
            <div style="
                display: flex;
                align-items: center;
                background-color: #262730;
                border-left: 5px solid {border_color};
                padding: 10px;
                margin: 5px 0;
                border-radius: 6px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.2);
                font-family: 'Inter', sans-serif;
                text-align: center;
            ">
                <div style="flex-grow: 1;">
                    <div style="color: {border_color}; font-size: 1.4rem; font-weight: 700;">{count}</div>
                    <div style="color: #b3b3b3; font-size: 0.85rem; font-weight: 500;">{risk_level} Risk</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
recommendation = risk_summary.get("recommendation", "")
overall_risk = risk_summary.get("overall_risk", "Medium")
if overall_risk == "Critical":
    st.error(f"🚨 {recommendation}")
elif overall_risk == "High":
    st.warning(f"⚠️ {recommendation}")
else:
    st.info(f"📊 {recommendation}")
st.markdown("### ⚡ Choose Protection Level")
masking_options = get_masking_recommendations()
col1, col2 = st.columns(2)
with col1:
    st.markdown("**Select protection options:**")
    protection_options = {
        "maximum_protection": "🛡️ Maximum Protection (All PII)",
        "high_risk_only": "🚨 High-Risk Only (Govt & Financial)",
        "financial_protection": "💰 Financial Protection",
        "contact_privacy": "📱 Contact Privacy",
        "custom": "⚙️ Custom Selection"
    }

    # radio button for single selection
    masking_strategy = st.radio(
        "Choose a protection strategy:",
        options=list(protection_options.keys()),
        format_func=lambda x: protection_options[x],
        index=0  # default: maximum_protection
    )

with col2:
    # yahan spacer de diya
    st.write("")  
    st.write("")  # jitna zyada likhega utna neeche jaayega

    if masking_strategy != "custom":
        strategy_info = masking_options[masking_strategy]
        st.info(f"**{strategy_info['name']}**\n\n{strategy_info['description']}")
        entities_to_mask = strategy_info['entities']
        mask_spans = [
            {"start": d["start"], "end": d["end"], "entity": d["entity"]} 
            for d in assessed_detections if d["entity"] in entities_to_mask
        ]
    else:
        st.info("Select specific entity types below.")


if masking_strategy == "custom":
    st.markdown("#### ⚙️ Custom Entity Selection")
    entity_options = {}
    for detection in assessed_detections:
        entity = detection["entity"]
        risk = detection.get("risk", "Medium")
        if risk not in entity_options:
            entity_options[risk] = set()
        entity_options[risk].add(entity)

    selected_entities = []

    # Loop through each risk level and create an expander for it
    for risk_level in ["Critical", "High", "Medium", "Low"]:
        if risk_level in entity_options:
            with st.expander(f"{risk_level} Risk Entities", expanded=(risk_level in ["Critical", "High"])):
                cols = st.columns(2)
                entities_sorted = sorted(entity_options[risk_level])
                for i, entity in enumerate(entities_sorted):
                    with cols[i % 2]:
                        entity_info = get_entity_display_info(entity)
                        count = len([d for d in assessed_detections if d["entity"] == entity])
                        checked = (risk_level in ["Critical", "High"])
                        if st.checkbox(
                            f"{entity_info['display_name']} ({count})",
                            value=checked,
                            key=f"mask_{entity}"
                        ):
                            selected_entities.append(entity)

    mask_spans = [
        {"start": d["start"], "end": d["end"], "entity": d["entity"]}
        for d in assessed_detections if d["entity"] in selected_entities
    ]

if mask_spans:
    masked_entities = set(ENTITY_LABELS.get(s["entity"], s["entity"]) for s in mask_spans)
    st.success(f"📋 **Will protect:** {', '.join(sorted(masked_entities))}")
else:
    st.warning("⚠️ No entities selected for protection.")
if mask_spans:
    st.markdown("### 🔒 Apply Protection")
    try:
        hex_color = redaction_color.lstrip('#')
        rgb_tuple = tuple(int(hex_color[i:i+2], 16)/255.0 for i in (0, 2, 4))
    except:
        rgb_tuple = (0, 0, 0)
    if filetype == "pdf":
        # Add vertical spacing before the button
        st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
        if st.button("📄 Apply PDF Redaction", type="primary"):
            with st.spinner("Applying PDF redaction..."):
                redacted_pdf, status = redact_pdf_output(
                    file_bytes, full_text, page_infos, mask_spans, rgb_tuple
                )
                if redacted_pdf:
                    st.success("✅ PDF redaction completed!")
                    st.info(status)
                    st.download_button(
                        "📥 Download Protected PDF",
                        redacted_pdf,
                        f"{Path(filename).stem}_protected.pdf",
                        "application/pdf",
                        use_container_width=True
                    )
                else:
                    st.error(f"❌ Redaction failed: {status}")
    elif filetype == "image":
        col1, col2 = st.columns([2, 1])
        with col1:
            redaction_style = st.selectbox(
                "Redaction style:",
                ["black_box", "blur", "pixelate"],
                format_func=lambda x: {
                    "black_box": "⬛ Black Box",
                    "blur": "🌫️ Blur Effect", 
                    "pixelate": "🔲 Pixelate"
                }.get(x, x)
            )
        with col2:
            # Add vertical spacing before the button
            st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
            apply_btn = st.button("🖼️ Apply Redaction", type="primary")
        if apply_btn:
            with st.spinner("Applying image redaction..."):
                page_info = page_infos[0] if page_infos else {"text": full_text, "ocr_words": []}
                redacted_img, status = redact_image_output(
                    file_bytes, page_info, mask_spans, redaction_style
                )
                if redacted_img:
                    st.success("✅ Image redaction completed!")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Original:**")
                        st.image(file_bytes, use_column_width=True)
                    with col2:
                        st.markdown("**Protected:**")
                        st.image(redacted_img, use_column_width=True)
                    st.download_button(
                        "📥 Download Protected Image",
                        redacted_img,
                        f"{Path(filename).stem}_protected.png",
                        "image/png",
                        use_container_width=True
                    )
                else:
                    st.error(f"❌ Redaction failed: {status}")
    else:
        # Add vertical spacing before the button
        st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
        if st.button("📝 Apply Text Masking", type="primary"):
            with st.spinner("Applying text masking..."):
                try:
                    masked_text, report = mask_text_output(
                        full_text, mask_spans, use_smart_masking, mask_style
                    )
                    st.success("✅ Text masking completed!")
                    successful = report.get("successful_masks", 0)
                    if successful > 0:
                        st.info(f"📊 Protected {successful} entities")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Original Text:**")
                        preview = full_text[:800] + "..." if len(full_text) > 800 else full_text
                        st.text_area("", preview, height=200, disabled=True, key="orig")
                    with col2:
                        st.markdown("**Protected Text:**")
                        preview = masked_text[:800] + "..." if len(masked_text) > 800 else masked_text
                        st.text_area("", preview, height=200, disabled=True, key="mask")
                    st.download_button(
                        "📥 Download Protected Text",
                        masked_text.encode("utf-8"),
                        f"{Path(filename).stem}_protected.txt",
                        "text/plain",
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"❌ Masking failed: {str(e)}")
# ================ FOOTER ================
st.markdown("---")
st.markdown("""
<div class="footer-content" style="text-align:center;">
    <p><strong>🛡️ PII Guardian</strong> — Advanced Privacy Protection System</p>
    <p>Made with <span class="footer-heart">❤️</span> by <strong>CipherX</strong> to protect your PII</p>
    <p><em>🇮🇳 India | 🤖 Multi-AI | 🔒 Enterprise Security</em></p>
</div>
""", unsafe_allow_html=True)
