# layers/layer2_decide.py — SIMPLIFIED Risk Assessment (No Purpose Logic)
# Production-ready with clear risk levels and regulatory compliance focus

from typing import Any, Dict, List, Optional, Set, Tuple
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Comprehensive entity mapping with Hindi translations
ENTITY_LABELS = {
    "AADHAAR": "Aadhaar Number (आधार संख्या)",
    "PAN": "PAN Number (पैन नंबर)",
    "PASSPORT": "Passport Number (पासपोर्ट संख्या)",
    "DRIVING_LICENSE": "Driving License Number (ड्राइविंग लाइसेंस)",
    "VOTER_ID": "Voter ID Number (मतदाता पहचान)",
    "BANK_ACCOUNT": "Bank Account Number (बैंक खाता संख्या)",
    "IFSC": "Bank IFSC Code (आईएफएससी कोड)",
    "MOBILE_NUMBER": "Mobile Number (मोबाइल नंबर)",
    "EMAIL_ADDRESS": "Email Address (ईमेल पता)",
    "CREDIT_CARD": "Credit Card Number (क्रेडिट कार्ड)",
    "NAME": "Person Name (व्यक्ति का नाम)",
    "DATE_TIME": "Date/Time Information (दिनांक/समय)",
    "LOCATION": "Address/Location (पता/स्थान)",
    "ORGANIZATION": "Organization Name (संस्था का नाम)",
    "FINANCIAL_INFO": "Financial Information (वित्तीय जानकारी)",
}

# Simplified risk level definitions based on Indian regulations
RISK_LEVELS = {
    "Critical": "Highly sensitive under Indian law - Heavy penalties for misuse",
    "High": "Sensitive personal information - Privacy risk if shared",
    "Medium": "Personal information - Standard protection needed",
    "Low": "General information - Minimal protection required"
}

# Indian regulatory compliance mappings (for user education)
REGULATORY_INFO = {
    "AADHAAR": {
        "risk": "Critical",
        "law": "Aadhaar Act 2016, UIDAI Guidelines",
        "penalty": "Up to ₹1 crore fine + 3 years imprisonment",
        "sharing": "Restricted - only for authorized purposes"
    },
    "PAN": {
        "risk": "Critical", 
        "law": "Income Tax Act 1961, CBDT Guidelines",
        "penalty": "Heavy penalties for unauthorized use",
        "sharing": "Required for financial transactions above ₹50,000"
    },
    "PASSPORT": {
        "risk": "Critical",
        "law": "Passport Act 1967",
        "penalty": "Legal action for misuse",
        "sharing": "Highly sensitive travel document"
    },
    "DRIVING_LICENSE": {
        "risk": "High",
        "law": "Motor Vehicles Act 1988",
        "penalty": "Identity fraud risk",
        "sharing": "Contains personal and address information"
    },
    "VOTER_ID": {
        "risk": "High",
        "law": "Representation of People Act 1951",
        "penalty": "Identity fraud risk", 
        "sharing": "Government-issued photo ID"
    },
    "BANK_ACCOUNT": {
        "risk": "Critical",
        "law": "Banking Regulation Act 1949, RBI Guidelines",
        "penalty": "Financial fraud and unauthorized access",
        "sharing": "Never share without encryption"
    },
    "IFSC": {
        "risk": "High",
        "law": "RBI Guidelines",
        "penalty": "Combined with account details enables fraud",
        "sharing": "Banking routing information"
    },
    "CREDIT_CARD": {
        "risk": "Critical",
        "law": "RBI Guidelines, IT Act 2000",
        "penalty": "Direct financial fraud risk",
        "sharing": "Never share - immediate fraud risk"
    },
    "MOBILE_NUMBER": {
        "risk": "Medium",
        "law": "TRAI Guidelines, IT Act 2000", 
        "penalty": "Spam, harassment, OTP fraud",
        "sharing": "Used for verification and contact"
    },
    "EMAIL_ADDRESS": {
        "risk": "Medium",
        "law": "IT Act 2000",
        "penalty": "Spam, phishing attacks",
        "sharing": "Primary communication channel"
    },
    "NAME": {
        "risk": "Low",
        "law": "Privacy considerations",
        "penalty": "Combined with other data increases risk",
        "sharing": "Generally acceptable for identification"
    },
    "DATE_TIME": {
        "risk": "Medium",
        "law": "Privacy considerations",
        "penalty": "Birth date used for identity verification",
        "sharing": "Can be sensitive depending on context"
    },
    "LOCATION": {
        "risk": "Medium",
        "law": "Privacy considerations", 
        "penalty": "Physical security and privacy risk",
        "sharing": "Address information can enable stalking"
    },
    "ORGANIZATION": {
        "risk": "Low",
        "law": "Corporate privacy policies",
        "penalty": "Minimal direct risk",
        "sharing": "Generally acceptable business information"
    }
}

def assess_entity_risk(entity: str) -> Dict[str, Any]:
    """
    Simplified risk assessment focused on regulatory compliance
    
    Args:
        entity: The detected entity type
        
    Returns:
        Dict with risk level, regulatory info, and user-friendly explanation
    """
    if not entity:
        return {
            "risk": "Low",
            "explanation": "No entity provided",
            "regulatory_info": None,
            "user_warning": None
        }
    
    # Get regulatory information
    reg_info = REGULATORY_INFO.get(entity, {
        "risk": "Medium",
        "law": "General privacy guidelines",
        "penalty": "Privacy risk if shared inappropriately", 
        "sharing": "Consider carefully before sharing"
    })
    
    risk_level = reg_info["risk"]
    
    # Generate user-friendly explanations
    explanations = {
        "AADHAAR": "🚨 CRITICAL: Aadhaar sharing is heavily restricted by UIDAI. Unauthorized use can result in ₹1 crore fine.",
        "PAN": "🚨 CRITICAL: PAN contains sensitive tax information. Misuse can lead to financial fraud and legal issues.",
        "PASSPORT": "🚨 CRITICAL: Passport is a primary identity document. Sharing can enable identity theft.",
        "BANK_ACCOUNT": "🚨 CRITICAL: Bank account details enable direct financial fraud. Never share without encryption.",
        "CREDIT_CARD": "🚨 CRITICAL: Credit card numbers enable immediate financial fraud. Extremely dangerous to share.",
        "DRIVING_LICENSE": "⚠️ HIGH RISK: Contains photo, address, and personal details. Can be used for identity fraud.",
        "VOTER_ID": "⚠️ HIGH RISK: Government-issued photo ID with address. Can be misused for verification fraud.",
        "IFSC": "⚠️ HIGH RISK: Banking routing code. Combined with account details enables unauthorized transfers.",
        "MOBILE_NUMBER": "📱 MEDIUM RISK: Can be used for OTP fraud, harassment, and spam. Consider masking.",
        "EMAIL_ADDRESS": "📧 MEDIUM RISK: Primary contact method. Can be used for phishing and spam attacks.",
        "DATE_TIME": "📅 MEDIUM RISK: Birth dates are used for identity verification. Can aid in fraud.",
        "LOCATION": "📍 MEDIUM RISK: Address information can be used for stalking and identity verification.",
        "NAME": "👤 LOW RISK: Generally safe but can be combined with other data for identity theft.",
        "ORGANIZATION": "🏢 LOW RISK: Company names are usually public information with minimal privacy risk."
    }
    
    explanation = explanations.get(entity, "Consider privacy implications before sharing this information.")
    
    # Generate user warnings for critical entities
    user_warnings = {
        "AADHAAR": "⚖️ LEGAL WARNING: Sharing Aadhaar may violate UIDAI guidelines",
        "PAN": "⚖️ LEGAL WARNING: PAN misuse can result in legal action",
        "PASSPORT": "⚖️ LEGAL WARNING: Passport fraud is a serious criminal offense",
        "BANK_ACCOUNT": "💰 FRAUD WARNING: Can enable unauthorized bank transactions",
        "CREDIT_CARD": "💳 FRAUD WARNING: Immediate financial fraud risk"
    }
    
    return {
        "risk": risk_level,
        "explanation": explanation,
        "regulatory_info": reg_info,
        "user_warning": user_warnings.get(entity),
        "entity_label": ENTITY_LABELS.get(entity, entity)
    }

def get_risk_summary(detections: List[Dict]) -> Dict[str, Any]:
    """
    Generate comprehensive risk summary without purpose logic
    
    Args:
        detections: List of detected entities
        
    Returns:
        Risk summary with counts, warnings, and recommendations
    """
    if not detections:
        return {
            "total_entities": 0,
            "risk_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "recommendation": "✅ No PII detected - document appears safe for sharing",
            "critical_entities": [],
            "regulatory_alerts": [],
            "overall_risk": "Safe"
        }
    
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    critical_entities = []
    regulatory_alerts = []
    entity_details = []
    
    for detection in detections:
        entity = detection.get("entity", "")
        assessment = assess_entity_risk(entity)
        risk = assessment.get("risk", "Medium")
        
        if risk in risk_counts:
            risk_counts[risk] += 1
        
        if risk == "Critical":
            critical_entities.append(entity)
            
        # Add regulatory alerts for high-risk entities
        if assessment.get("user_warning"):
            regulatory_alerts.append(assessment["user_warning"])
            
        entity_details.append({
            "entity": entity,
            "risk": risk,
            "explanation": assessment.get("explanation", ""),
            "count": 1  # Individual detection
        })
    
    total = len(detections)
    
    # Determine overall risk level
    if risk_counts["Critical"] > 0:
        overall_risk = "Critical"
    elif risk_counts["High"] > 2:
        overall_risk = "High"  
    elif risk_counts["High"] > 0 or risk_counts["Medium"] > 3:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"
    
    # Generate recommendation based on overall risk
    recommendations = {
        "Critical": f"🚨 CRITICAL RISK: {risk_counts['Critical']} highly sensitive entities detected. These are protected by Indian law. Consider masking all critical entities before sharing.",
        "High": f"⚠️ HIGH RISK: {risk_counts['High']} sensitive entities detected. Strong recommendation to mask sensitive information before sharing.",
        "Medium": f"📊 MODERATE RISK: Document contains personal information. Review and mask as needed based on your sharing context.",
        "Low": f"✅ LOW RISK: Minimal sensitive information detected. Generally safe with standard privacy precautions."
    }
    
    return {
        "total_entities": total,
        "risk_counts": risk_counts,
        "recommendation": recommendations.get(overall_risk, "Review detected entities carefully."),
        "critical_entities": critical_entities,
        "regulatory_alerts": list(set(regulatory_alerts)),  # Remove duplicates
        "overall_risk": overall_risk,
        "entity_details": entity_details
    }

def get_masking_recommendations() -> Dict[str, Dict]:
    """
    Get masking recommendations for different scenarios
    
    Returns:
        Dict with masking strategies for different use cases
    """
    return {
        "maximum_protection": {
            "name": "🛡️ Maximum Protection",
            "description": "Mask all detected PII for public sharing or maximum privacy",
            "entities": list(ENTITY_LABELS.keys()),
            "use_case": "Social media, public websites, untrusted sharing"
        },
        "high_risk_only": {
            "name": "🚨 High-Risk Only", 
            "description": "Mask only critical and high-risk entities (Government IDs, Financial info)",
            "entities": ["AADHAAR", "PAN", "PASSPORT", "DRIVING_LICENSE", "VOTER_ID", "BANK_ACCOUNT", "IFSC", "CREDIT_CARD"],
            "use_case": "Internal documents, trusted sharing, business use"
        },
        "financial_protection": {
            "name": "💰 Financial Protection",
            "description": "Mask financial and government IDs only",
            "entities": ["AADHAAR", "PAN", "BANK_ACCOUNT", "IFSC", "CREDIT_CARD"],
            "use_case": "Professional documents, resumes, applications"
        },
        "contact_privacy": {
            "name": "📱 Contact Privacy",
            "description": "Mask contact information and keep identity documents",
            "entities": ["MOBILE_NUMBER", "EMAIL_ADDRESS", "LOCATION"],
            "use_case": "When identity verification needed but contact privacy desired"
        }
    }

def validate_entity_format(entity: str, detected_text: str) -> bool:
    """Enhanced validation for detected entities"""
    try:
        if entity == "AADHAAR":
            clean_text = re.sub(r'[\s-]', '', detected_text)
            return len(clean_text) == 12 and clean_text.isdigit()
        
        elif entity == "PAN":
            clean_text = re.sub(r'[\s-]', '', detected_text.upper())
            return bool(re.match(r'^[A-Z]{5}\d{4}[A-Z]$', clean_text))
        
        elif entity == "IFSC":
            clean_text = detected_text.upper().replace(' ', '')
            return bool(re.match(r'^[A-Z]{4}0[A-Z0-9]{6}$', clean_text))
        
        elif entity == "MOBILE_NUMBER":
            clean_text = re.sub(r'[\s\-\+]', '', detected_text)
            if clean_text.startswith('91'):
                clean_text = clean_text[2:]
            return len(clean_text) == 10 and clean_text[0] in '6789'
        
        elif entity == "CREDIT_CARD":
            # Basic length check - full Luhn validation is in Layer 1
            clean_text = re.sub(r'[\s-]', '', detected_text)
            return len(clean_text) in [15, 16] and clean_text.isdigit()
        
        return True  # For other entities, assume valid
        
    except Exception:
        return False

def get_entity_display_info(entity: str, count: int = 1) -> Dict[str, str]:
    """Get display information for entities in UI"""
    assessment = assess_entity_risk(entity)
    risk_icons = {
        "Critical": "🚨",
        "High": "⚠️", 
        "Medium": "📊",
        "Low": "ℹ️"
    }
    
    risk = assessment.get("risk", "Medium")
    icon = risk_icons.get(risk, "📋")
    label = ENTITY_LABELS.get(entity, entity)
    
    count_text = f" ({count})" if count > 1 else ""
    
    return {
        "display_name": f"{icon} {label}{count_text}",
        "risk_level": risk,
        "explanation": assessment.get("explanation", ""),
        "warning": assessment.get("user_warning", "")
    }