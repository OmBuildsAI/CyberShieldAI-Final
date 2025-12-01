import streamlit as st
from PIL import Image
import datetime

# Page configuration with dark theme
st.set_page_config(
    page_title="🛡️ CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark theme CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #00d4ff;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
    }
    .feature-card {
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #00d4ff;
        background-color: #1e1e1e;
        margin-bottom: 1rem;
        color: white;
    }
    .safe-result {
        background-color: #1a472a;
        color: #00ff88;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #00ff88;
    }
    .suspicious-result {
        background-color: #4a3c00;
        color: #ffd700;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #ffd700;
    }
    .dangerous-result {
        background-color: #5a1a1a;
        color: #ff4444;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #ff4444;
    }
    .stApp {
        background-color: #0e1117;
    }
</style>
""", unsafe_allow_html=True)

# Import utility functions
try:
    from utils.url_analyzer import check_phishing
    from utils.qr_scanner import scan_qr_code
    from utils.deepfake_check import detect_deepfake, detect_deepfake_video
except ImportError as e:
    st.error(f"Error importing modules: {e}")
    st.info("Please make sure all utility files are properly set up.")
    def check_phishing(url): return {"status": "Safe", "message": "Demo mode", "confidence": 80}
    def scan_qr_code(image_file): return {"qr_found": False, "message": "Demo mode"}
    def detect_deepfake(image_file): return {"is_real": True, "confidence": 75, "message": "Demo mode"}
    def detect_deepfake_video(video_file): return {"is_real": True, "confidence": 75, "message": "Demo mode"}

# Initialize session state
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# Sidebar
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/3063/3063817.png", width=80)
    st.title("CyberShield AI")
    st.markdown("---")
    
    # Navigation
    st.subheader("🔍 Navigation")
    page = st.radio("Go to:", ["URL Analyzer", "QR Scanner", "Deepfake Detector", "About"])
    
    st.markdown("---")
    
    # Statistics
    st.subheader("📊 Statistics")
    scans = st.session_state.scan_history
    total_scans = len(scans)
    url_scans = len([h for h in scans if h['type'] == 'url'])
    qr_scans = len([h for h in scans if h['type'] == 'qr'])
    deepfake_scans = len([h for h in scans if h['type'] == 'deepfake'])
    
    st.metric("Total Scans", total_scans)
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("URL", url_scans)
    with col2: st.metric("QR", qr_scans)
    with col3: st.metric("Deepfake", deepfake_scans)

# Main content
st.markdown('<div class="main-header">🛡️ CyberShield AI</div>', unsafe_allow_html=True)
st.markdown("### Your Complete 3-in-1 Cybersecurity Solution")
st.markdown("---")

if page == "URL Analyzer":
    st.header("🔗 URL Phishing Detector")
    st.markdown('<div class="feature-card">Analyze URLs for phishing attempts and suspicious patterns</div>', unsafe_allow_html=True)
    
    url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    col1, col2 = st.columns([3, 1])
    with col1: analyze_btn = st.button("🔍 Analyze URL", type="primary", use_container_width=True)
    with col2: clear_btn = st.button("🧹 Clear", use_container_width=True)
    
    if clear_btn: st.rerun()
    
    if analyze_btn and url:
        with st.spinner("🛡️ Analyzing URL for phishing patterns..."):
            result = check_phishing(url)
        
        # Display results
        if result['status'] == 'Safe':
            st.markdown(f'<div class="safe-result"><h4>✅ SAFE</h4>Confidence: {result["confidence"]}%<br>{result["message"]}</div>', unsafe_allow_html=True)
        elif result['status'] == 'Suspicious':
            st.markdown(f'<div class="suspicious-result"><h4>⚠️ SUSPICIOUS</h4>Confidence: {result["confidence"]}%<br>{result["message"]}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="dangerous-result"><h4>🚨 DANGEROUS</h4>Confidence: {result["confidence"]}%<br>{result["message"]}</div>', unsafe_allow_html=True)
        
        # Add to history
        st.session_state.scan_history.append({
            'type': 'url', 'input': url, 'result': result['status'],
            'confidence': result['confidence'], 'time': datetime.datetime.now()
        })

elif page == "QR Scanner":
    st.header("📱 QR Code Scanner")
    st.markdown('<div class="feature-card">Scan QR codes and analyze extracted content for safety</div>', unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader("Upload QR Code Image", type=['png', 'jpg', 'jpeg'])
    
    if uploaded_file:
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded QR Code", use_container_width=True)
        
        if st.button("🔍 Scan QR Code", type="primary"):
            with st.spinner("🔍 Scanning QR code..."):
                result = scan_qr_code(uploaded_file)
            
            if result['qr_found']:
                st.success(f"✅ QR Code Found! ({result['qr_count']} codes detected)")
                st.write(f"Extracted Data: {result['data']}")
                
                if result['is_url']:
                    st.info("🔗 Analyzing URL safety...")
                    url_result = check_phishing(result['data'])
                    status_class = "safe-result" if url_result['status'] == 'Safe' else "dangerous-result" if url_result['status'] == 'Dangerous' else "suspicious-result"
                    st.markdown(f'<div class="{status_class}">URL Analysis: {url_result["status"]}</div>', unsafe_allow_html=True)
                
                st.session_state.scan_history.append({
                    'type': 'qr', 'input': result['data'][:50], 'result': 'Scanned',
                    'confidence': None, 'time': datetime.datetime.now()
                })
            else:
                st.error("❌ No QR code found")

elif page == "Deepfake Detector":
    st.header("🎭 Deepfake Detector")
    st.markdown('<div class="feature-card">Detect AI-generated deepfakes in images and videos using advanced AI analysis</div>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["🖼️ Image Analysis", "🎥 Video Analysis"])
    
    with tab1:
        uploaded_image = st.file_uploader("Upload Image", type=['png', 'jpg', 'jpeg'], key="image")
        if uploaded_image:
            image = Image.open(uploaded_image)
            st.image(image, caption="Uploaded Image", use_container_width=True)
            
            if st.button("🤖 Analyze Image", type="primary"):
                with st.spinner("🔍 Analyzing with AI models..."):
                    result = detect_deepfake(uploaded_image)
                
                if result['is_real']:
                    st.markdown(f'<div class="safe-result"><h4>✅ AUTHENTIC IMAGE</h4>Confidence: {result["confidence"]}%<br>{result["message"]}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="dangerous-result"><h4>🚨 AI-GENERATED</h4>Confidence: {result["confidence"]}%<br>{result["message"]}</div>', unsafe_allow_html=True)
                
                st.session_state.scan_history.append({
                    'type': 'deepfake', 'input': f"Image ({uploaded_image.name})",
                    'result': 'Real' if result['is_real'] else 'Fake',
                    'confidence': result['confidence'], 'time': datetime.datetime.now()
                })
    
    with tab2:
        uploaded_video = st.file_uploader("Upload Video", type=['mp4', 'avi', 'mov'], key="video")
        if uploaded_video:
            st.video(uploaded_video)
            st.info("🎯 Video analysis extracts multiple frames for comprehensive detection")
            
            if st.button("🤖 Analyze Video", type="primary"):
                with st.spinner("🎥 Processing video frames..."):
                    result = detect_deepfake_video(uploaded_video)
                
                if result['is_real']:
                    st.markdown(f'<div class="safe-result"><h4>✅ AUTHENTIC VIDEO</h4>Confidence: {result["confidence"]}%<br>{result["message"]}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="dangerous-result"><h4>🚨 AI-GENERATED VIDEO</h4>Confidence: {result["confidence"]}%<br>{result["message"]}</div>', unsafe_allow_html=True)
                
                st.session_state.scan_history.append({
                    'type': 'deepfake', 'input': f"Video ({uploaded_video.name})",
                    'result': 'Real' if result['is_real'] else 'Fake',
                    'confidence': result['confidence'], 'time': datetime.datetime.now()
                })

else:  # About page
    st.header("ℹ️ About CyberShield AI")
    st.markdown("""
    <div class="feature-card">
    <h3>Your All-in-One Cybersecurity Solution</h3>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("🔗 URL Protection")
        st.write("• Phishing URL detection\n• Real-time safety scoring\n• Risk factor analysis")
    with col2:
        st.subheader("📱 QR Security") 
        st.write("• QR code scanning\n• URL safety analysis\n• Content verification")
    with col3:
        st.subheader("🎭 Deepfake Detection")
        st.write("• AI image detection\n• Video analysis\n• Advanced pattern recognition")
    
    st.markdown("---")
    st.subheader("🚀 Quick Start")
    st.write("1. URL Analysis - Check any URL for phishing\n2. QR Scanning - Upload QR codes for safety check\n3. Deepfake Detection - Detect AI-generated content")

# Footer
st.markdown("---")
st.markdown("<div style='text-align: center; color: #888;'>🛡️ CyberShield AI - Protecting Your Digital World</div>", unsafe_allow_html=True)