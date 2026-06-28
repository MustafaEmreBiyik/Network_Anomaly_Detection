import os

# .env değerlerini yükle (merkezi tek kaynak). python-dotenv yoksa (ör. minimal
# eğitim ortamı) sessizce atla; os.environ / default'lar yine de çalışır.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

TOP_FEATURES = [
    "Bwd Packet Length Std",
    "Bwd Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Bwd Packet Length Max",
    "Subflow Bwd Bytes",
    "Avg Bwd Segment Size",
    "Packet Length Mean",
    "Average Packet Size",
    "Max Packet Length",
    "Total Length of Bwd Packets",
    "Fwd IAT Std",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Bwd Packets/s",
    "Idle Min",
    "Fwd IAT Mean",
    "Subflow Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd IAT Max"
]

# ---------------------------------------------------------------------------
# ÇALIŞMA-ANI AYARLARI (.env ile override edilebilir) — sihirli sabitler burada
# ---------------------------------------------------------------------------
# Eskalasyon: aynı IP'den son ESCALATION_WINDOW_SECONDS saniyedeki tespit sayısı
# eşikleri aşınca ŞÜPHELİ / ENGELLENDİ kararı verilir (kafka_consumer._get_escalation).
ESCALATION_WINDOW_SECONDS = int(os.getenv("ESCALATION_WINDOW_SECONDS", "60"))
ESCALATION_SUSPICIOUS_THRESHOLD = int(os.getenv("ESCALATION_SUSPICIOUS_THRESHOLD", "2"))
ESCALATION_BLOCK_THRESHOLD = int(os.getenv("ESCALATION_BLOCK_THRESHOLD", "4"))

# Pano zaman-serisi gruplama frekansı (pandas resample/Grouper freq, ör. "10s").
BUCKET_FREQUENCY = os.getenv("BUCKET_FREQUENCY", "10s")
