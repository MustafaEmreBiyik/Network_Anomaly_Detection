# Gerçek Zamanlı Ağ Anomali Tespit Sistemi — Kapsamlı Teknik Analiz

**Hazırlayan:** Mustafa Emre Bıyık · Betül Danışmaz  
**Tarih:** Haziran 2026

---

## İçindekiler

1. [Proje Genel Bakış](#1-proje-genel-bakış)
2. [Kullanılan Teknolojiler ve Araçlar](#2-kullanılan-teknolojiler-ve-araçlar)
3. [Veri Seti ve Veri Mühendisliği](#3-veri-seti-ve-veri-mühendisliği)
4. [Tehdit Taksonomisi](#4-tehdit-taksonomisi)
5. [Model Geliştirme](#5-model-geliştirme)
6. [Değerlendirme Metodolojisi](#6-değerlendirme-metodolojisi)
7. [Gerçek Zamanlı Sistem Mimarisi](#7-gerçek-zamanlı-sistem-mimarisi)
8. [Deneysel Sonuçlar](#8-deneysel-sonuçlar)
9. [Teknik Kararların Gerekçeleri](#9-teknik-kararların-gerekçeleri)
10. [Proje Dosya Yapısı](#10-proje-dosya-yapısı)

---

## 1. Proje Genel Bakış

### Amaç

Bu proje, bir ağ üzerindeki trafiği gerçek zamanlı olarak izleyip makine öğrenmesi modelleriyle analiz ederek zararlı trafiği tespit eden ve otomatik olarak engelleyen uçtan uca bir **Ağ Saldırı Tespit Sistemi (NIDS — Network Intrusion Detection System)** geliştirmektir.

### Çözülen Problem

Geleneksel güvenlik duvarları ve imza tabanlı saldırı tespit sistemleri, yalnızca önceden bilinen saldırı kalıplarını tanıyabilir. Bu proje, **davranışsal analiz** ile ağ trafiğindeki istatistiksel anormallikleri öğrenerek hem bilinen hem de varyasyonlu saldırıları yakalamayı hedefler. Temel sorun şudur: binlerce paket saniyede geçerken insan müdahalesi mümkün değildir; sistemin kendi kendine karar verip engellemesi gerekir.

### Gerçek Dünya Kullanım Senaryosu

Bir kurumsal ağa bağlı güvenlik sunucusunda çalışır. Sistem;

1. Ağ arayüzünden (Wi-Fi veya Ethernet) paket yakalar.
2. Her akış için 78 öznitelik çıkarır.
3. ML modeline sorar: *Bu trafik normal mi, hacimsel saldırı mı, yoksa anlamsal saldırı mı?*
4. Saldırı tespit edilirse kaynak IP'yi işletim sistemi güvenlik duvarında otomatik olarak engeller.
5. Tüm bu süreci gerçek zamanlı bir panoda görselleştirir.

```
Ağ Arayüzü → Scapy (4 saniyelik pencere) → CICFlowMeter (78 öznitelik)
      ↓
Kafka (üretici) → Kafka Konusu: network-traffic → Kafka (tüketici)
      ↓
ML Modeli → Tahmin (Zararsız / Hacimsel / Anlamsal)
      ↓
Yanıt Motoru → Güvenlik Duvarı Engelleme + SQLite Loglama + Streamlit Pano
```

---

## 2. Kullanılan Teknolojiler ve Araçlar

### Apache Kafka

**Ne olduğu:** Dağıtık bir mesaj akış platformudur. Üretici-tüketici mimarisi üzerine inşa edilmiştir; mesajlar konulara (topic) yazılır ve tüketiciler bu konuları dinler.

**Bu projede neden tercih edildi:**
- Paket yakalama (üretici) ile model tahmini (tüketici) süreçlerini birbirinden ayırır. Tüketici çökerse üreticinin yakalamaya devam etmesi sağlanır; mesajlar Kafka'da bekler.
- İleride birden fazla tüketici eklenebilir (örn. farklı modellerin paralel çalışması veya ensemble oylama).
- Yüksek verimli ağlarda 100.000'den fazla akış/saniyeye ölçeklenebilir.

**Yapılandırma (`docker-compose.yml`):**
```yaml
KAFKA_BOOTSTRAP_SERVERS: '127.0.0.1:9092'
KAFKA_TOPIC: network-traffic
KAFKA_GROUP_ID: nids-consumer-group-v2
KAFKA_AUTO_OFFSET_RESET: latest   # İlk başlatmada eski mesajları atla
```

**Alternatifi ne olurdu:** RabbitMQ veya Redis Pub/Sub. Ancak Kafka, mesaj kalıcılığı (disk tabanlı log) ve geri oynatma (replay) özelliğiyle öne çıkar; bu, model güncellenince eski trafiği yeniden analiz etmeye olanak tanır.

---

### Scapy

**Ne olduğu:** Python tabanlı düşük seviyeli paket yakalama ve işleme kütüphanesidir.

**Bu projede neden tercih edildi:** Ham ağ paketlerini doğrudan yakalamak için kullanılır. `src/live_bridge.py` içinde 4 saniyelik pencerelerle paketler toplanır ve geçici bir `.pcap` dosyasına yazılır.

```python
# src/live_bridge.py
packets = sniff(iface=NETWORK_INTERFACE, timeout=4,
                count=MAX_BUFFER_PACKETS, stop_filter=lambda p: len(packets) >= MIN_BUFFER_PACKETS)
wrpcap("temp_live.pcap", packets)
```

**Alternatifi:** tcpdump (CLI aracı, platform bağımlı) veya PyShark (Wireshark wrapper, daha yavaş).

---

### CICFlowMeter

**Ne olduğu:** Kanada'nın CICIDS araştırma grubunun geliştirdiği, ham `.pcap` dosyalarından 78 ağ akışı özniteliği çıkaran Java tabanlı bir araçtır.

**Bu projede neden tercih edildi:** CICIDS2017 veri seti de aynı araçla üretildiğinden, gerçek zamanlı özniteliklerin eğitim verisiyle **birebir aynı formatta** olması sağlanır. Bu kritik bir karardır: farklı bir öznitelik çıkarma aracı kullansaydık, eğitim ve çıkarım arasında öznitelik dağılımı kaymasına (distribution shift) yol açardık.

**Alternatifi:** Python tabanlı `scapy`'nin manuel hesaplaması veya `nfcapd/nfdump` (NetFlow tabanlı); ancak bunlar CICIDS2017 öznitelikleriyle uyumlu değildir.

---

### TensorFlow / Keras

**Ne olduğu:** Google'ın açık kaynak derin öğrenme çerçevesidir.

**Bu projede kullanım alanı:** LSTM ve BiLSTM modellerinin tanımlanması, eğitilmesi ve kaydedilmesi için kullanılmıştır.

```python
# src/models/train_bilstm.py
model = Sequential([
    Bidirectional(LSTM(128, return_sequences=True), input_shape=(10, 20)),
    BatchNormalization(),
    Dropout(0.3),
    ...
])
model.save("models/bilstm_model.keras")
```

**Alternatifi:** PyTorch. TF'nin seçilme nedeni `tf.data.Dataset` ile bellek-verimli büyük veri yükleme ve `ReduceLROnPlateau` gibi yerleşik callback desteğidir.

---

### XGBoost

**Ne olduğu:** Gradient boosting üzerine inşa edilmiş, GPU hızlandırması destekleyen yüksek performanslı bir karar ağacı topluluğu algoritmasıdır.

**Bu projede neden tercih edildi:** Scikit-learn'den 10 kat daha hızlı eğitim (CUDA desteği), yerleşik erken durdurma ve çok sınıflı `multi:softprob` hedefi.

**Yapılandırma (`models/xgb_3class_config.json`):**
```json
{
  "n_estimators": 1000,
  "max_depth": 7,
  "learning_rate": 0.05,
  "subsample": 0.8,
  "colsample_bytree": 0.8,
  "device": "cuda",
  "tree_method": "hist",
  "early_stopping_rounds": 50,
  "best_iteration": 857
}
```

**Alternatifi:** LightGBM (daha hızlı, daha az bellek) veya CatBoost (kategorik öznitelikler için iyi, bu projede tüm öznitelikler sayısal olduğundan avantajı yok).

---

### Scikit-learn

**Ne olduğu:** Python'un temel ML kütüphanesidir; Random Forest, Decision Tree, preprocessing araçları ve metrik hesaplamaları içerir.

**Bu projede kullanım alanı:**
- `MinMaxScaler`: öznitelik normalizasyonu
- `RandomForestClassifier`: topluluk modeli
- `DecisionTreeClassifier`: yorumlanabilir temel model
- `train_test_split`: stratified bölme
- `compute_sample_weight('balanced', y)`: sınıf ağırlığı hesabı

**Alternatifi:** İzole işlemler için alternatif yok; bu projede değiştirilemez altyapı sağlar.

---

### Streamlit

**Ne olduğu:** Python'da veri uygulamaları için minimal bir web çerçevesidir.

**Bu projede neden tercih edildi:** Sıfır HTML/JS ile gerçek zamanlı izleme panosu oluşturmayı sağlar; backend Python olduğundan SQLite sorgularıyla direkt entegrasyon mümkündür.

**Alternatifi:** Grafana (production-grade, ama daha karmaşık kurulum ve InfluxDB/Prometheus altyapısı gerektirir), Flask + Chart.js (özel geliştirme gerektirir).

---

## 3. Veri Seti ve Veri Mühendisliği

### CICIDS2017 Nedir?

**CICIDS2017** (Canadian Institute for Cybersecurity Intrusion Detection System 2017), Kanada Siber Güvenlik Enstitüsü tarafından üretilmiş, gerçek ağ ortamını taklit eden sentetik ama gerçekçi bir ağ trafiği veri setidir.

**Temel Özellikler:**
- 2.83 milyon ağ akışı
- 8 günlük trafik verisi (Pazartesi–Cuma)
- 14 farklı sınıf: BENIGN, DDoS, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, Heartbleed, Bot, PortScan, FTP-Patator, SSH-Patator, Web Attack Brute Force, Web Attack XSS, Web Attack Sql Injection, Infiltration
- CICFlowMeter ile üretilmiş 78 öznitelik

**Bu veri seti neden seçildi:**
1. Hem gerçekçi hem de etiketlenmiş veri sağlar (etiketleme çok maliyetlidir).
2. Aynı CICFlowMeter aracıyla üretildiği için gerçek zamanlı özniteliklerle uyumludur.
3. Akademik çevrelerde yaygın referans verisidir; sonuçlar karşılaştırılabilir.
4. Çok çeşitli saldırı türleri içerir.

---

### Ham Veriden Modele Giden Adımlar

#### 3.1 ML Modelleri için Ön İşleme (`src/features/preprocess_ml_3class.py`)

**Girdi:** 8 ham CICIDS2017 CSV dosyası  
**Çıktı:** `data/processed_ml/{train.csv, val.csv, test.csv}`

```
Adım 1: Her CSV dosyası yüklenir
Adım 2: Etiket normalizasyonu (boşluk, BOM karakteri, özel karakter temizleme)
Adım 3: Ham etiket → 3 sınıf haritalama (classes_map.json ile)
Adım 4: Dosya başına stratified bölme: %80 train, %10 val, %10 test
Adım 5: Tüm dosyalardan gelen parçalar birleştirilir
Adım 6: MinMaxScaler YALNIZCA train üzerinde fit edilir, tüm kümelere transform uygulanır
Adım 7: scaler_ml_3class.pkl kaydedilir
```

**Sonuç Dağılımı:**
- Eğitim: ~1.82M akış (%64)
- Doğrulama: ~0.23M akış (%8)
- Test: ~0.78M akış (%28)

---

#### 3.2 "Dosya Bazlı Katmanlı Bölme" Protokolü

Bu kritik bir tasarım kararıdır. Nadir sınıflar (özellikle Infiltration) yalnızca belirli günlerin CSV dosyalarında bulunur. Tüm veriyi birleştirip sonra bölseydik, bazı dosyalardaki nadir sınıflar yalnızca eğitim kümesine, bazıları yalnızca test kümesine düşebilirdi.

**Çözüm: Her dosyayı ayrı ayrı böl, sonra birleştir.**

```python
# src/features/preprocess_ml_3class.py
train_parts, val_parts, test_parts = [], [], []

for csv_file in csv_files:
    df = pd.read_csv(csv_file)
    df["Label"] = df[" Label"].str.strip().map(classes_map)  # Normalizasyon
    
    # Dosya başına stratified bölme
    train_df, temp_df = train_test_split(
        df, test_size=0.20, stratify=df["Label"], random_state=42
    )
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, stratify=temp_df["Label"], random_state=42
    )
    
    train_parts.append(train_df)
    val_parts.append(val_df)
    test_parts.append(test_df)

# Birleştir
train_all = pd.concat(train_parts, ignore_index=True)
val_all   = pd.concat(val_parts,   ignore_index=True)
test_all  = pd.concat(test_parts,  ignore_index=True)

# Sızıntısız ölçekleme: sadece train üzerinde fit
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(train_all[TOP_FEATURES])
X_val_scaled   = scaler.transform(val_all[TOP_FEATURES])
X_test_scaled  = scaler.transform(test_all[TOP_FEATURES])
joblib.dump(scaler, "models/scaler.pkl")
```

---

#### 3.3 LSTM için Ön İşleme (`src/features/preprocess_lstm.py`)

LSTM zaman dizisi öğrendiğinden, öznitelik vektörleri art arda gelen akışlardan oluşan 3B tensörlere dönüştürülmüştür.

```python
# src/features/preprocess_lstm.py
WINDOW_SIZE = 10  # Her örnek 10 ardışık akıştan oluşur
STRIDE = 1        # Her adımda 1 akış kayma

def create_sequences(X, y, window_size=10, stride=1):
    sequences, labels = [], []
    for i in range(0, len(X) - window_size + 1, stride):
        sequences.append(X[i : i + window_size])   # (10, 20)
        labels.append(y[i + window_size - 1])       # Pencerenin son etiketini al
    return np.array(sequences), np.array(labels)

# Kritik sıralama: önce bölme, sonra pencere oluştur
train_flows, test_flows = train_test_split(df, test_size=0.2, stratify=y, random_state=42)
X_train, y_train = create_sequences(train_flows[TOP_FEATURES].values, train_flows["Label"].values)
X_test,  y_test  = create_sequences(test_flows[TOP_FEATURES].values,  test_flows["Label"].values)

# Sonuç: X_train.shape = (1_249_851, 10, 20)
```

---

### Sınıf Dengesizliği Nasıl Ele Alındı?

CICIDS2017'de sınıf dağılımı ciddi ölçüde dengesizdir:

| Sınıf | Örnekler | Oran |
|-------|----------|------|
| Zararsız (0) | ~2.1M | %74 |
| Hacimsel (1) | ~0.55M | %19 |
| Anlamsal (2) | ~0.18M | %6 |

**ML modelleri için:** `sklearn.utils.class_weight.compute_sample_weight('balanced', y_train)` fonksiyonu kullanılmıştır. Bu fonksiyon her örneğe bir ağırlık atar:

```
ağırlık[sınıf] = toplam_örnek / (sınıf_sayısı × sınıftaki_örnek_sayısı)
```

Sonuç olarak:
- Zararsız (0): 0.415 (çoğunluk sınıfı, düşük ağırlık)
- Hacimsel (1): 2.479
- Anlamsal (2): 5.333 (en nadir sınıf, yüksek ağırlık)

**Derin öğrenme modelleri için:**
- `class_weight` parametresi `model.fit()` çağrısına geçirilmiştir.
- Ek olarak Focal Loss kullanılmıştır (aşağıda açıklanmıştır).

---

### Seçilen 20 Öznitelik

78 CICFlowMeter özniteliğinden şu 20'si seçilmiştir (`src/config.py`):

```python
TOP_FEATURES = [
    "Bwd Packet Length Std",       # Geri yönlü paket boyutu standart sapması
    "Bwd Packet Length Mean",      # Geri yönlü paket boyutu ortalaması
    "Packet Length Std",           # Genel paket boyutu standart sapması
    "Packet Length Variance",      # Genel paket boyutu varyansı
    "Bwd Packet Length Max",       # Geri yönlü maksimum paket boyutu
    "Subflow Bwd Bytes",           # Alt akış geri yönlü bayt sayısı
    "Avg Bwd Segment Size",        # Geri yönlü ortalama segment boyutu
    "Packet Length Mean",          # Genel ortalama paket boyutu
    "Average Packet Size",         # Ortalama paket boyutu
    "Max Packet Length",           # Maksimum paket boyutu
    "Total Length of Bwd Packets", # Geri yönlü toplam bayt
    "Fwd IAT Std",                 # İleri yönlü paketlerarası varış süresi sapması
    "Total Fwd Packets",           # İleri yönlü toplam paket sayısı
    "Total Backward Packets",      # Geri yönlü toplam paket sayısı
    "Bwd Packets/s",               # Saniyedeki geri paket hızı
    "Idle Min",                    # Minimum boşta kalma süresi
    "Fwd IAT Mean",                # İleri yönlü ortalama varış aralığı
    "Subflow Fwd Packets",         # Alt akış ileri yönlü paket sayısı
    "Total Length of Fwd Packets", # İleri yönlü toplam bayt
    "Fwd IAT Max"                  # İleri yönlü maksimum varış aralığı
]
```

**Neden bu öznitelikler seçildi:**
- **Paket boyutu istatistikleri** (ilk 11 öznitelik): DDoS saldırıları büyük hacimli paketler gönderirken, tarayan araçlar küçük prob paketleri kullanır. Bu istatistikler saldırı türünü davranışsal olarak ayırt eder.
- **Zamansal öznitelikler** (IAT — Inter-Arrival Time): Botnet trafiği düzenli aralıklarla gelen paketlerle karakterizedir; normal kullanıcı trafiği ise düzensizdir.
- **Yönsel asimetri** (Fwd/Bwd oranları): SYN flood gibi saldırılarda ileri yönlü paketler geri yönlü paketlerden çok daha fazladır.

Öznitelik seçimi Random Forest önem puanları ve SHAP değerleri (`src/utils/xai_engine.py`) analiz edilerek gerçekleştirilmiştir.

---

## 4. Tehdit Taksonomisi

### Neden 14 Sınıf Yerine 3 Sınıf?

CICIDS2017'deki 14 sınıfın hepsiyle model eğitmek birkaç nedenle sorunludur:

1. **Sınıf dengesizliği şiddetlenir:** Infiltration sınıfında yalnızca 36 örnek vardır; bir modelin bu kadar az örnekten anlamlı bir şey öğrenmesi olanaksızdır.
2. **Operasyonel değersizlik:** Güvenlik operatörü için önemli olan "ne engelleneceği" kararıdır, "tam olarak hangi saldırı türü" değil. DDoS'u DoS Hulk'tan ayırt etmek savunma kararını değiştirmez.
3. **Gerçek zamanlı yanıt sınırı:** Güvenlik duvarı yalnızca iki şey yapabilir: izin ver veya engelle. 14 sınıf bu kararı gereksiz ölçüde karmaşıklaştırır.

**Çözüm:** Savunma stratejisine göre gruplanmış 3 anlamlı sınıf.

---

### Zararsız / Hacimsel / Anlamsal Ayrımı

Bu sınıflandırma iki boyuta dayanır: **bant genişliği etkisi** ve **gizlilik derecesi**.

| Sınıf | Tanım | Yanıt Stratejisi |
|-------|-------|------------------|
| **Zararsız (0)** | Normal kullanıcı trafiği | İzin ver |
| **Hacimsel (1)** | Bant genişliğini dolduran, yüksek hacimli saldırılar | Hız sınırlama / IP engelleme |
| **Anlamsal (2)** | Düşük hacimli ama hedefli, gizli saldırılar | Derin inceleme / imza analizi |

---

### Hangi Saldırı Hangi Sınıfa Atandı?

**`src/utils/classes_map.json`'dan:**

```json
{
  "BENIGN":                    0,
  "DDoS":                      1,
  "DoS Hulk":                  1,
  "DoS GoldenEye":             1,
  "DoS slowloris":             1,
  "DoS Slowhttptest":          1,
  "Heartbleed":                1,
  "Bot":                       2,
  "PortScan":                  2,
  "FTP-Patator":               2,
  "SSH-Patator":               2,
  "Web Attack Brute Force":    2,
  "Web Attack XSS":            2,
  "Web Attack Sql Injection":  2,
  "Infiltration":              2
}
```

**Sınıflandırma mantığı:**
- **Hacimsel (1):** DDoS, DoS türleri ve Heartbleed bant genişliği veya bağlantı sonu kaynakları tüketir. Yüksek paket hızı ve büyük hacimle kendini belli eder. Heartbleed protokol kötüye kullanımına rağmen hacim tabanlı yanıt gerektirir.
- **Anlamsal (2):** Port tarama, kaba kuvvet, web saldırıları ve botnet bağlantısı düşük hacimlidir ama amaçlıdır. Bu trafik ağ trafiğine karışır ve içeriği anlamlandırma gerektirir.

---

## 5. Model Geliştirme

### 5.1 XGBoost (GPU Hızlandırmalı, 3 Sınıf)

**Model nedir, nasıl çalışır:**  
XGBoost, karar ağaçlarını art arda ekleyerek (boosting) hatayı iteratif biçimde azaltan bir topluluk yöntemidir. Her yeni ağaç, önceki ağaçların yanlış tahmin ettiği örneklere odaklanır. `multi:softprob` hedefi her sınıf için olasılık döndürür.

**Bu projede kullanılan hiperparametreler ve gerekçeleri:**

| Parametre | Değer | Neden |
|-----------|-------|-------|
| `n_estimators` | 1000 | Yeterince fazla ağaç; erken durdurma ile gerçek kullanılan sayı 857 |
| `max_depth` | 7 | Derin ağaçlar ağ trafiği öznitelikleri için zengin etkileşimleri yakalar; aşırı öğrenme riski `subsample` ile dengelenir |
| `learning_rate` | 0.05 | Düşük öğrenme hızı + çok ağaç kombinasyonu genellikle daha iyi genelleştirir |
| `subsample` | 0.8 | Her ağaç için verinin %80'ini kullan; aşırı öğrenmeyi azaltır |
| `colsample_bytree` | 0.8 | Her bölmede özniteliklerin %80'ini kullan; modeli çeşitlendirir |
| `device` | cuda | GPU üzerinde hist yöntemi ile eğitim; CPU'ya göre ~10x hızlı |
| `early_stopping_rounds` | 50 | Doğrulama kaybı 50 turda iyileşmezse dur |

**Eğitim süreci:**
```python
# src/models/train_xgboost.py
sample_weights = compute_sample_weight('balanced', y_train)

model = XGBClassifier(
    objective='multi:softprob',
    eval_metric='mlogloss',
    n_estimators=1000,
    max_depth=7, learning_rate=0.05,
    subsample=0.8, colsample_bytree=0.8,
    num_class=3, device='cuda', tree_method='hist',
    early_stopping_rounds=50, random_state=42
)

model.fit(
    X_train_scaled, y_train,
    sample_weight=sample_weights,
    eval_set=[(X_val_scaled, y_val)],
    verbose=100
)
# Best iteration: 857 (143 ağaç erken durdurma ile iptal edildi)
```

**Girdi formatı:** 2B — `(örnek_sayısı, 20)` düz vektör.

**Güçlü yönleri:** En hızlı eğitim süresi (GPU ile 2-3 dakika), mükemmel AUC-ROC (0.9991), NaN toleransı, öznitelik önem puanı.  
**Zayıf yönleri:** Zamansal kalıpları öğrenemez (akışlar arası bağımlılık yok), büyük model boyutu (~50MB pkl).

---

### 5.2 Random Forest (3 Sınıf)

**Model nedir, nasıl çalışır:**  
Random Forest, birbirinden bağımsız çok sayıda karar ağacı eğitip tahminleri çoğunluk oyuyla birleştiren bir topluluk yöntemidir. Her ağaç farklı örnekler (bootstrap) ve farklı öznitelik alt kümeleri üzerinde büyür.

**Hiperparametre arama süreci:**

```python
# src/models/train_randomforest.py
param_grid = {
    'max_depth':        [20, 30, None],
    'min_samples_leaf': [10, 30, 50],
    'max_features':     ['sqrt', 'log2'],
    'class_weight':     ['balanced', {0: 1.0, 1: 2.0, 2: 4.0}]
}
# Sabit: n_estimators=100, criterion='entropy'
# 3 × 3 × 2 × 2 = 36 kombinasyon denenmiş gibi görünse de
# aktif: 18 kombinasyon (bazıları hızlı ayıklandı)
# Skor metriği: doğrulama kümesinde Makro F1
```

**En iyi konfigürasyon:** `max_depth=30, min_samples_leaf=30, max_features='sqrt', class_weight={0:1.0, 1:2.0, 2:4.0}`

**Eğitim süreci:** Grid search, doğrulama kümesi Makro F1 skoruna göre en iyi modeli seçer. k-katlı çapraz doğrulama kullanılmamıştır (dengesiz verilerle riski vardır ve zaman maliyeti yüksektir).

**Girdi formatı:** 2B — `(örnek_sayısı, 20)`.

**Güçlü yönleri:** Yorumlanabilir öznitelik önemleri, aşırı öğrenmeye dirençli, NaN toleranslı, paralel ağaç eğitimi.  
**Zayıf yönleri:** Tahmin süresi XGBoost'tan yavaş ama hâlâ gerçek zamanlı; büyük ağaçlar için bellek yoğun.

---

### 5.3 Decision Tree (Karar Ağacı, 3 Sınıf)

**Model nedir:** Tek bir ağaç tabanlı sınıflandırıcı; özniteliklere göre dallar oluşturur.

**Hiperparametreler:**
```python
# src/models/train_decisiontree.py
DecisionTreeClassifier(
    criterion='entropy',
    max_depth=15,
    min_samples_leaf=10,
    class_weight={0: 1.0, 1: 2.0, 2: 4.0},
    random_state=42
)
```

**Bu projede rolü:** Hem bir kıyaslama noktası hem de yorumlanabilirlik aracı olarak kullanılmıştır. `src/utils/visualize_dt.py` ile ağaç görselleştirilebilir; güvenlik analistleri kararların hangi koşullara dayandığını görebilir.

**Güçlü yönleri:** En hızlı çıkarım (7.5M örnek/sn), tam yorumlanabilirlik, görselleştirilebilir kurallar.  
**Zayıf yönleri:** Anlamsal sınıfta Random Forest ve XGBoost'tan düşük F1.

---

### 5.4 BiLSTM (Çift Yönlü Uzun Kısa Dönem Belleği)

**Model nedir, nasıl çalışır:**  
LSTM hücreler, önceki zaman adımlarını "unutma", "güncelleme" ve "çıkış" kapıları aracılığıyla seçici biçimde hatırlar. BiLSTM (Bidirectional LSTM), sırayı hem ileri hem geri yönde işleyerek her zaman adımı için hem geçmiş hem de gelecek bağlamı yakalar. Ağ trafiğinde bu, bir akışın hem öncesindeki hem sonrasındaki akışlarla ilişkisini modellemeye yarar.

**Mimari (`src/models/train_bilstm.py`):**

```python
model = Sequential([
    Input(shape=(10, 20)),                              # (pencere, öznitelik)
    
    Bidirectional(LSTM(128, return_sequences=True)),    # → (10, 256)
    BatchNormalization(),
    Dropout(0.3),
    
    Bidirectional(LSTM(64, return_sequences=False)),    # → (128,)
    BatchNormalization(),
    Dropout(0.3),
    
    Dense(64, activation='relu'),
    Dropout(0.3),
    
    Dense(3, activation='softmax')                     # 3 sınıf olasılığı
])
```

**Hiperparametreler:**

| Parametre | Değer | Neden |
|-----------|-------|-------|
| `lstm_units_1` | 128 | İlk katman yüksek boyutlu temsil öğrenir; `return_sequences=True` ile zaman boyutu korunur |
| `lstm_units_2` | 64 | İkinci katman özetleme yapar; `return_sequences=False` ile tek vektöre indirgenir |
| `dropout_rate` | 0.3 | %30 düğüm rastgele sıfırlama — aşırı öğrenmeyi önler |
| `learning_rate` | 0.001 | Adam optimizer için standart başlangıç; `ReduceLROnPlateau` ile adaptif olarak azalır |
| `batch_size` | 256 | GPU bellek/hesaplama dengesi |
| `focal_gamma` | 2.0 | Focal loss yoğunlaştırıcısı — kolay örnekleri bastırır, zor örneklere odaklanır |
| `label_smoothing` | 0.1 | Hedef etiketleri yumuşatır: 1.0 → 0.9, 0.0 → 0.033 |

**Kayıp fonksiyonu — Focal Loss + Etiket Yumuşatma:**

```python
# Focal Loss: zor ve azınlık sınıflarına odaklanmayı sağlar
# p_t: doğru sınıfın tahmin olasılığı
# focal_weight = (1 - p_t) ^ gamma
# Model doğru tahmin ettiğinde (p_t yüksek) → ağırlık küçülür (kolay örnek)
# Model yanlış tahmin ettiğinde (p_t düşük) → ağırlık büyür (zor örnek)

# Etiket Yumuşatma: one-hot hedefi soft hedefe dönüştürür
# [0, 0, 1] → [0.033, 0.033, 0.933]   (ε=0.1, K=3)
# Modelin aşırı özgüvenini önler
```

**Eğitim sürecindeki callback'ler:**
```python
callbacks = [
    EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
    ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6),
    ModelCheckpoint('models/bilstm_model.keras', save_best_only=True)
]
```

**Girdi formatı:** 3B — `(batch, 10, 20)`. 10 ardışık ağ akışından oluşan zaman penceresi.

**Güçlü yönleri:** En yüksek Makro F1 (%97.98), zamansal kalıpları öğrenir, çift yönlü bağlam, hem Hacimsel hem Anlamsal sınıfta dengeli.  
**Zayıf yönleri:** En yavaş çıkarım (9.212 örnek/sn), GPU gerektirir, büyük bellek tüketimi, eğitim süresi ~45 dk/epoch.

---

### 5.5 LSTM (Tek Yönlü)

**Mimari:**

```python
# src/models/train_lstm.py
model = Sequential([
    Input(shape=(10, 20)),
    LSTM(128, return_sequences=True),
    BatchNormalization(), Dropout(0.3),
    
    LSTM(64, return_sequences=False),
    BatchNormalization(), Dropout(0.3),
    
    Dense(64, activation='relu'), Dropout(0.3),
    Dense(3, activation='softmax')
])
```

BiLSTM ile özdeş mimaridir ancak katmanlar tek yönlüdür; her adımda yalnızca geçmiş bağlam kullanılır. Sonuç olarak çıkarım hızı BiLSTM'den yaklaşık 2x daha yüksektir (17.383 örnek/sn).

**Girdi formatı:** 3B — `(batch, 10, 20)`.

**Güçlü yönleri:** BiLSTM'den daha hızlı, zamansal kalıpları öğrenir.  
**Zayıf yönleri:** BiLSTM'den yaklaşık %1.5 daha düşük Makro F1.

---

## 6. Değerlendirme Metodolojisi

### Neden Makro F1 Skoru?

Ağ anomali tespitinde hem saldırı türlerini hem de zararsız trafiği eşit önemde doğru sınıflandırmak gerekir. Bu bağlamda ağırlıklı ortalama F1 yanıltıcı olurdu: model Zararsız sınıfını (%74 oranında) çok iyi tahmin etse bile yüksek ağırlıklı F1 verir, ama nadir Anlamsal saldırıları kaçırıyor olabilir.

**Makro F1** her sınıfın F1 skorunu **eşit ağırlıkta** ortalama alır:

```
Makro F1 = (F1_Zararsız + F1_Hacimsel + F1_Anlamsal) / 3
```

Bu formül, modeli Anlamsal sınıfta kötü performans gösterdiğinde cezalandırır, veri dengesizliğine göre ödüllendirmez.

---

### Test/Train/Validation Split Nasıl Yapıldı?

"Dosya Bazlı Katmanlı Bölme" protokolü (Bölüm 3.2'de açıklandı) uygulanmıştır:

```
Eğitim: %64 (~1.82M akış)
Doğrulama: %8 (~0.23M akış)  — erken durdurma ve model seçimi için
Test: %28 (~0.78M akış)      — nihai değerlendirme için (tek kez kullanıldı)
```

LSTM için sıralama kritiktir:
```
Ham akışlar → Stratified bölme → Pencere oluşturma (her kümede ayrı)
```

---

### Zamansal Veri Sızıntısı Nedir, Nasıl Önlendi?

**Problem:** LSTM için pencereler oluştururken, eğer önce tüm veriden pencereler oluşturup sonra bölseydik, bazı pencereler hem eğitim hem test akışlarını içerebilirdi. Bu, model test kümesindeki bilgiyi eğitim sırasında "görmüş" olur.

**Örnek:**
```
Akışlar: [1, 2, 3, 4, 5, ..., 100]
Pencere boyutu = 10

# Yanlış (sızıntı): önce pencere, sonra bölme
Pencere_1: [1..10], Pencere_2: [2..11], ...
→ Bölme sınırı akış 80'de ise, Pencere_71: [71..80] eğitimde
  Pencere_72: [72..81] test'te ama 72-80 akışlarını PAYLAŞIYOR

# Doğru: önce bölme, sonra pencere
Eğitim akışları: [1..80] → Pencereler sadece bu aralıktan
Test akışları: [81..100] → Pencereler sadece bu aralıktan
```

**`preprocess_lstm.py`'deki uygulaması:** Stratified split yapılarak `train_flows` ve `test_flows` ayrıldıktan sonra `create_sequences()` her küme üzerinde bağımsız çağrılmıştır.

---

## 7. Gerçek Zamanlı Sistem Mimarisi

### Uçtan Uca Sistem Akışı

```
[Ağ Arayüzü]
      ↓ (Scapy, 4 saniyelik pencereler)
[temp_live.pcap]
      ↓ (CICFlowMeter CLI / FlowSession API)
[78-öznitelikli CSV]
      ↓ (src/live_bridge.py — sütun yeniden adlandırma, NaN temizleme)
[Kafka Üretici — network-traffic konusu]
      ↓ (JSON mesajları)
[Kafka Tüketicisi — src/kafka_consumer.py]
      ↓ (TOP_FEATURES filtreleme → MinMaxScaler → model.predict())
[Tahmin: 0/1/2 + güven skoru]
      ↓
[Yanıt Motoru]
   ├─ ALLOW  → CSV logu ekle
   ├─ ALERT  → SQLite'a yaz + konsol uyarısı
   ├─ SUSPICIOUS → Uyarı + artış sayacı
   └─ BLOCKED → SQLite yaz + Güvenlik Duvarı Kuralı
      ↓
[Streamlit Panosu ← SQLite sorgular]
```

---

### Her Bileşenin Rolü

| Bileşen | Dosya | Rol |
|---------|-------|-----|
| Üretici | `src/live_bridge.py` | Paket yakala → öznitelik çıkar → Kafka'ya gönder |
| Tüketici | `src/kafka_consumer.py` | Kafka'dan oku → tahmin → yanıt |
| Model Kayıt Defteri | `src/model_registry.py` | Hangi modelin hangi scaler ve config ile yükleneceğini tanımlar |
| Config | `src/config.py` | `TOP_FEATURES` listesi ve genel sabitler |
| Güvenlik Duvarı | `src/utils/firewall_manager.py` | Windows/Linux'ta IP engelleme komutlarını çalıştırır |
| Veritabanı | `src/utils/db_manager.py` | SQLite CRUD operasyonları |
| Pano | `src/dashboard/app.py` | Streamlit görselleştirme |
| Başlatıcı | `run_system.py` | Docker + tüm servisleri ayrı terminal pencerelerinde başlatır |

---

### Kafka Yapılandırması

```yaml
# docker-compose.yml
zookeeper:
  image: confluentinc/cp-zookeeper:7.4.0
  ports: ["2181:2181"]

kafka:
  image: confluentinc/cp-kafka:7.4.0
  depends_on: [zookeeper]
  ports: ["9092:9092"]
  environment:
    KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
    KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
    KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
```

```python
# src/kafka_consumer.py
KAFKA_BOOTSTRAP_SERVERS = '127.0.0.1:9092'
KAFKA_TOPIC = 'network-traffic'
KAFKA_GROUP_ID = "nids-consumer-group-v2"
KAFKA_AUTO_OFFSET_RESET = "latest"   # Eski mesajları atla
```

---

### Sıfır Kesintili Model Değişimi (Hot-Swap)

`data/active_model.txt` dosyası değiştirilerek Kafka tüketicisini durdurmadan model anında değiştirilebilir.

```python
# src/kafka_consumer.py — 5 saniyede bir kontrol
MODEL_CHECK_INTERVAL = 5  # saniye
last_model_check = 0

def check_and_reload_model():
    global CURRENT_MODEL, CURRENT_SCALER, CURRENT_MODEL_NAME, last_model_check
    
    now = time.time()
    if now - last_model_check < MODEL_CHECK_INTERVAL:
        return
    last_model_check = now
    
    # Aktif modeli oku
    with open("data/active_model.txt", "r") as f:
        requested_model = f.read().strip()
    
    # Değişmediyse hiçbir şey yapma
    if requested_model == CURRENT_MODEL_NAME:
        return
    
    # Yeni modeli yükle (hata olursa eskiyle devam et)
    registry_entry = MODEL_REGISTRY.get(requested_model)
    if not registry_entry:
        logger.warning(f"Bilinmeyen model: {requested_model}")
        return
    
    try:
        new_model  = load_model(registry_entry["model_path"])
        new_scaler = joblib.load(registry_entry["scaler_path"])
        
        # Atomik değişim
        CURRENT_MODEL      = new_model
        CURRENT_SCALER     = new_scaler
        CURRENT_MODEL_NAME = requested_model
        logger.info(f"Model degistirildi: {requested_model}")
    except Exception as e:
        logger.error(f"Model yuklenemedi: {e}. Eskiyle devam ediliyor.")
```

**Nasıl kullanılır:**
```bash
echo "XGBoost" > data/active_model.txt
# 5 saniye içinde tüketici yeni modeli yükler, hiç kesinti yok
```

---

### Otomatik Tehdit Yanıtı

Tek bir saldırı paketi false positive olabilir. Sistem **yükselen uyarı** (escalation) mantığı kullanır:

```python
# src/kafka_consumer.py
_attack_history = defaultdict(list)          # {src_ip: [timestamp1, timestamp2, ...]}
ESCALATION_WINDOW_SECONDS = 60              # Son 60 saniyeye bak

def _get_escalation(src_ip: str) -> tuple[str, int]:
    now = time.time()
    # 60 saniye dışındaki kayıtları temizle
    _attack_history[src_ip] = [
        t for t in _attack_history[src_ip]
        if t > (now - ESCALATION_WINDOW_SECONDS)
    ]
    _attack_history[src_ip].append(now)
    
    count = len(_attack_history[src_ip])
    
    if count >= 4:
        return "BLOCKED", count      # 4+ tespit → IP engelle
    elif count >= 2:
        return "SUSPICIOUS", count   # 2-3 tespit → şüpheli işaretle
    else:
        return "ALERT", count        # 1 tespit → uyarı ver
```

**Windows güvenlik duvarı engelleme:**
```python
# src/utils/firewall_manager.py
def block_ip(ip_address: str) -> bool:
    if ip_address in WHITELIST:
        return False
    rule_name = f"Block_AI_{ip_address}"
    command = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" dir=in action=block remoteip={ip_address}'
    )
    result = os.system(command)
    if result == 0:
        _record_block(ip_address)   # SQLite'a ekle
        return True
    return False
```

---

## 8. Deneysel Sonuçlar

### Tüm Modeller — Performans Özeti

| Model | Doğruluk | Makro Hassasiyet | Makro Geri Çağırma | Makro F1 | ROC-AUC | Gecikme (ms/örnek) | Verim (örnek/sn) |
|-------|----------|-----------------|-------------------|----------|---------|-------------------|-----------------|
| **BiLSTM** | %98.88 | %97.98 | %98.02 | **%97.98** | — | 0.1085 | 9.212 |
| **LSTM** | %98.15 | %96.45 | %96.52 | %96.45 | — | 0.0575 | 17.383 |
| **Random Forest** | %97.34 | %94.43 | %97.70 | %95.91 | 0.9983 | 0.0031 | 319.398 |
| **XGBoost** | %97.71 | %93.62 | %98.38 | %95.87 | 0.9991 | 0.0079 | 126.546 |
| **Karar Ağacı** | %97.27 | — | — | ~%94 | — | 0.0001 | 7.534.659 |

*Gecikme: 10.000 örneklik kıyaslama, ısınma adımı sonrası (`src/models/benchmark_all_models.py`)*

---

### BiLSTM Neden En Yüksek F1'i Aldı?

1. **Zamansal bağlam:** Saldırılar akış dizileri halinde gerçekleşir; bireysel akışlar değil, ardışık paket örüntüleri bir tehdidi oluşturur. BiLSTM bu 10-akışlık pencereyi hem ileri hem geri işleyerek kalıpları yakalar.
2. **Çift yönlülük:** Standart LSTM yalnızca geçmişe bakarken, BiLSTM her akış için hem önceki hem sonraki bağlamı kullanır. Bu, bir saldırının "tırmanma ve zirve" örüntüsünü daha iyi modeller.
3. **Focal Loss:** Nadir Anlamsal sınıfa ekstra odaklanma; bu sınıfın F1'ini %91→%97 aralığına taşır.
4. **Batch Normalization:** Eğitim stabilitesini artırır; gradyan patlamasını önler.

---

### XGBoost Neden Hız/Doğruluk Dengesi Açısından Tercih Edilebilir?

- **Doğruluk:** BiLSTM'den yalnızca ~%2 daha düşük Makro F1 (%95.87 vs %97.98)
- **Hız:** BiLSTM'den 13.7x daha yüksek verim (126.546 vs 9.212 örnek/sn)
- **Gerçek zamanlı kullanım:** Tabular modeller mevcut altyapıda (sliding window olmadan) direkt çalışır
- **ROC-AUC:** 0.9991 — ayrım gücü açısından neredeyse mükemmel
- **Hafıza:** GPU olmadan da CPU üzerinde makul performans

**Sonuç:** Gerçek zamanlı yüksek hacimli ağlarda XGBoost birincil tercih, BiLSTM daha az acil senaryolar veya toplu analiz için uygundur.

---

### Karar Ağacı Anlamsal Sınıfta Neden İyi Performans Gösterir?

Anlamsal saldırılar (Port tarama, Kaba kuvvet) belirgin ve yinelemeli davranış kalıpları gösterir:
- Port tarama: kısa akışlar, çok sayıda farklı hedef port, küçük byte miktarı
- Kaba kuvvet: tekrarlı bağlantı denemeleri, sabit hedef port, küçük akış boyutu

Karar ağacı bu **keskin ayrım sınırlarını** (`if Bwd Packets/s < 0.5 and Total Fwd Packets > 100`) açıkça kodlar. Toplu saldırılarda, topluluk yöntemlerinin interpolasyon yaptığı yerde karar ağacı doğrudan keskin bir kural öğrenir.

---

## 9. Teknik Kararların Gerekçeleri

### Neden Kayan Pencere (Sliding Window) LSTM İçin Kullanıldı?

**Karar:** Her LSTM örneği, art arda 10 ağ akışından oluşan bir penceredir.

**Neden:** Tek bir ağ akışı bağımsız değildir. DDoS saldırısı yüzlerce küçük paketin belirli bir tempo ile gönderilmesinden oluşur; tek akışa bakarak bu tempoyu göremezsiniz. LSTM'nin değer katması için **zaman serisini görmesi** gerekir.

**Alternatif:** Her akışı bağımsız girdi olarak vermek. Bu tabular yaklaşımdır ve Random Forest/XGBoost'un yaptığı şeydir. LSTM bu durumda tabular modelden üstün olamaz.

**Trade-off:** Pencere yaklaşımı eğitim örneklerini ~10x artırır ve bellek kullanımını artırır; bunun karşılığında zamansal bağlam öğrenilir.

---

### Neden Stride=1 Seçildi?

**Karar:** Her adımda pencere 1 akış kayar (maksimum örtüşme).

**Neden:** Stride=1 her geçerli zaman kalıbını yakalar. Stride=10 kullanılsaydı, pencereler örtüşmez ve aralarındaki geçiş dönemleri hiç görülmezdi; nadir saldırı kalıplarını kaçırma riski artar.

**Kod:**
```python
# src/features/preprocess_lstm.py
STRIDE = 1
for i in range(0, len(X) - WINDOW_SIZE + 1, STRIDE):
    sequences.append(X[i : i + WINDOW_SIZE])
```

**Trade-off:**
- Stride=1: 1.249.851 eğitim penceresi, maksimum kapsam, yavaş eğitim
- Stride=10: ~125.000 pencere, 10x hızlı eğitim, nadir kalıpları kaçırabilir

**Neden Stride=1 tercih edildi:** Güvenlik alanında kaçırılan saldırı, hızlı eğitimden çok daha maliyetlidir.

---

### Neden Pencere Boyutu 10 Olarak Belirlendi?

**Karar:** Her pencere 10 ardışık ağ akışını içerir.

**Neden:** Deneysel. Çok küçük pencere (örn. 3) yeterli zamansal bağlam sağlamaz; çok büyük pencere (örn. 50) LSTM'nin uzun vadeli bağımlılıkları öğrenmesini zorlaştırır ve eğitim örneklerini azaltır. 10, ağ trafiğinde tipik bir saldırı dizisi için yeterli bağlamı sağlayan makul bir değerdir.

**Alternatifler:** 5 (daha hızlı, daha az bağlam), 20 (daha zengin bağlam, %50 daha az pencere). Bu bir hiperparametre olup döküman içindeki `WINDOW_SIZE` sabiti değiştirilerek test edilebilir.

---

### Neden MinMaxScaler Kullanıldı?

**Karar:** Tüm öznitelikler [0, 1] aralığına ölçeklenir.

**Neden:**
1. Ağ trafiği öznitelikleri çok farklı ölçeklerdedir: `Packet Length Std` 0–65535 aralığında olabilirken `Bwd Packets/s` 0–1000 olabilir. Ölçekleme olmadan büyük ölçekli öznitelikler modele hakim olur.
2. Neural network'ler (LSTM/BiLSTM) için aktivasyon fonksiyonları (sigmoid, tanh) [0,1] veya [-1,1] aralığında en iyi çalışır.
3. MinMax, negatif olmayan öznitelikler için (paket sayısı, byte sayısı) doğal bir seçimdir.

**Sızıntı önlemi:**
```python
# DOĞRU: Scaler YALNIZCA eğitim verisine fit edilir
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled   = scaler.transform(X_val)    # fit() değil!
X_test_scaled  = scaler.transform(X_test)   # fit() değil!
```

**Alternatifler:**
- `StandardScaler` (Z-score): Gauss dağılımı varsayar; ağ trafiği çoğunlukla çarpık dağılımlıdır.
- `RobustScaler`: Aykırı değerlere dayanıklı, ancak CICIDS2017'de CICFlowMeter zaten infinity değerlerini kırpıyor.

---

### Neden Dropout %30 Seçildi?

**Karar:** Her Dropout katmanında rate=0.3 kullanıldı.

**Neden:** Dropout, eğitim sırasında nöronları rastgele devre dışı bırakarak modeli belirli özelliklere aşırı bağımlı olmaktan korur. %30 oranı:
- %10-20 çok düşük: aşırı öğrenmeyi önlemez
- %50+ çok yüksek: öğrenme kapasitesini azaltır, eğitim yavaşlar
- %30: derin öğrenme pratiğinde standart başlangıç noktası; deneysel olarak en iyi doğrulama F1'ini bu değer vermiştir

```python
# src/models/train_bilstm.py
Dropout(0.3)   # BiLSTM katmanlarından sonra
Dropout(0.3)   # Dense katmanından sonra
```

---

### Neden Batch Normalization Eklendi?

**Karar:** Her LSTM katmanının ardına `BatchNormalization()` eklendi.

**Neden:**
1. **Gradyan akışı:** Derin ağlarda gradyanlar katmanlar arasında kaybolabilir (vanishing gradient). BN, her katmanın girişini normalleştirir; gradyanlar daha kararlı akar.
2. **Öğrenme hızı duyarsızlığı:** BN, daha yüksek öğrenme oranlarıyla çalışabilme olanağı sağlar.
3. **Regularizasyon etkisi:** Hafif düzenleştirme; dropout ile birlikte kullanıldığında sinerjik etki.
4. **Pratik gözlem:** BN eklenmeden eğitim, erken epoch'larda dengesiz davranmaktaydı; BN ile val_loss eğrisi düzleşti.

---

## 10. Proje Dosya Yapısı

```
Network Detection/
│
├── run_system.py                      # Tek komutla tüm sistemi başlatır:
│                                      # Docker kontrol, Kafka başlatma,
│                                      # consumer/producer/dashboard ayrı terminallerde
├── docker-compose.yml                 # Kafka (9092) + Zookeeper (2181) konteynerleri
├── requirements.txt                   # Python bağımlılıkları (numpy, pandas, tf, xgb...)
├── .env / .env.example                # NETWORK_INTERFACE, WHITELIST_IPS, BLOCK_TTL_SECONDS
│
├── data/
│   ├── original_csv/                  # Ham CICIDS2017 CSV dosyaları (8 dosya, ~3GB)
│   ├── processed_ml/                  # ML için işlenmiş veri: train.csv, val.csv, test.csv
│   ├── processed_lstm/                # LSTM için: X_train.npy, y_train.npy, X_test.npy, y_test.npy
│   │                                  # (1.249.851 × 10 × 20 boyutlu tensörler)
│   ├── active_model.txt               # Hangi modelin aktif olduğunu belirler ("XGBoost" gibi)
│   └── live_captured_traffic.csv      # Gerçek zamanlı yakalanan trafik logu
│
├── models/
│   ├── rf_3class_model.pkl            # Eğitilmiş Random Forest (scikit-learn)
│   ├── xgb_3class_model.pkl           # Eğitilmiş XGBoost (GPU destekli)
│   ├── dt_3class_model.pkl            # Eğitilmiş Karar Ağacı
│   ├── lstm_model.keras               # Eğitilmiş LSTM (TensorFlow Keras format)
│   ├── bilstm_model.keras             # Eğitilmiş BiLSTM
│   ├── bilstm_savedmodel/             # SavedModel format (TF Serving için)
│   ├── scaler.pkl                     # MinMaxScaler (ML modelleri için)
│   ├── scaler_lstm.pkl                # MinMaxScaler (LSTM/BiLSTM için)
│   ├── rf_3class_config.json          # RF model metadatası
│   ├── xgb_3class_config.json         # XGBoost hiperparametreleri ve best_iteration
│   ├── lstm_config.json               # LSTM mimari bilgisi
│   ├── bilstm_config.json             # BiLSTM mimari bilgisi
│   └── class_weights.json             # {0: 0.415, 1: 2.479, 2: 5.333}
│
├── binary_models/                     # Eski ikili sınıflandırma modelleri (arşiv)
│
├── src/
│   ├── config.py                      # TOP_FEATURES listesi (20 öznitelik), genel sabitler
│   ├── model_registry.py              # MODEL_REGISTRY: her model için dosya yolları, scaler, config
│   ├── live_bridge.py                 # Üretici: Scapy → CICFlowMeter → Kafka
│   ├── kafka_consumer.py              # Tüketici: Kafka → ML → yanıt + hot-swap
│   │
│   ├── capture/
│   │   └── sniffer.py                 # Scapy paket yakalama sarmalayıcısı
│   │
│   ├── features/
│   │   ├── preprocess_ml_3class.py    # ML için: dosya bazlı stratified bölme + MinMaxScaler
│   │   ├── preprocess_lstm.py         # LSTM için: sliding window dizisi oluşturma
│   │   ├── preprocess.py             # Eski ikili model ön işleme (arşiv)
│   │   └── data_audit_3class.py       # Veri kalitesi denetimi, dağılım istatistikleri
│   │
│   ├── models/
│   │   ├── train_randomforest.py      # Grid search + RF eğitimi
│   │   ├── train_xgboost.py           # GPU XGBoost eğitimi, erken durdurma
│   │   ├── train_decisiontree.py      # DT eğitimi
│   │   ├── train_bilstm.py            # BiLSTM: Focal Loss, BN, Dropout, callbacks
│   │   ├── train_lstm.py              # LSTM eğitimi
│   │   ├── evaluate_randomforest.py   # Confusion matrix, F1, ROC-AUC raporları
│   │   ├── evaluate_xgboost.py        # XGBoost değerlendirme ve görselleştirme
│   │   ├── evaluate_bilstm.py         # BiLSTM değerlendirme
│   │   ├── evaluate_lstm.py           # LSTM değerlendirme
│   │   ├── evaluate_decisiontree.py   # DT değerlendirme
│   │   ├── benchmark_all_models.py    # Gecikme ve verim kıyaslaması (10K örnek)
│   │   └── stress_test.py             # Sistem performans testi
│   │
│   ├── dashboard/
│   │   └── app.py                     # Tek SOC panosu (TR/EN iki dilli): 6 sekme —
│   │                                  # Canlı İzleme, Tehdit Haritası, Olay Kayıtları,
│   │                                  # XAI Açıklayıcı, Model Performansı, Yönetim & Yanıt
│   │
│   └── utils/
│       ├── db_manager.py              # SQLite: alerts, pipeline_events, blocked_ips tabloları
│       ├── firewall_manager.py        # Windows (netsh) ve Linux (iptables) IP engelleme
│       ├── xai_engine.py              # SHAP tabanlı açıklanabilirlik (feature importance)
│       ├── model_optimizer.py         # Karar eşiği optimizasyonu
│       ├── visualize_dt.py            # Karar ağacını görsel olarak çizer
│       └── classes_map.json           # 14 saldırı etiketi → 3 sınıf haritalama
│
├── reports/
│   ├── figures/
│   │   ├── randomforest/              # RF için confusion matrix, ROC eğrisi, önem grafiği
│   │   ├── xgboost/                   # XGBoost görselleştirmeleri
│   │   ├── decisiontree/              # DT görselleştirmeleri ve ağaç diyagramı
│   │   ├── lstm/ ve bilstm/           # DL modeli eğitim eğrileri, confusion matrisler
│   │   └── latency_benchmark.json    # Ham gecikme/verim verileri
│   └── data/
│       ├── classes_map.json           # Referans kopyası
│       ├── class_distribution_summary.json
│       ├── top_20_features.json       # Seçilen özniteliklerin önem sıralaması
│       └── activity_details.json
│
├── paper_reports/
│   ├── technical_reports/
│   │   ├── ARCHITECTURE.md            # Canlı köprü akış diyagramı
│   │   ├── DATA_ARCHITECTURE_REPORT.md # Çift katmanlı depolama gerekçesi
│   │   └── REFACTORING_SUMMARY.md
│   └── system_architecture.md
│
├── experiments/
│   └── pycaret_setup.ipynb            # AutoML deneyi (exploratory, üretimde kullanılmıyor)
│
├── test/
│   ├── check_interfaces.py            # Mevcut ağ arayüzlerini listeler
│   ├── attack_test.py                 # Simüle saldırı senaryoları
│   ├── test_model_registry.py         # Model kayıt defteri birim testleri
│   └── test_csv_schema.py             # CSV şema doğrulama testleri
│
├── tools/
│   ├── mcnemar_test.py                # İki model arasında istatistiksel anlamlılık testi
│   └── query_alerts_db.py             # SQLite sorgulama yardımcı aracı
│
└── archive/
    └── app2.py                        # Eski/basit pano — arşivlendi
                                       # (tek aktif pano: src/dashboard/app.py)
```

---

## Ek: Bağımlılıklar ve Sürümler

```
numpy==1.26.4
pandas==2.3.3
scikit-learn==1.7.2
tensorflow==2.15.0
xgboost==2.1.4        # CUDA destekli
scapy==2.6.1
streamlit==1.52.0
joblib==1.5.2
matplotlib
seaborn
plotly
python-dotenv
confluent-kafka==2.14.0
cicflowmeter            # Java tabanlı, ayrıca kurulum gerektirir
```

---

*Bu belge `proje_analiz.md` olarak kaydedilmiştir. Tüm teknik kararlar kaynak koddan doğrudan alınmıştır.*
