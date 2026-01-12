\# Anomaly Detection from PCAP (tcpdump / pktmon)



Bu proje, ham ağ trafiği (PCAP/PCAPNG) üzerinden \*\*anomali tespiti\*\* yapar.



\*\*Amaç\*\*

\- Traffic spike (yüksek trafik / ani artış)

\- Port scan (çok sayıda porta SYN denemesi)

\- Beklenmedik davranışlar (model tabanlı skor)



\*\*Hedef:\*\* Baseline (normal trafik) üzerinde \*\*False Positive ~ %5\*\*.



Ham paketleri okudu

Paketten ölçülebilir özet özellikler (features) üretti

“Normal trafik”ten (baseline) modeli eğitti

Test trafiğini modele verip anomali skorladı

Ek olarak port taraması / trafik artışı gibi davranışları kural ile yakaladı

Sonuçları CSV + grafik olarak raporladı

Her şeyi GitHub’a koydu (kod + README + örnek figürler)

---



\## Proje Yapısı



\- `src/`

&nbsp; - `extract\_features.py` : PCAP -> Feature CSV (window + host-window)

&nbsp; - `detect\_anomalies.py` : IsolationForest + FP kalibrasyonu + kural tabanlı sinyaller

&nbsp; - `make\_charts.py` : Grafik üretimi (matplotlib)

\- `data/pcap/` : PCAP/PCAPNG dosyaları (\*\*gitignore\*\*)

\- `reports/outputs/` : CSV/JSON çıktılar (\*\*gitignore\*\*)

\- `reports/figures/` : Grafikler (\*\*gitignore\*\*)

\- `docs/figures/` : README’de gösterilecek örnek görseller (\*\*repo’ya dahil\*\*)



> Not: PCAP ve büyük rapor çıktıları repo’yu şişirmemek / veri paylaşmamak için GitHub’a eklenmez.



---



\## Kurulum (Windows)



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

pip install -r requirements.txt



