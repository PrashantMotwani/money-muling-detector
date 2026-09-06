# Money Mule Detection System (MMDS)

An advanced fraud prevention and anti-money laundering (AML) detection system designed to identify and flag structured money mulling activity in real-time banking pipelines.

## 🚀 Core Features
* **Velocity Tracking:** Analyzes "rapid funds in, rapid funds out" patterns over sliding time windows.
* **Anomalous Behavioral Scoring:** Flags sudden transaction spikes that deviate heavily from a profile's historical baseline.
* **Network & Graph Linking:** Group accounts sharing device fingerprints, IPs, or rapid sequential routing paths.

## 🛠️ Technical Stack
* **Language:** Python 3.11+
* **Data Processing:** Pandas / NumPy
* **Analytics/ML:** Scikit-Learn / NetworkX (for graph analysis)

## 📦 Installation & Setup
1. Clone the repository:
   ```bash
   git clone https://github.com
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the mock detection pipeline:
   ```bash
   python src/main.py
   ```
