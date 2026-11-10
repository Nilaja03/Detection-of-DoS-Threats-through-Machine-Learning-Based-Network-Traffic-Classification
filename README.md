# Integrated Network Security Auditing and Machine Learning-Based Traffic Classification

**Student:** Nilanjana Jamindar\
**USN:** 1RUB25CSE0013\
**Programme:** M.Tech Computer Science and Engineering\
**Institution:** RV University, Bengaluru\
**Guide:** Dr. Basavaraj Patil

## Project overview

This academic prototype combines:

1.  **Port & Access Audit** --- a bounded Nmap TCP scan of authorized
    localhost/private-network targets, with best-effort listener process
    context.
2.  **HTTP rate-limit indicators** --- five sequential HTTP GET requests
    and inspection of common rate-limit response headers.
3.  **AI Threat Detection** --- Random Forest classification of uploaded
    network-flow CSV records into `BENIGN`, `PortScan`, and `DoS`.
4.  **Security Report** --- generation of a PDF summarizing the latest
    available scan, HTTP observations, ML outputs, and mitigation
    recommendations.

> **Scope:** The current prototype does not capture packets or
> continuously monitor live network traffic. The ML module classifies
> uploaded flow-level CSV records. Do not describe it as a live IDS.

## Dataset

-   Hugging Face repository:
    https://huggingface.co/datasets/bvsam/cic-ids-2017
-   Configuration: `machine_learning`
-   Split: `train`
-   Selected project classes: `BENIGN`, `PortScan`, `DoS Hulk`,
    `DoS Slowloris` (DoS labels are mapped to the project class `DoS`).
-   Maximum sample used by the notebook: 10,000 valid records per
    project class.
-   Five model features:
    -   `Destination Port`
    -   `Flow Duration`
    -   `Total Fwd Packets`
    -   `Total Backward Packets`
    -   `Flow Bytes/s`

## Model

The notebook trains a scikit-learn `RandomForestClassifier` with 180
trees, maximum depth 24, minimum split size 4, minimum leaf size 2,
`class_weight="balanced_subsample"`, and `random_state=42`. The selected
records are split using a stratified 80:20 train/test split.

The supplied labelled test CSV contains 6,000 rows. Its comparison with
the classified output yielded **99.38% accuracy (5,963/6,000)**. This is
a held-out benchmark-dataset result, not a guarantee of performance on
live traffic or other networks.

## Repository layout (recommended)

``` text
project/
├── app.py
├── model_training.ipynb
├── requirements.txt
├── README.md
├── models/
│   └── threat_detector.joblib
├── data/
│   └── test_flows.csv
├── outputs/
│   ├── classified_network_flows.csv
│   └── AI_Web_Security_Audit_Report.pdf
├── screenshots/
└── docs/
    ├── Technical_Report_Network_Security_Framework.docx
    └── Test_Plan_and_Execution_Evidence.docx
```

Do not commit private credentials, tunnel tokens, API keys, or personal
access tokens. Check the repository history before publishing files.

## Environment and dependencies

The notebook was developed for Google Colab. It installs system-level
Nmap and Python packages during notebook execution. Python package
dependencies used by the notebook/dashboard include:

``` text
streamlit
pandas
numpy
scikit-learn
matplotlib
seaborn
joblib
requests
reportlab
datasets
pyarrow
```

Nmap must also be installed on the machine running the audit module. The
current notebook installs it in a Debian/Ubuntu-based Colab runtime
using `apt-get`.

## Running in Google Colab

1.  Open `model_training.ipynb` in Google Colab.
2.  Run the notebook cells in order.
3.  The notebook loads the Hugging Face dataset, preprocesses selected
    classes, trains the Random Forest model, evaluates it, and saves the
    model and metrics.
4.  The notebook writes the Streamlit application to `/content/app.py`.
5.  Start the Streamlit server using the notebook's launch cell.
6.  Start the tunnel using the notebook's tunnel cell and open the
    generated URL.
7.  In **AI Threat Detection**, upload a CSV containing the five
    required feature columns. A `Label` column is optional for
    inference, but required to calculate accuracy against ground truth.
8.  Use **Security Report** to generate the PDF.

The notebook uses runtime paths such as
`/content/threat_detector.joblib` and `/content/model_metrics.json`.
These are temporary Colab runtime files and must be regenerated or
uploaded into a fresh runtime. Do not assume they persist between
sessions.

## Input CSV format

Required columns (exact names or supported common aliases):

``` text
Destination Port
Flow Duration
Total Fwd Packets
Total Backward Packets
Flow Bytes/s
```

Optional column:

``` text
Label
```

If `Label` is supplied and recognized, the dashboard can calculate
accuracy by comparing it with `Predicted Class`. Without ground-truth
labels, the model can produce predictions but cannot calculate
classification accuracy for that uploaded file.

## Test evidence

The supplied evidence includes:

-   Nmap scan of `127.0.0.1`: `8080/tcp` open; the listener was
    attributed to a process likely managed by Google Colab.
-   HTTP check: five requests returned `404`; the rate-limit assessment
    is inconclusive because the tested path was not found.
-   ML test: 6,000 labelled records classified; 99.38% agreement with
    labels.
-   PDF report generation: completed successfully.

See `Test_Plan_and_Execution_Evidence.docx` for expected outcomes,
actual results, and test interpretations.

## Security and ethical use

-   Scan only systems you own or are explicitly authorized to assess.
-   The current scanner restricts targets to loopback/private/link-local
    addresses.
-   The Nmap scan is bounded to the top 100 TCP ports.
-   The HTTP checker sends five sequential requests; use a documented,
    known-valid endpoint for meaningful rate-limit testing.
-   A 404 response does not establish whether rate limiting is enabled
    or disabled.
-   An open port is an observation, not automatically a vulnerability.
-   ML predictions are indicators for investigation, not confirmed
    incidents.
-   Do not expose tunnel credentials, secrets, or private tokens in
    source control.

## Known limitations

-   No packet capture or automatic live network traffic ingestion.
-   ML classification operates on uploaded flow records only.
-   The five selected features provide a limited representation of
    network behavior.
-   The Colab localhost scan examines the hosted runtime, not the user's
    personal computer or necessarily the deployed application.
-   Process attribution is best-effort.
-   The supplied HTTP test was inconclusive due to HTTP 404.
-   Results are not a security certification or proof that a target is
    secure.

## References

-   CIC-IDS2017 dataset: https://www.unb.ca/cic/datasets/ids-2017.html
-   Hugging Face dataset:
    https://huggingface.co/datasets/bvsam/cic-ids-2017
-   Nmap manual: https://nmap.org/book/man.html
-   scikit-learn Random Forest:
    https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
-   Streamlit documentation: https://docs.streamlit.io/
