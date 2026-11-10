
import streamlit as st
import pandas as pd
import numpy as np
import joblib, socket, ipaddress, subprocess, tempfile, os, json, time, re
import requests
from datetime import datetime
from urllib.parse import urlparse
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

st.set_page_config(page_title="AI Web Security Framework", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Assisted Web Security Framework")
st.caption("Exposed-port auditing • Access-control indicators • ML-based PortScan / DoS detection")

MODEL_PATH = "/content/threat_detector.joblib"
METRICS_PATH = "/content/model_metrics.json"
FEATURES = ["Destination Port", "Flow Duration", "Total Fwd Packets",
            "Total Backward Packets", "Flow Bytes/s"]

if not os.path.exists(MODEL_PATH):
    st.error("Trained model not found. Run the model-training cells in the notebook first.")
    st.stop()

bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
features = bundle["features"]

# Holdout accuracy calculated during model training (Cell 7).
model_metrics = {}
if os.path.exists(METRICS_PATH):
    try:
        with open(METRICS_PATH, "r") as metrics_file:
            model_metrics = json.load(metrics_file)
    except (OSError, json.JSONDecodeError):
        model_metrics = {}
holdout_accuracy = model_metrics.get("accuracy")

if "scan_results" not in st.session_state: st.session_state.scan_results = None
if "rate_results" not in st.session_state: st.session_state.rate_results = None
if "threat_results" not in st.session_state: st.session_state.threat_results = None
if "uploaded_test_accuracy" not in st.session_state: st.session_state.uploaded_test_accuracy = None
if "uploaded_test_accuracy_n" not in st.session_state: st.session_state.uploaded_test_accuracy_n = 0
if "target" not in st.session_state: st.session_state.target = ""

def resolve_private_target(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Enter a target IP or hostname.")
    candidate = raw
    if "://" in raw:
        parsed = urlparse(raw)
        candidate = parsed.hostname or ""
    else:
        candidate = raw.split("/")[0].split(":")[0]
    if not candidate:
        raise ValueError("Could not parse the target.")
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            resolved = socket.gethostbyname(candidate)
            ip = ipaddress.ip_address(resolved)
        except Exception as exc:
            raise ValueError(f"Hostname resolution failed: {exc}")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ValueError("For this Colab demonstration, scans are restricted to localhost/private-network targets.")
    return candidate, str(ip)

def run_nmap(target_ip):
    cmd = ["nmap", "-sT", "-sV", "--top-ports", "100", "-T2", "-Pn", target_ip]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr or result.stdout or "Nmap failed.")
    rows = []
    for line in result.stdout.splitlines():
        m = re.match(r"^(\d+)/tcp\s+(open|closed|filtered)\s+(.+)?$", line.strip())
        if m:
            rows.append({"Port": int(m.group(1)), "Protocol": "TCP",
                         "State": m.group(2), "Service": (m.group(3) or "unknown").strip()})
    return rows, result.stdout

def identify_local_listener(port):
    """Best-effort process attribution for a loopback TCP listener; never terminate it."""
    pid = None
    command = ""
    try:
        probe = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{int(port)}", "-sTCP:LISTEN", "-t"],
            capture_output=True, text=True, timeout=5
        )
        pids = [x.strip() for x in probe.stdout.splitlines() if x.strip().isdigit()]
        if pids:
            pid = pids[0]
            ps = subprocess.run(
                ["ps", "-p", pid, "-o", "args="],
                capture_output=True, text=True, timeout=5
            )
            command = ps.stdout.strip()
    except (FileNotFoundError, subprocess.SubprocessError, ValueError):
        pass

    if command and ("/datalab/web/app.js" in command or "/tools/node/bin/node" in command):
        context = "Likely Google Colab-managed web infrastructure; not identified as the project application."
    elif command:
        context = "Local listener process identified; application ownership/purpose is not independently verified."
    else:
        context = "Local listener process could not be attributed with available system tools."
    return {"Listener PID": pid or "Unavailable",
            "Listener process": command or "Unavailable",
            "Environment context": context}


def enrich_port_context(target_ip, ports):
    """Attach process context only for loopback scans; do not infer ownership for remote hosts."""
    try:
        is_loopback = ipaddress.ip_address(target_ip).is_loopback
    except ValueError:
        is_loopback = False
    enriched = []
    for item in ports:
        row = dict(item)
        if is_loopback and row.get("State") == "open":
            row.update(identify_local_listener(row["Port"]))
        else:
            row.update({"Listener PID": "Not checked", "Listener process": "Not checked",
                        "Environment context": "Process attribution is available only for loopback targets."})
        enriched.append(row)
    return enriched

def low_volume_http_check(raw_target, scan_results=None):
    """Make five sequential requests; distinguish HTTP responses from connection failures."""
    raw = raw_target.strip()
    if not raw:
        raise ValueError("Enter a target IP, hostname, or full URL.")

    has_scheme = "://" in raw
    parsed = urlparse(raw if has_scheme else "http://" + raw)
    host = parsed.hostname
    if not host:
        raise ValueError("Could not parse a valid hostname or IP address.")

    _, resolved_ip = resolve_private_target(host)
    scheme = parsed.scheme.lower() if parsed.scheme.lower() in ("http", "https") else "http"
    explicit_port = parsed.port

    if explicit_port is not None:
        port = explicit_port
    elif has_scheme and scheme == "https":
        port = 443
    elif has_scheme and scheme == "http":
        port = 80
    else:
        candidates = []
        if scan_results and scan_results.get("resolved_ip") == resolved_ip:
            for item in scan_results.get("ports", []):
                if str(item.get("State", "")).lower() != "open":
                    continue
                number = int(item.get("Port"))
                service = str(item.get("Service", "")).lower()
                if number in {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000} or "http" in service or "proxy" in service:
                    candidates.append(number)
        candidates = sorted(set(candidates))
        if len(candidates) == 1:
            port = candidates[0]
        elif len(candidates) > 1:
            raise ValueError(
                "Multiple HTTP-like ports are open (" + ", ".join(map(str, candidates)) +
                "). Enter a full URL including the desired port and path."
            )
        else:
            raise ValueError(
                "No open HTTP-like port was identified. Run Nmap first, or enter a full URL "
                "including its port, e.g. http://127.0.0.1:8080/."
            )

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    url = f"{scheme}://{resolved_ip}:{port}{path}"
    host_header = host if port in (80, 443) else f"{host}:{port}"

    observations = []
    session = requests.Session()
    for i in range(5):
        try:
            response = session.get(
                url, timeout=5, allow_redirects=False,
                headers={"User-Agent": "Authorized-Security-Audit/1.0", "Host": host_header}
            )
            h = {k.lower(): v for k, v in response.headers.items()}
            indicators = {
                "RateLimit-Limit": h.get("ratelimit-limit") or h.get("x-ratelimit-limit"),
                "RateLimit-Remaining": h.get("ratelimit-remaining") or h.get("x-ratelimit-remaining"),
                "RateLimit-Reset": h.get("ratelimit-reset") or h.get("x-ratelimit-reset"),
                "Retry-After": h.get("retry-after")
            }
            found = {k: v for k, v in indicators.items() if v}
            status = int(response.status_code)
            if status == 429:
                assessment = "HTTP 429 throttling response observed for this request path"
            elif status == 404:
                assessment = "Path returned 404; rate-limit assessment is inconclusive for this path"
            elif found:
                assessment = "Rate-limit-related response header(s) observed; policy adequacy not verified"
            else:
                assessment = "No standard rate-limit signal observed; assessment remains inconclusive"

            observations.append({
                "Request": i + 1,
                "Target URL": f"{scheme}://{host}:{port}{path}",
                "HTTP Status": status,
                "Rate-limit indicators": "; ".join(f"{k}: {v}" for k, v in found.items()) or "Not observed",
                "Assessment": assessment
            })
        except requests.RequestException as exc:
            observations.append({
                "Request": i + 1,
                "Target URL": f"{scheme}://{host}:{port}{path}",
                "HTTP Status": "Connection error",
                "Rate-limit indicators": "Not assessed",
                "Assessment": f"Connection failed: {str(exc)[:180]}"
            })
        if i < 4:
            time.sleep(1)
    return observations

def prepare_flow_frame(frame):
    frame = frame.copy()

    # Normalize uploaded column names for case-insensitive matching.
    lookup = {
        str(column).replace("\\ufeff", "").strip().lower(): column
        for column in frame.columns
    }

    # Map common CIC-IDS2017/CICFlowMeter variants to the exact
    # feature names used when training the Random Forest model.
    aliases = {
        "Destination Port": ["destination port", "dst port"],
        "Flow Duration": ["flow duration"],
        "Total Fwd Packets": ["total fwd packets", "tot fwd pkts"],
        "Total Backward Packets": ["total backward packets", "tot bwd pkts"],
        "Flow Bytes/s": ["flow bytes/s", "flow byts/s", "flow bytes per second"]
    }

    rename = {}
    for canonical_name, choices in aliases.items():
        for choice in choices:
            if choice in lookup:
                rename[lookup[choice]] = canonical_name
                break

    frame = frame.rename(columns=rename)

    missing = [column for column in FEATURES if column not in frame.columns]
    if missing:
        raise ValueError(
            f"Missing required flow features: {missing}. "
            f"Columns found in uploaded CSV: {list(frame.columns)}"
        )

    X = frame[FEATURES].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    valid = X.notna().all(axis=1)

    return X.loc[valid], frame.loc[valid].copy()

tab1, tab2, tab3 = st.tabs(["1. Port & Access Audit", "2. AI Threat Detection", "3. Security Report"])

with tab1:
    st.subheader("Proactive endpoint audit")
    st.info("Use only an endpoint you own or are explicitly authorized to assess. This demonstration scans localhost/private-network targets only. In Google Colab, localhost may expose notebook-platform services rather than your own application.")
    target = st.text_input("Target IP address or URL", value=st.session_state.target,
                           placeholder="127.0.0.1 or http://192.168.1.10")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Run bounded Nmap scan", type="primary"):
            try:
                original, target_ip = resolve_private_target(target)
                with st.spinner("Running Nmap top-100 TCP port scan..."):
                    rows, raw = run_nmap(target_ip)
                rows = enrich_port_context(target_ip, rows)
                is_loopback = ipaddress.ip_address(target_ip).is_loopback
                environment_note = (
                    "Loopback scan inside the hosted notebook runtime. Any identified listener may be part of Google Colab infrastructure; this scan does not establish exposure of the user's own computer or production application."
                    if is_loopback else
                    "Private-network target scan. Confirm the target owner and authorization independently."
                )
                st.session_state.target = target
                st.session_state.scan_results = {"target": original, "resolved_ip": target_ip,
                                                  "timestamp": datetime.now().isoformat(timespec="seconds"),
                                                  "ports": rows, "raw": raw,
                                                  "environment_note": environment_note}
                st.success(f"Scan completed for {target_ip}.")
            except Exception as e: st.error(str(e))
    with c2:
        if st.button("Check HTTP rate-limit indicators"):
            try:
                resolve_private_target(target)
                with st.spinner("Sending at most five sequential HTTP requests..."):
                    observations = low_volume_http_check(
                        target,
                        scan_results=st.session_state.scan_results
                    )
                st.session_state.target = target
                st.session_state.rate_results = observations
                received = [x for x in observations if isinstance(x["HTTP Status"], int)]
                throttled = [x for x in received if x["HTTP Status"] == 429]
                header_signals = [x for x in received if x["Rate-limit indicators"] != "Not observed"]
                if throttled:
                    st.warning("HTTP 429 response(s) observed. This is evidence of throttling for the tested request path.")
                elif any(x["HTTP Status"] == 404 for x in received):
                    statuses = sorted(set(x["HTTP Status"] for x in received))
                    st.warning(
                        f"The HTTP service returned status code(s) {statuses}, including 404. The tested path was not found. "
                        "Rate limiting cannot be assessed reliably on this path; this result is inconclusive. "
                        "Use a documented, known-valid application endpoint for a meaningful check."
                    )
                elif header_signals:
                    st.info("Rate-limit-related headers were observed. Their presence is an indicator, not proof that the configured limit is adequate.")
                elif received:
                    statuses = sorted(set(x["HTTP Status"] for x in received))
                    st.warning(
                        f"The HTTP service returned status code(s) {statuses}, but no standard rate-limit signals were observed. "
                        "This is inconclusive; server-side limits may exist without these headers."
                    )
                else:
                    st.error("The HTTP service could not be reached. Rate limiting was not assessed.")
            except Exception as e: st.error(str(e))

    if st.session_state.scan_results:
        s = st.session_state.scan_results
        st.markdown(f"**Target:** `{s['target']}` · **Resolved:** `{s['resolved_ip']}` · **Time:** {s['timestamp']}")
        st.caption(s.get("environment_note", "Environment context was not recorded for this scan."))
        ports = s["ports"]
        if ports:
            st.metric("Open TCP ports discovered", sum(p["State"] == "open" for p in ports))
            st.dataframe(pd.DataFrame(ports), use_container_width=True, hide_index=True)
            st.info("An open port is an observation, not automatically a vulnerability. Confirm the service owner, business purpose, network exposure, authentication, patch status, and firewall controls before assigning risk.")
            for p in ports:
                if p.get("State") == "open" and "Colab-managed" in str(p.get("Environment context", "")):
                    st.warning(
                        f"Port {p['Port']} appears to be served by a likely Google Colab-managed process: "
                        f"{p.get('Listener process', 'process unavailable')}. Treat this as notebook-runtime infrastructure, not as evidence that your own web application is exposed."
                    )
        else:
            st.info("No open ports were identified in the scanned top-100 TCP port range. This does not mean all ports are closed.")
        with st.expander("Raw Nmap output"): st.code(s["raw"])
    if st.session_state.rate_results:
        st.markdown("**HTTP rate-limit indicator observations**")
        st.dataframe(pd.DataFrame(st.session_state.rate_results), use_container_width=True, hide_index=True)
        rate_rows = st.session_state.rate_results
        successful = [x for x in rate_rows if isinstance(x["HTTP Status"], int)]
        throttled = [x for x in successful if x["HTTP Status"] == 429]
        header_signals = [
            x for x in successful
            if x["Rate-limit indicators"] != "Not observed"
        ]
        if any(x["HTTP Status"] == 404 for x in successful):
            statuses = sorted(set(x["HTTP Status"] for x in successful))
            st.warning(
                f"The service returned HTTP status code(s) {statuses}, including 404. The tested path was not found; "
                "the rate-limit result is inconclusive. Test a documented, known-valid endpoint before drawing conclusions."
            )
        elif throttled:
            st.warning(f"{len(throttled)} HTTP 429 response(s) observed. This is evidence of throttling for the tested request path, not a complete validation of the rate-limit policy.")
        elif header_signals:
            st.info("Rate-limit-related headers were observed. Their presence is an indicator, not proof that the configured limit is adequate.")
        elif successful:
            statuses = sorted(set(x["HTTP Status"] for x in successful))
            st.warning(
                f"The HTTP service responded with status code(s) {statuses}, but no standard rate-limit "
                "signals were observed. This is inconclusive; server-side limits may exist without these headers."
            )
        else:
            st.error("All HTTP requests failed to connect. Rate limiting could not be assessed. Check the target URL, port, and service availability.")

with tab2:
    st.subheader("Machine-learning traffic classification")
    st.write("Upload a CIC-IDS2017-style flow CSV or another CSV containing the five model features.")
    flow_file = st.file_uploader("Upload network-flow CSV", type=["csv"], key="flow_csv")
    if flow_file is not None:
        try:
            input_df = pd.read_csv(flow_file, low_memory=False)
            X, valid_rows = prepare_flow_frame(input_df)
            if len(X) == 0: st.error("No valid rows after numeric feature validation.")
            else:
                preds = model.predict(X)
                probabilities = model.predict_proba(X)
                result = valid_rows.copy()
                result["Predicted Class"] = preds
                result["Confidence"] = probabilities.max(axis=1)

                # If the uploaded CSV includes ground-truth labels, calculate
                # accuracy only over rows with recognized labels. Never treat
                # unlabeled inference data as an accuracy evaluation.
                uploaded_accuracy = None
                evaluated_rows = 0
                if "Label" in result.columns:
                    def normalize_project_label(value):
                        value = str(value).strip().lower()
                        if value == "benign":
                            return "BENIGN"
                        if "portscan" in value or "port scan" in value:
                            return "PortScan"
                        if value.startswith("dos") or value == "ddos":
                            return "DoS"
                        return None

                    actual_labels = result["Label"].map(normalize_project_label)
                    predicted_labels = result["Predicted Class"].map(normalize_project_label)
                    evaluable = actual_labels.notna() & predicted_labels.notna()
                    evaluated_rows = int(evaluable.sum())
                    if evaluated_rows:
                        uploaded_accuracy = float(
                            (actual_labels[evaluable] == predicted_labels[evaluable]).mean()
                        )

                st.session_state.uploaded_test_accuracy = uploaded_accuracy
                st.session_state.uploaded_test_accuracy_n = evaluated_rows
                st.session_state.threat_results = result
                counts = pd.Series(preds).value_counts()
                m1,m2,m3 = st.columns(3)
                m1.metric("Flows analyzed", f"{len(result):,}")
                m2.metric("PortScan predictions", int((result["Predicted Class"]=="PortScan").sum()))
                m3.metric("DoS predictions", int((result["Predicted Class"]=="DoS").sum()))

                a1, a2 = st.columns(2)
                if holdout_accuracy is not None:
                    a1.metric("Model holdout accuracy", f"{float(holdout_accuracy):.2%}",
                              help="Accuracy measured on the stratified held-out test split during model training.")
                else:
                    a1.metric("Model holdout accuracy", "Unavailable",
                              help="Run the model evaluation/training cell to create model_metrics.json.")
                if uploaded_accuracy is not None:
                    a2.metric("Uploaded labelled-data accuracy", f"{uploaded_accuracy:.2%}",
                              help=f"Agreement with the uploaded CSV's ground-truth Label column across {evaluated_rows:,} labelled rows.")
                else:
                    a2.metric("Uploaded labelled-data accuracy", "Not available",
                              help="Upload a CSV with a recognized Label column to calculate accuracy. Unlabelled traffic can be classified but not scored.")
                st.dataframe(result.head(1000), use_container_width=True, hide_index=True)
                st.download_button("Download classified CSV", result.to_csv(index=False).encode(),
                                   "classified_network_flows.csv", "text/csv")
                st.bar_chart(counts)
                st.caption("Predictions are based on the trained CIC-IDS2017 model and uploaded flow records; this is not passive live network capture.")
        except Exception as e: st.error(f"Could not process flow file: {e}")
    elif st.session_state.threat_results is not None:
        st.info("Previously analyzed results are retained for this dashboard session.")

with tab3:
    st.subheader("Consolidated security report")
    st.write("The PDF combines the latest scan, HTTP indicator check, and traffic classification results from this session.")
    scan = st.session_state.scan_results
    rate = st.session_state.rate_results
    threats = st.session_state.threat_results
    st.write(f"**Port scan:** {'Available' if scan else 'Not run'}")
    st.write(f"**HTTP indicator check:** {'Available' if rate else 'Not run'}")
    st.write(f"**ML traffic analysis:** {'Available' if threats is not None else 'Not run'}")

    def build_pdf():
        path = "/content/security_audit_report.pdf"
        styles = getSampleStyleSheet()
        story = [Paragraph("AI-Assisted Web Security Audit Report", styles["Title"]),
                 Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
                 Spacer(1, 8)]
        story.append(Paragraph("1. Port and Service Audit", styles["Heading2"]))
        if scan:
            story.append(Paragraph(f"Target: {scan['target']} (resolved: {scan['resolved_ip']})", styles["Normal"]))
            story.append(Paragraph(f"Scan time: {scan['timestamp']}", styles["Normal"]))
            story.append(Paragraph("Environment context: " + scan.get("environment_note", "Not recorded."), styles["Normal"]))
            table_data = [["Port", "Protocol", "State", "Service"]]
            table_data += [[str(p["Port"]), p["Protocol"], p["State"], p["Service"]] for p in scan["ports"]]
            if len(table_data) == 1: table_data.append(["-", "-", "-", "No results in scanned range"])
            t = Table(table_data, repeatRows=1, colWidths=[25*mm, 25*mm, 25*mm, 95*mm])
            t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#243B53")),
                                   ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                   ("GRID",(0,0),(-1,-1),0.4,colors.grey),
                                   ("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"TOP")]))
            story += [t, Spacer(1, 8)]
            for p in scan["ports"]:
                if p.get("State") == "open":
                    context_text = (
                        f"Port {p['Port']} listener attribution: {p.get('Listener process', 'Unavailable')}. "
                        f"Context: {p.get('Environment context', 'Not assessed')}"
                    )
                    story.append(Paragraph(context_text, styles["Normal"]))
            story.append(Spacer(1, 4))
            story.append(Paragraph("Interpretation: an open port is an observed listening service, not by itself a confirmed vulnerability. Confirm service ownership, intended purpose, exposure scope, authentication, patching, and access controls before assigning severity.", styles["Normal"]))
            story.append(Paragraph("Recommendation: verify business need for each service, restrict access with firewall/security-group rules, and keep required services patched. For a hosted notebook loopback scan, do not attribute platform-managed services to the user's own application.", styles["Normal"]))
        else: story.append(Paragraph("No Nmap scan was run in this session.", styles["Normal"]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("2. HTTP Rate-Limit Indicator Check", styles["Heading2"]))
        if rate:
            rd = [["Request", "HTTP Status", "Observed indicators"]] + [[str(x["Request"]), str(x["HTTP Status"]), x["Rate-limit indicators"]] for x in rate]
            t = Table(rd, repeatRows=1, colWidths=[25*mm, 30*mm, 115*mm])
            t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#243B53")),
                                   ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey),
                                   ("FONTSIZE",(0,0),(-1,-1),8)]))
            story += [t, Spacer(1, 6)]
            http_successes = [x for x in rate if isinstance(x["HTTP Status"], int)]
            http_429 = [x for x in http_successes if x["HTTP Status"] == 429]
            if not http_successes:
                interpretation = "Assessment inconclusive: the HTTP service could not be reached, so rate limiting was not assessed. Verify the target URL and port."
            elif any(x["HTTP Status"] == 404 for x in http_successes):
                interpretation = "Assessment inconclusive: one or more requests returned HTTP 404, so the tested path was not found. No conclusion about application rate limiting can be drawn from this path. Repeat only against a documented, known-valid endpoint."
            elif http_429:
                interpretation = "HTTP 429 response(s) were observed, which is evidence of throttling during this limited check. Review server-side policy and logs; this does not validate the adequacy of the configured limit."
            else:
                interpretation = "No HTTP 429 response was observed. Absence of standard rate-limit headers is inconclusive and does not prove that server-side rate limiting is absent. Validate configuration at the reverse proxy/application layer."
            story.append(Paragraph("Interpretation: " + interpretation, styles["Normal"]))
        else: story.append(Paragraph("No HTTP indicator check was run.", styles["Normal"]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("3. AI Traffic Analysis", styles["Heading2"]))
        if threats is not None:
            counts = threats["Predicted Class"].value_counts()
            td = [["Predicted class", "Flow count"]] + [[str(k), str(v)] for k,v in counts.items()]
            t = Table(td, repeatRows=1, colWidths=[80*mm, 40*mm])
            t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#243B53")),
                                   ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey)]))
            story += [t, Spacer(1, 6)]
            story.append(Paragraph(f"Total analyzed flows: {len(threats)}. Predictions are model-based and should be reviewed alongside network and host context.", styles["Normal"]))
            if holdout_accuracy is not None:
                story.append(Paragraph(
                    f"Model holdout accuracy: {float(holdout_accuracy):.2%}. "
                    "This score was measured on the stratified held-out test split during model evaluation.",
                    styles["Normal"]
                ))
            uploaded_accuracy = st.session_state.get("uploaded_test_accuracy")
            uploaded_accuracy_n = int(st.session_state.get("uploaded_test_accuracy_n", 0))
            if uploaded_accuracy is not None:
                story.append(Paragraph(
                    f"Accuracy on uploaded labelled flows: {float(uploaded_accuracy):.2%} "
                    f"({round(float(uploaded_accuracy) * uploaded_accuracy_n):,} correct out of {uploaded_accuracy_n:,} labelled flows).",
                    styles["Normal"]
                ))
            else:
                story.append(Paragraph(
                    "Accuracy on uploaded flows: Not calculated because the uploaded data did not contain recognized ground-truth labels.",
                    styles["Normal"]
                ))
        else: story.append(Paragraph("No flow dataset was analyzed.", styles["Normal"]))
        story += [Spacer(1, 12), Paragraph("4. General Mitigation Recommendations", styles["Heading2"])]
        recommendations = [
            "Close unnecessary services and expose only required ports.",
            "Restrict administrative and sensitive services to trusted networks or VPN access.",
            "Apply rate limits at the application, API gateway, reverse proxy, or web-server layer.",
            "Use firewall rules, monitoring, patching, and alerting as layered controls.",
            "Investigate ML alerts with logs and packet/flow context before taking action."
        ]
        for item in recommendations: story.append(Paragraph("• " + item, styles["Normal"]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Scope note: This report reflects only the checks and uploaded flow records processed in this dashboard session. A localhost scan in Google Colab examines the hosted notebook runtime, not the user's personal computer or automatically the user's deployed application. Process attribution is best-effort. An open port is not by itself a vulnerability, and absence of rate-limit headers is not proof that rate limiting is absent. This report is not a certification or proof that a target is secure.", styles["Italic"]))
        SimpleDocTemplate(path, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
                          topMargin=16*mm, bottomMargin=16*mm).build(story)
        return path

    if st.button("Generate PDF security report", type="primary"):
        try:
            pdf_path = build_pdf()
            with open(pdf_path, "rb") as f:
                st.download_button("Download security audit report", f.read(),
                                   "AI_Web_Security_Audit_Report.pdf", "application/pdf")
        except Exception as e: st.error(f"PDF generation failed: {e}")

st.sidebar.header("Project information")
st.sidebar.write("**Model:** Random Forest")
st.sidebar.write("**Dataset:** CIC-IDS2017")
st.sidebar.write("**Classes:** BENIGN / PortScan / DoS")
st.sidebar.caption("Academic prototype. Use only with explicit authorization.")
