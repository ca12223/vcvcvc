#!/usr/bin/env python3
import time
import re
import pandas as pd
import ipaddress
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import yagmail
import os
import warnings
import json

# --- Ignore warnings ---
warnings.filterwarnings("ignore", message=".*arrow.*", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*DeprecationWarning:.*pandas.*", category=DeprecationWarning)

# --- Configuration (env override) ---
INFLUX_URL = os.getenv("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iot-admin-token-123")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iot-org")
SRC_BUCKET = os.getenv("SRC_BUCKET", "iot-data")
ALERT_BUCKET = os.getenv("ALERT_BUCKET", "iot-data")

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO", "").split(",")

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "300"))
PAYLOAD_LIMIT = int(os.getenv("PAYLOAD_LIMIT", "1024"))

# Thresholds (tune as needed)
RECONNECT_THRESHOLD = int(os.getenv("RECONNECT_THRESHOLD", "5"))
RETAIN_THRESHOLD = int(os.getenv("RETAIN_THRESHOLD", "5"))
PUBLISH_FLOOD_THRESHOLD = int(os.getenv("PUBLISH_FLOOD_THRESHOLD", "10"))
ENUMERATION_THRESHOLD = int(os.getenv("ENUMERATION_THRESHOLD", "5"))

ANOMALY_KEYWORDS = [
    "AAAAAA", "script", "DROP TABLE", "rm -rf", "<script>",
    "SELECT", "UNION", "payload_attack", "alert(", "onload=",
    "wildcard_abuser", "flood_attacker", "duplicate_attacker", "topic_enum",
    "replayer", "retain_abuse", "attack_type", "abuse", "storm_data",
    "flood_payload", "retain_data"
]

# <<< ADDED >>>
# Thêm danh sách tiền tố Client ID đáng ngờ
SUSPICIOUS_CLIENT_ID_PREFIXES = [
    "anomaly_attacker",
    "mqtt-fuzzer",
    "test_client_malicious",
    "mqtt_stress"
]
# <<< END ADDED >>>

VALID_TOPICS = [
    "factory/office/", "factory/security/", "factory/production/",
    "factory/storage/", "factory/energy/", "system/status", "system/health"
]

PRIVATE_NETS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
]

ALERT_COOLDOWN = {}
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))  # 5 phút


# --- Utilities ---
def send_email(subject, message):
    try:
        if not EMAIL_USER or not EMAIL_PASS or not EMAIL_TO or all(e.strip() == "" for e in EMAIL_TO):
            print("[WARN] Email credentials not configured, skipping send.")
            return
        yag = yagmail.SMTP(EMAIL_USER, EMAIL_PASS)
        full_msg = f"{message}\n\n[Time: {datetime.now().isoformat()}] [Detected at: {INFLUX_URL}]"
        yag.send(to=EMAIL_TO, subject=subject, contents=full_msg)
        print(f"[EMAIL] Sent: {subject}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def should_alert(key):
    now = time.time()
    if key in ALERT_COOLDOWN and now - ALERT_COOLDOWN[key] < COOLDOWN_SECONDS:
        return False
    ALERT_COOLDOWN[key] = now
    return True


def write_alert(write_api, alert_type, src_ip, client_id, message):
    try:
        safe_client_id = str(client_id).strip() if client_id is not None else "unknown"
        if safe_client_id.lower() in ["nan", "none", ""]:
            safe_client_id = "unknown"
        point = (
            Point("mqtt_alert")
            .tag("type", alert_type)
            .tag("src_ip", src_ip or "unknown")
            .tag("client_id", safe_client_id)
            .field("message", message)
            .time(time.time_ns(), WritePrecision.NS)
        )
        write_api.write(bucket=ALERT_BUCKET, org=INFLUX_ORG, record=point)
        print(f"[ALERT] {alert_type} | {src_ip} | client_id: {safe_client_id} | {message[:120]}")
    except Exception as e:
        print(f"[WRITE ERROR] {e}")


def is_public(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in PRIVATE_NETS)
    except:
        return False


def parse_subscribe_topics(topics_str):
    """Parse topics JSON string from subscribe field, return set of unique topics."""
    if not topics_str or topics_str == "[]":
        return set()
    try:
        topics_list = json.loads(topics_str)
        if isinstance(topics_list, list):
            return set(t.get("topic", "") for t in topics_list)
    except:
        # fallback: try to split by comma / whitespace
        cleaned = re.sub(r'[\[\]\"]', '', str(topics_str))
        parts = [p.strip() for p in re.split(r'[,\s]+', cleaned) if p.strip()]
        return set(parts)
    return set()


def detect_wildcard_abuse(topics_set):
    if not topics_set:
        return False
    for topic in topics_set:
        if topic.count("#") > 0 or topic.count("+") > 2:
            return True
    return False


def detect_payload_anomaly(payload):
    if not payload:
        return False
    if len(payload) > PAYLOAD_LIMIT:
        return True
    payload_lower = payload.lower()
    for kw in ANOMALY_KEYWORDS:
        if kw.lower() in payload_lower:
            return True
    if re.search(r"[^a-zA-Z0-9\s\.,:{}_\-\[\]\(\)\"']", payload) and len(payload) > 500:
        return True
    return False


def detect_http_flood(df):
    # Detect HTTP dashboard flood (proxy events)
    if "app_proto" in df.columns:
        # <<< CHANGED >>>: Sửa logic check http
        # Giờ đây chúng ta tìm các sự kiện có app_proto == 'http' (từ fileinfo hoặc http)
        http_df = df[df["app_proto"] == "http"]
        # <<< END CHANGED >>>

        if http_df is None or http_df.empty:
            return None
        flood_counts = http_df.groupby("src_ip").size().reset_index(name="count")
        for _, row in flood_counts.iterrows():
            if row["count"] > 10:  # Ngưỡng flood HTTP
                return row["src_ip"], row["count"]
    return None


# --- Main ---
def main():
    print("[INIT] Connecting to InfluxDB...")
    client = None
    query_api = None
    write_api = None

    while True:
        try:
            client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            query_api = client.query_api()
            write_api = client.write_api(write_options=SYNCHRONOUS)
            # quick health check
            client.health()
            print("[INIT] Connected successfully. Query API ready.")
            break
        except Exception as e:
            print(f"[CONNECT ERROR] {e}. Retrying in 10s...")
            time.sleep(10)

    # detection loop
    while True:
        try:
            query = f'''
            from(bucket: "{SRC_BUCKET}")
              |> range(start: -{WINDOW_SECONDS}s)
              |> filter(fn: (r) => r._measurement == "mqtt_event")
              // <<< REMOVED >>>: Xóa dòng rename không cần thiết
              // |> rename(columns: {{ client_id: "client_id_field" }}) 
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
              // <<< CHANGED >>>: Đảm bảo 'keep' bao gồm tất cả các trường mới từ Field.txt và HTTP
              |> keep(columns: [
                  "_time", "src_ip", "client_id", "mqtt_type", "topic", "payload_raw", 
                  "retain", "qos", "client_identifier", "bytes_toserver", "pkts_toserver", 
                  "state", "protocol_version", "flags_clean_session", "flags_username", 
                  "flags_password", "flags_will", "flags_will_retain", "topics", 
                  "dup", "message_id", "password", "protocol_string", "return_code", 
                  "session_present", "username", "qos_granted", "reason_codes",
                  "event_type", "app_proto", "http_method", "url", "status", "length"
              ])
            '''  # <<< END CHANGED >>>

            # Use query_data_frame to get DataFrame(s)
            df = query_api.query_data_frame(org=INFLUX_ORG, query=query)

            # query_data_frame may return a list of DataFrames
            if isinstance(df, list):
                if len(df) == 0:
                    print(f"[QUERY] No tables returned from Influx for last {WINDOW_SECONDS}s. Sleeping...")
                    time.sleep(CHECK_INTERVAL)
                    continue
                df = pd.concat(df, ignore_index=True)

            # If still empty
            if df is None or df.empty:
                print(f"[QUERY] No data in last {WINDOW_SECONDS}s. Sleeping...")
                time.sleep(CHECK_INTERVAL)
                continue

            # Debug
            print(f"[QUERY] Processed {len(df)} rows.")
            # print("[DEBUG] Columns:", list(df.columns)) # Bỏ comment nếu cần debug
            # print a small sample safely
            # try:
            #     print("[DEBUG] Sample:\n", df.head(3).to_string())
            # except:
            #     pass

            # --- Normalize columns safely ---
            # client_id (từ tag) SẼ luôn tồn tại (vì forwarder đã thêm "unknown" cho http)
            # client_identifier (từ field 'connect') SẼ tồn tại nếu có gói connect
            if "client_id" not in df.columns and "client_identifier" in df.columns:
                # Logic này vẫn giữ nguyên, phòng trường hợp tag client_id bị thiếu
                df["client_id"] = df["client_identifier"]
            else:
                # Đảm bảo cột client_id tồn tại (cho các sự kiện http/flow)
                df["client_id"] = df.get("client_id", pd.Series(["unknown"] * len(df)))

            # <<< CHANGED >>>: Thêm các trường mới từ Field.txt vào chuẩn hóa
            if "payload_raw" not in df.columns:
                df["payload_raw"] = ""
            if "topic" not in df.columns:
                df["topic"] = ""
            if "topics" not in df.columns:  # Cho subscribe
                df["topics"] = "[]"
            if "retain" not in df.columns:
                df["retain"] = "0"
            if "qos" not in df.columns:
                df["qos"] = "0"
            if "src_ip" not in df.columns:
                df["src_ip"] = "unknown"
            # <<< END CHANGED >>>

            # Ensure types
            df["retain"] = df["retain"].astype(str)
            df["qos"] = df["qos"].astype(str)

            # Prepare subscribe_df for subscribe-related rules
            subscribe_df = df[df.get("mqtt_type") == "subscribe"] if "mqtt_type" in df.columns else pd.DataFrame()

            # ---------------- RULES ----------------
            # (Các quy tắc bên dưới không cần thay đổi vì chúng dựa trên các cột
            # đã được chuẩn hóa ở trên, và các cột này (topic, topics, retain, qos, v.v.)
            # hiện đã được điền đúng bởi forwarder mới)
            # -----------------------------------------

            # Rule: Duplicate client_id (multiple CONNECT)
            if "mqtt_type" in df.columns:
                try:
                    connect_df = df[df["mqtt_type"] == "connect"]
                    if not connect_df.empty:
                        # Nhóm theo client_id (từ tag hoặc field đã chuẩn hóa)
                        dup_counts = connect_df.groupby("client_id").size().reset_index(name="count")
                        for _, row in dup_counts.iterrows():
                            if int(row["count"]) >= 2:
                                client = row["client_id"]
                                key = ("duplicate_id", client)
                                if should_alert(key):
                                    ips = connect_df[connect_df["client_id"] == client]["src_ip"].unique().tolist()
                                    msg = f"Duplicate client_id '{client}' connected {row['count']} times in last {WINDOW_SECONDS}s from IPs: {ips}"
                                    write_alert(write_api, "duplicate_id", ",".join(ips) if len(ips) else "unknown",
                                                client, msg)
                                    send_email("MQTT Duplicate ID Attack", msg)
                except Exception as e:
                    print(f"[RULE ERROR] duplicate_id: {e}")

            # Rule: Reconnect storm (many connect/disconnect)
            if "mqtt_type" in df.columns:
                try:
                    recon_df = df[df["mqtt_type"].isin(["connect", "disconnect"])]
                    if not recon_df.empty:
                        recon_counts = recon_df.groupby(["src_ip", "client_id"]).size().reset_index(name="count")
                        for _, row in recon_counts.iterrows():
                            if int(row["count"]) >= RECONNECT_THRESHOLD:
                                key = ("reconnect_storm", row["src_ip"], row["client_id"])
                                if should_alert(key):
                                    msg = f"Reconnect storm: {row['count']} events from {row['src_ip']} (client_id: {row['client_id']})"
                                    write_alert(write_api, "reconnect_storm", row["src_ip"], row["client_id"], msg)
                                    send_email("Reconnect Storm", msg)
                except Exception as e:
                    print(f"[RULE ERROR] reconnect_storm: {e}")

            # Rule: Wildcard abuse in subscribe topics
            if not subscribe_df.empty:
                try:
                    subscribe_df = subscribe_df.copy()
                    # Cột 'topics' (json string) giờ đã được forwarder cung cấp
                    subscribe_df["topics_set"] = subscribe_df["topics"].apply(
                        lambda x: parse_subscribe_topics(x) if "topics" in subscribe_df.columns else set())
                    for idx, row in subscribe_df.iterrows():
                        if detect_wildcard_abuse(row.get("topics_set", set())):
                            key = ("wildcard_abuse", row.get("src_ip", "unknown"), row.get("client_id", "unknown"))
                            if should_alert(key):
                                bad_topics = [t for t in row.get("topics_set", []) if "#" in t or "+" in t]
                                msg = f"Wildcard abuse topics: {bad_topics} from {row.get('src_ip', 'unknown')} (client_id: {row.get('client_id', 'unknown')})"
                                write_alert(write_api, "wildcard_abuse", row.get("src_ip", "unknown"),
                                            row.get("client_id", "unknown"), msg)
                                send_email("Wildcard Abuse", msg)
                except Exception as e:
                    print(f"[RULE ERROR] wildcard_abuse: {e}")

            # Rule: Retain + QoS abuse (publish with retain=1 and high qos)
            try:
                # Các cột 'retain' và 'qos' giờ đã được forwarder cung cấp
                if "mqtt_type" in df.columns and "retain" in df.columns:
                    retain_df = df[(df["mqtt_type"] == "publish") & (df["retain"].astype(str) == "1") & (
                        df["qos"].isin(["1", "2"]))]
                    if not retain_df.empty:
                        retain_counts = retain_df.groupby(["src_ip", "client_id"]).size().reset_index(name="count")
                        for _, row in retain_counts.iterrows():
                            if int(row["count"]) >= RETAIN_THRESHOLD:
                                key = ("retain_qos_abuse", row["src_ip"], row["client_id"])
                                if should_alert(key):
                                    msg = f"Retain QoS abuse ({row['count']} msgs) from {row['src_ip']} (client_id: {row['client_id']})"
                                    write_alert(write_api, "retain_qos_abuse", row["src_ip"], row["client_id"], msg)
                                    send_email("Retain QoS Abuse", msg)
            except Exception as e:
                print(f"[RULE ERROR] retain_qos_abuse: {e}")

            # Rule: Payload anomaly (publish)
            try:
                if "mqtt_type" in df.columns:
                    payload_df = df[df["mqtt_type"].isin(["publish", "publish_flow"])]
                else:
                    payload_df = df.copy()
                if "payload_raw" in payload_df.columns:
                    for _, row in payload_df.iterrows():
                        payload = str(row.get("payload_raw", ""))
                        if detect_payload_anomaly(payload):
                            key = ("payload_anomaly", row.get("src_ip", "unknown"), row.get("client_id", "unknown"))
                            if should_alert(key):
                                msg = f"Payload anomaly from {row.get('src_ip', 'unknown')} (client_id={row.get('client_id', 'unknown')}) | Sample: {payload[:200]}..."
                                write_alert(write_api, "payload_anomaly", row.get("src_ip", "unknown"),
                                            row.get("client_id", "unknown"), msg)
                                send_email("Payload Anomaly", msg)
            except Exception as e:
                print(f"[RULE ERROR] payload_anomaly: {e}")

            # Rule: Unauthorized topic (publish/subscribe)
            try:
                # Cột 'topic' giờ đã được forwarder cung cấp
                if "mqtt_type" in df.columns and "topic" in df.columns:
                    topic_df = df[df["mqtt_type"].isin(["publish", "subscribe"]) & (df["topic"].astype(str) != "")]
                    for idx, row in topic_df.iterrows():
                        topic = str(row.get("topic", ""))
                        if not any(topic.startswith(v) for v in VALID_TOPICS):
                            key = ("unauthorized_topic", row.get("src_ip", "unknown"), row.get("client_id", "unknown"),
                                   topic[:50])
                            if should_alert(key):
                                msg = f"Unauthorized topic '{topic}' ({row.get('mqtt_type')}) from {row.get('src_ip', 'unknown')} (client_id: {row.get('client_id', 'unknown')})"
                                write_alert(write_api, "unauthorized_topic", row.get("src_ip", "unknown"),
                                            row.get("client_id", "unknown"), msg)
                                send_email("Unauthorized Topic", msg)
            except Exception as e:
                print(f"[RULE ERROR] unauthorized_topic: {e}")

            # Rule: Publish Flood (count publishes per ip/client)
            try:
                if "mqtt_type" in df.columns:
                    publish_df = df[df["mqtt_type"].isin(["publish", "publish_flow"])]
                else:
                    publish_df = pd.DataFrame()
                if not publish_df.empty:
                    flood_counts = publish_df.groupby(["src_ip", "client_id"]).size().reset_index(name="count")
                    for _, row in flood_counts.iterrows():
                        if int(row["count"]) > PUBLISH_FLOOD_THRESHOLD:
                            key = ("publish_flood", row["src_ip"], row["client_id"])
                            if should_alert(key):
                                msg = f"Publish flood: {row['count']} msgs from {row['src_ip']} (client_id: {row['client_id']})"
                                write_alert(write_api, "publish_flood", row["src_ip"], row["client_id"], msg)
                                send_email("MQTT Publish Flood", msg)
            except Exception as e:
                print(f"[RULE ERROR] publish_flood: {e}")

            # Rule: Topic Enumeration (many unique subscribe topics)
            try:
                if not subscribe_df.empty:
                    subscribe_df = subscribe_df.copy()
                    # Cột 'topics' (json string) giờ đã được forwarder cung cấp
                    subscribe_df["topics_set"] = subscribe_df["topics"].apply(
                        lambda x: parse_subscribe_topics(x) if "topics" in subscribe_df.columns else set())
                    # union sets per (src_ip, client_id)
                    grouped = subscribe_df.groupby(["src_ip", "client_id"])["topics_set"].agg(
                        lambda s: set().union(*s) if len(s) > 0 else set()).reset_index(name="unique_topics_set")
                    grouped["unique_topics"] = grouped["unique_topics_set"].apply(len)
                    for _, row in grouped.iterrows():
                        if int(row["unique_topics"]) > ENUMERATION_THRESHOLD:
                            key = ("topic_enumeration", row["src_ip"], row["client_id"])
                            if should_alert(key):
                                msg = f"Topic enumeration: {row['unique_topics']} unique topics from {row['src_ip']} (client_id: {row['client_id']})"
                                write_alert(write_api, "topic_enumeration", row["src_ip"], row["client_id"], msg)
                                send_email("Topic Enumeration", msg)
            except Exception as e:
                print(f"[RULE ERROR] topic_enumeration: {e}")

            # Rule: HTTP dashboard flood (proxy for probes)
            try:
                # Hàm này giờ sẽ hoạt động vì forwarder đã gửi log http
                http_flood = detect_http_flood(df)
                if http_flood:
                    src_ip, count = http_flood
                    key = ("http_dashboard_flood", src_ip)
                    if should_alert(key):
                        msg = f"HTTP dashboard flood: {count} requests from {src_ip} (possible attack probe)"
                        write_alert(write_api, "http_dashboard_flood", src_ip, "unknown", msg)
                        send_email("HTTP Dashboard Flood", msg)
            except Exception as e:
                print(f"[RULE ERROR] http_dashboard_flood: {e}")
                
            # <<< ADDED >>>
            # Rule: Suspicious Client ID
            # Phát hiện client ID khớp với các tiền tố tấn công đã biết (ví dụ: anomaly_attacker)
            try:
                # Cột client_id đã được chuẩn hóa ở trên
                if "client_id" in df.columns:
                    # Lấy các client_id duy nhất đã thấy (khác "unknown")
                    unique_client_ids = df[df["client_id"] != "unknown"]["client_id"].unique()
                    
                    for client_id in unique_client_ids:
                        client_id_lower = str(client_id).lower()
                        for prefix in SUSPICIOUS_CLIENT_ID_PREFIXES:
                            if client_id_lower.startswith(prefix.lower()):
                                # Tìm thấy client đáng ngờ
                                key = ("suspicious_client_id", client_id)
                                if should_alert(key):
                                    # Lấy IP từ dòng đầu tiên thấy client này
                                    row = df[df["client_id"] == client_id].iloc[0]
                                    src_ip = row.get("src_ip", "unknown")
                                    msg = f"Suspicious client_id detected: '{client_id}' matches prefix '{prefix}' from {src_ip}"
                                    write_alert(write_api, "suspicious_client_id", src_ip, client_id, msg)
                                    send_email("Suspicious MQTT Client ID", msg)
                                break # Đã cảnh báo, chuyển sang client_id tiếp theo
            except Exception as e:
                print(f"[RULE ERROR] suspicious_client_id: {e}")
            # <<< END ADDED >>>

        except Exception as e:
            print(f"[ERROR] Query/Detect: {e}")
            # swallow and continue loop to avoid crash
            time.sleep(CHECK_INTERVAL)
            continue

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()