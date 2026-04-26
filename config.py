from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / 'model'
IOC_DIR = BASE_DIR / 'iocs'

MODEL_PATH = MODEL_DIR / 'CICIDS_baseline (2).h5'
MAPPING_PATH = MODEL_DIR / 'Mapping'
TRAIN_HEADER_SOURCE = MODEL_DIR / 'train_CICIDS2017Multiclass_NumericFS.csv'
PREPROCESSOR_PATH = MODEL_DIR / 'preprocessor.pkl'  # optional; export this from training notebook

BLACKLIST_PATH = IOC_DIR / 'blacklist.csv'
WHITELIST_PATH = IOC_DIR / 'whitelist.csv'
BLACKLISTED_PORTS_PATH = IOC_DIR / 'blacklisted_ports.csv'
ALERT_LOG_PATH = BASE_DIR / 'alerts.log'
ALERT_JSON_PATH = BASE_DIR / 'alerts.json'

# tshark / capture settings
INTERFACES = ['eth0']
TSHARK_PATH = 'tshark'
TSHARK_FIELDS = [
    'frame.time_epoch',
    'ip.src',
    'ip.dst',
    'ip.proto',
    'ip.len',
    'ip.hdr_len',
    'tcp.srcport',
    'tcp.dstport',
    'udp.srcport',
    'udp.dstport',
    'tcp.len',
    'tcp.hdr_len',
    'udp.length',
    'tcp.window_size_value',
    'tcp.flags.fin',
    'tcp.flags.reset',
    'tcp.flags.push',
    'tcp.flags.ack',
    'tcp.flags.urg',
    'tcp.flags.cwr',
    'tcp.flags.ece',
]

# Pipeline settings
SHARD_COUNT = 4
FLOW_IDLE_TIMEOUT_SEC = 15.0
ACTIVE_TIMEOUT_SEC = 20.0
ACTIVITY_GAP_SEC = 1.0
BULK_GAP_SEC = 1.0
MIN_PACKETS_BEFORE_EARLY_CLASSIFY = 4
BATCH_SIZE = 64
BATCH_WAIT_SEC = 0.5
MODEL_CONFIDENCE_THRESHOLD = 0.80
BLOCK_ON_MALICIOUS_ML = True
AUTO_BLACKLIST_ML_DETECTIONS = True
ENABLE_WHITELIST_SHORTCIRCUIT = True
BLACKLIST_FLUSH_BATCH_SIZE = 100
BLACKLIST_FLUSH_INTERVAL_SEC = 2.0

# The labels below match the uploaded Mapping file.
LABEL_MAP = {
    0: 'BENIGN',
    1: 'DoS Hulk',
    2: 'PortScan',
    3: 'DDoS',
    4: 'DoS GoldenEye',
    5: 'FTP-Patator',
    6: 'SSH-Patator',
    7: 'DoS slowloris',
    8: 'DoS Slowhttptest',
}
