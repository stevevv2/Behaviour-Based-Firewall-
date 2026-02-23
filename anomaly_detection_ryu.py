# anomaly_detection_ryu.py

import eventlet
# This simple patch is now safe because 'requests' is never imported in this process.
eventlet.monkey_patch()

# Standard libraries. These are all safe.
import os
import sys
import json
import subprocess

# Ryu-specific imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub

# Machine Learning libraries
import numpy as np
import joblib

# Paths to your models and dashboard
ISOF_PATH = os.path.expanduser("~/PROJECT/ryu/isoforest_model.pkl")
SCALER_PATH = os.path.expanduser("~/PROJECT/ryu/feature_scaler.pkl")
DASHBOARD_URL = "http://127.0.0.1:5000/log"

# Define the feature names/abbreviations in the correct order.
FEATURE_NAMES = [
    'FlowDur',       # Flow Duration
    'FwdPkts',       # Total Fwd Packets
    'FwdPktLen',     # Total Length of Fwd Packets
    'FlowBytes/s',
    'FlowPkts/s'
]

class AnomalyDetectionSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnomalyDetectionSwitch, self).__init__(*args, **kwargs)
        try:
            self.isolation_model = joblib.load(ISOF_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.logger.info("✅ 5-Feature Isolation Forest and Scaler loaded successfully.")
        except FileNotFoundError as e:
            self.logger.error(f"❌ Model or Scaler File Missing: {e}")
            sys.exit(f"Exiting: {e}")

        self.datapaths, self.mac_to_port = {}, {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("✅ Switch %s connected.", hex(datapath.id))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                              idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                              buffer_id=buffer_id or ofproto.OFP_NO_BUFFER)
        datapath.send_msg(mod)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        datapath.send_msg(datapath.ofproto_parser.OFPFlowStatsRequest(datapath))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            if stat.priority != 1: continue
            try:
                # --- Create feature values ---
                flow_duration = stat.duration_sec
                total_fwd_packets = stat.packet_count
                total_length_fwd_packets = stat.byte_count
                flow_packets_per_s = total_fwd_packets / flow_duration if flow_duration > 0 else 0
                flow_bytes_per_s = total_length_fwd_packets / flow_duration if flow_duration > 0 else 0
                
                feature_values = [
                    flow_duration, total_fwd_packets, total_length_fwd_packets, 
                    flow_bytes_per_s, flow_packets_per_s
                ]
                
                # Model needs a numpy array
                features_np = np.array([feature_values])

                scaled = self.scaler.transform(features_np)
                is_anomaly = (self.isolation_model.predict(scaled)[0] == -1)
                
                # Dashboard needs a dictionary with names
                features_dict = dict(zip(FEATURE_NAMES, feature_values))
                result = {"switch_id": hex(ev.msg.datapath.id), "features": features_dict}
                
                if is_anomaly:
                    result.update({"anomaly": "YES", "attack_type": "ANOMALY", "action": "DROP"})
                    self.logger.warning(f"🚨 ANOMALY DETECTED on {result['switch_id']}")
                    self.block_flow(ev.msg.datapath, stat.match)
                else:
                    result.update({"anomaly": "NO", "attack_type": "Normal Traffic", "action": "ALLOW"})
                    self.logger.info(f"✅ Normal traffic detected. Reporting to dashboard.")
                
                self.report_to_dashboard(result)
            except Exception as e:
                self.logger.error(f"❌ Error during stats analysis: {e}")

    def block_flow(self, datapath, match):
        self.add_flow(datapath, 10, match, [], hard_timeout=300)
        self.logger.info(f"⛔ Block rule installed for: {match}")

    def report_to_dashboard(self, data):
        """
        Executes reporter.py in a separate, completely clean process, passing
        data as a command-line argument. This is the definitive way to isolate
        the 'requests' library from the Ryu eventlet loop.
        """
        try:
            # Get the path to the current Python executable to ensure the subprocess uses the same environment.
            python_executable = sys.executable
            
            # Convert the data dictionary to a JSON string that can be passed as a single command-line argument.
            data_string = json.dumps(data)
            
            # Get the full path to the reporter.py script to make sure it's found.
            reporter_path = os.path.join(os.path.dirname(__file__), 'reporter.py')
            
            # Define the command to execute: 'python reporter.py <url> <json_data>'
            command = [python_executable, reporter_path, DASHBOARD_URL, data_string]
            
            # Use Popen to launch the command in the background without blocking the Ryu app.
            # stdout and stderr are redirected to DEVNULL to prevent cluttering the main Ryu log.
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        except Exception as e:
            self.logger.error("Failed to spawn reporter process: %s", e)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg, datapath = ev.msg, ev.msg.datapath
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        in_port, pkt = msg.match['in_port'], packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            return

        dst, src, dpid = eth.dst, eth.src, datapath.id
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=20)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER: return

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
