# reporter.py

import sys
import json
import requests

def send_report(url, data_dict):
    """
    Sends the data to the specified URL via a POST request.
    This function is designed to be called by the command line.
    """
    try:
        # Send the data to the dashboard
        requests.post(url, json=data_dict, timeout=2)
    except Exception:
        # This separate process will fail silently if the dashboard is not running.
        # This is safe and prevents crashing the main Ryu application.
        pass

if __name__ == '__main__':
    # This block of code runs ONLY when the file is executed directly as a script.
    # We expect 3 command-line arguments:
    # 1. The script name itself (e.g., 'reporter.py')
    # 2. The URL for the dashboard (e.g., 'http://127.0.0.1:5000/log')
    # 3. The data to send, formatted as a single JSON string
    if len(sys.argv) == 3:
        dashboard_url = sys.argv[1]
        json_data_string = sys.argv[2]
        
        # Convert the JSON string from the command line back into a Python dictionary
        try:
            log_data = json.loads(json_data_string)
            send_report(dashboard_url, log_data)
        except json.JSONDecodeError:
            # Handle cases where the JSON data from the main app might be malformed
            pass
