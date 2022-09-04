# pyinstaller --onefile process_monitor.py

import re
import os
import time
import signal
import subprocess
from subprocess import Popen, PIPE, check_output
import csv

# read suspicious process names from a csv
suspicious_processes = []
with open('suspicious_processes.csv', 'r') as read_obj:
    csv_reader = csv.reader(read_obj)
    list_of_rows = list(csv_reader)
    for rows in list_of_rows:
        suspicious_processes.append(rows[0])

# take tasklist output and parse the table into a dictionary
def get_live_processes():
	tasks = check_output(['tasklist']).decode('cp866', 'ignore').split("\r\n")
	processes = []
	for task in tasks:
		m = re.match(b'(.*?)\\s+(\\d+)\\s+(\\w+)\\s+(\\w+)\\s+(.*?)\\s.*', task.encode())
		if m is not None:
			processes.append({"image":m.group(1).decode(), "pid":int(m.group(2).decode())})
	return(processes)

def run():
	while True:
		live_processes = get_live_processes()
		for process in live_processes:
			# check if the process in suspicious
			if process['image'] in suspicious_processes:
				print("Killed WannaCry Related process: " + str(process['image']))
				subprocess.Popen("taskkill /F /T /PID %i"%int(process['pid']) , shell=True)
				
				print("Disabling Network Adapters")
                # disable physical network adapter
                os.system("wmic path win32_networkadapter where PhysicalAdapter=True call disable")
                # disable Wifi
                os.system("netsh interface set interface Wi-Fi disable")
	time.sleep(0.01)

if __name__ == '__main__':
	run()
