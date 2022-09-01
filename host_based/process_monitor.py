import re
import os
import time
import signal
import subprocess
from subprocess import Popen, PIPE, check_output

suspicious_process = ["tasksche.exe", "@WanaDecryptor@.exe", "taskse.exe", "taskdl.exe", "mssecsvc.exe", "tasksche.exe"]

def get_processes_running():
	"""
	Takes tasklist output and parses the table into a dict
	"""
	tasks = check_output(['tasklist']).decode('cp866', 'ignore').split("\r\n")
	p = []
	for task in tasks:
		m = re.match(b'(.*?)\\s+(\\d+)\\s+(\\w+)\\s+(\\w+)\\s+(.*?)\\s.*', task.encode())
		if m is not None:
			p.append({"image":m.group(1).decode(), "pid":int(m.group(2).decode())})
	return(p)

def run():
	while True:
		lstp = get_processes_running()
		for p in lstp:
			if p['image'] in suspicious_process:
				print("Killed" + str(p['image']))
				subprocess.Popen("taskkill /F /T /PID %i"%int(p['pid']) , shell=True)
	time.sleep(0.01)

if __name__ == '__main__':
	run()