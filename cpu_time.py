import os
import sys
import time
import psutil
import datetime
import statistics

def check_cpu():
	cpu_usage = []
	sum = 0.0
	i = 1
	
	try:
		print("  CPU Usage % \t\tSystem Time  \t\t  Real Time Average")
		while True:
			usage = psutil.cpu_percent()
			cpu_usage.append(usage)
			sum += usage
			print("    ", usage, "\t ", datetime.datetime.now(), "\t\t", sum/i)
			i += 1
			time.sleep(1)
	except KeyboardInterrupt:
		print("Interrupted")
		print(cpu_usage)
		print("Datapoints: ", len(cpu_usage))
		print("Average : ", statistics.mean(cpu_usage))
		try:
			sys.exit(0)
		except SystemExit:
			os._exit(0)


check_cpu()
