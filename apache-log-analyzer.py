#!/usr/bin/env python

'''
this script analyzes apache(2) log files and
automatically generates a summary.
'''

import sys
import os
import datetime
import time
from collections import defaultdict

COLOR_ERROR = "\033[91m"
COLOR_NORMAL = "\033[0m"
COLUMN_WIDTH = 30

poll_interval_seconds = 60
accesslog_path = ""
sensitive_chunks = []

def print_formatted(message, error=False):
	datetime_logging = datetime.datetime.now()
	error = "" if not error else ("%s[ERROR]%s " % (COLOR_ERROR, COLOR_NORMAL))
	print("[%s] %s%s" % (datetime_logging, error, message))

def print_usage():
	print_formatted("Usage: %s 'path_to_access.log' poll_interval_minutes sensitive_chunk [sensitive_chunk ...]" % sys.argv[0])

def print_summary(access_dict):
	if len(access_dict) > 0:
		table = "\n\n"
		table = table + "".join(entry.ljust(COLUMN_WIDTH) for entry in ["IP", "USER", "DATE", "PATH"])
		for ip_address in access_dict:
			table = table + "\n"
			for access in access_dict[ip_address]:
				table = table + "".join(entry.ljust(COLUMN_WIDTH) for entry in access)
				table = table + "\n"
		print_formatted("Summary: %s" % table)
	else:	
		print_formatted("No accesses with chunks '%s' found" % str(sensitive_chunks))

def minutes_to_seconds(minutes):
	return minutes * 60

def init():
	global accesslog_path
	global poll_interval_seconds
	global sensitive_chunks

	print_formatted("Initializing %s" % sys.argv[0])
	if len(sys.argv) < 4:
		print_formatted("Too few arguments: Check usage", error=True)
		raise 
	try:
		accesslog_path = sys.argv[1]
		access_log = open(accesslog_path, "r")
                access_log.close()
		poll_interval_seconds = minutes_to_seconds(int(sys.argv[2]))
	except FileNotFoundError:
		print_formatted("Could not find access.log", error=True)
		raise
	except ValueError:	
		print_formatted("Could not convert '%s' to int" % sys.argv[2], error=True)
		raise
	for i in range(3, len(sys.argv)):
		sensitive_chunks.append(sys.argv[i])

def process_accesslog_line(line):
	chunk_in_line = False
	for chunk in sensitive_chunks:
		if chunk in line:
			chunk_in_line = True
			break
	if chunk_in_line:

		# quite ugly because the space character is not the perfect split argument for
		# the apache access.log file but for the current usage it is precise enough
		columns = line.split(" ")
		ip_address = columns[0]
		username = columns[2]
		date = columns[3]
		path = columns[6]
		return [ip_address, username, date, path]
	return []

def process_accesslog():
	lines_of_interest = []
	with open(accesslog_path) as accesslog_file:
		for line in accesslog_file:
			processed_line = process_accesslog_line(line)
			if len(processed_line) > 0:
				lines_of_interest.append(process_accesslog_line(line))
	return lines_of_interest

def process_accesses_of_interest(accesses_of_interest):
	access_dict = defaultdict(list)
	for access in accesses_of_interest:
		access_dict[access[0]].append(access)
	return access_dict

def start_polling():
	print_formatted("Start polling log: '%s'" % accesslog_path)
	while True:
		time.sleep(poll_interval_seconds)
		accesses_of_interest = process_accesslog()
		access_dict = process_accesses_of_interest(accesses_of_interest)
		print_summary(access_dict)
	
if __name__ == "__main__":
	try:
		init()
	except Exception:
		print_usage()
		print_formatted("Stopping script with errors")	
	start_polling()
