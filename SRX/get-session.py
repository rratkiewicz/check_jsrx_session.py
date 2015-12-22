import sys
import argparse
import ipaddress
from lxml import etree
import xml.etree.ElementTree as ET
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError
import pprint


def get_session(source_ip,destination_ip,destination_port,protocol,device):
	dev = Device(host=device)
	try:
		dev.open()
	except ConnectError as err:
		print "Cannot connect to device: {0}".format(err)
		sys.exit(1)


	flow_args = {}
	if source_ip != None :
		flow_args['source_prefix'] = source_ip 
		
	if destination_ip != None :
		flow_args['destination_prefix'] = destination_ip

	if destination_port != None :
		flow_args['destination_port'] = destination_port

	if protocol != None :
		flow_args['protocol'] = protocol
	
	flow_request = dev.rpc.get_flow_session_information(**flow_args)
	dev.close()
	
	



	root = ET.fromstring(etree.tostring(flow_request))
	session_list = []

	for session in root.findall('./multi-routing-engine-item/flow-session-information/flow-session'):
		session_state = session.find('session-state')
		session_identifier = session.find('session-identifier')
		policy = session.find('policy')
		configured_timeout = session.find('configured-timeout')
		timeout = session.find('timeout')
		start_time = session.find('start-time')
		duration = session.find('duration')

		session_dict = {'session-id' : session_identifier.text, 'session-state' : session_state.text, 'policy' : policy.text, 'timeout' : timeout.text, \
			'start-time' : start_time.text, 'duration' : duration.text, 'configured-timeout' : configured_timeout.text }

		flow_list = []

		for flow in session.findall('./flow-information'):
			direction = flow.find('direction')
			source_address = flow.find('source-address')
			destination_address = flow.find('destination-address')
			source_port = flow.find('source-port')
			destination_port = flow.find('destination-port')
			protocol = flow.find('protocol')
			byte_count = flow.find('byte-cnt')

			session_dict.update({ direction.text + ':source-address' : source_address.text, direction.text + ':destination-address' : destination_address.text, \
			direction.text + ':source_port' : source_port.text, direction.text + ':destination-port' : destination_port.text, direction.text + ':protocol' : protocol.text,\
			direction.text + ':byte-count' : byte_count.text })
			

		if session_state.text == 'Active' :
			session_list.append(session_dict.copy())

	return session_list;

def main(argv):
	source_ip = None
	destination_ip = None
	destination_port = None
	protocol = None
	device = None


	parser = argparse.ArgumentParser()
	parser.add_argument("device",help="Specify the hostname or IP address of your Juniper SRX")
	parser.add_argument("--src_address", help="Source address or prefix of desired session(s)")
	parser.add_argument("--dst_address", help="Destination address or prefix of desired session(s)")
	parser.add_argument("--dst_port", help="Destination port of desired session(s)")
	parser.add_argument("--protocol", help="TCP or UDP, or any supported SRX protocol")
	parser.add_argument("--nagios", dest="nagios", action="store_true",  help="Nagios formatted output")

	args = parser.parse_args()

	session = get_session(args.src_address, args.dst_address, args.dst_port, args.protocol, args.device)

	if args.nagios :
		if len(session)> 0 :
			print 'SESSION OK - Session ID ' + session[0].get('session-id') + ' | bytes_in=' + session[0].get('In:byte-count') + ' bytes_out=' + session[0].get('Out:byte-count') \
			+ ' configured_timeout=' + session[0].get('configured-timeout') + ' timeout=' + session[0].get('timeout') 
		else:
			print "SESSION CRITICAL"
	else:
		pp = pprint.PrettyPrinter(indent=4)
		pp.pprint(session[0])


if __name__ == "__main__":
	main(sys.argv[1:])


