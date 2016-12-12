#!/usr/bin/env python
"""#
# Author: Ryan Ratkiewicz (<ryan ATSIGN ryanrat.com>)
# check_jsrx_session.py
# Last-Modified:  2016-12-12
# Version 0.1.1
#
# get_session.py was originally intended to pull a specific session from the Juniper SRX Firewall
# via PYEZ from a Nagios host. The script relies upon version 2.7 of Python, although earlier
# versions may also work.
#
# Example:
# python check_jsrx_session.py myfirewall.corp.com
# Will return all sessions in the firewall in a pretty print format.
#
# python check_jsrx_session.py myfirewall.corp.com --src_address x.x.x.x --dst_address y.y.y.y
#    --dst_port 80 --protocol tcp
#    Will return all sessions that match specified criteria.
#
# python check_jsrx_session.py myfirewall.corp.com --src_address x.x.x.x --dst_address y.y.y.y
#    --dst_port 80 --protocol tcp --nagios_bytes
#    Will return all sessions that match specified criteria, but evaluate
#    only the first match in a Nagios output format.
#
# Output Example:
#    SESSION OK - Session ID 31432 | bytes_in=17515 bytes_out=4786 configured_timeout=43200
#    timeout=43094
#
# python check_jsrx_session.py --username XXXXXX --password YYYYYYY
# Will return all sessions, but leverage a username and password in lieu of SSH keys.
#
# python check_jsrx_session.py myfirewall.corp.com --src_address x.x.x.x --dst_address y.y.y.y
#   --dst_port 80 --protocol tcp --nagios_bytes --debug
#   Will return all sessions that match the specified critera, and also show the facts and
#   session parameters sent to the SRX.
# Output Exmaple:
# {   '2RE': True,
#
#    'HOME': '/cf/var/home/user',
#    'RE0': {   'last_reboot_reason': '0x1:power cycle/failure',
#               'model': 'RE-SRX210HE2',
#               'status': 'OK',
#               'up_time': '12 days, 19 hours, 35 minutes, 44 seconds'},
#    'RE1': {   'last_reboot_reason': '0x1:power cycle/failure',
#               'model': 'RE-SRX210HE2',
#               'status': 'OK',
#               'up_time': '12 days, 19 hours, 18 minutes, 48 seconds'},
#    'RE_hw_mi': True,
#   ...
#   ...
#   {  'destination_port': '80',
#      'destination_prefix': 'x.x.x.x',
#      'protocol': 'tcp',
#      'source_prefix': 'y.y.y.y'}
#   OK - Session ID 31539 | bytes_in=3884785;bytes_out=3843606;;"""



import sys
import argparse
import xml.etree.ElementTree as ET
import pprint
from lxml import etree
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError

# Since the SRX returns XML data, we parse the XML using etree, and place the corresponding data
# session elements inside a dictionary.  We then also parse each flow or wing element of the
# session and add it to the dictionary. In order to distinguish between 'in' and 'out' wings, we
# prepend the dictionary with the 'direction' element of the wing, thus giving us a unique key for
# the flow.

def get_session(source_ip, destination_ip, destination_port, protocol, device,
                username, password, debug):
    """get_session returns a list of dictionary items that contain Juniper SRX session data based upon
    # the input criteria given. device is the only mandatory field for this, as if no other options are
    # specified, all sessions will be returned. if the SRX is clustered, Backup sessions from the
    # passive device are not included in the list.  Netconf must be enabled on the firewall."""

    if (username and password) != None:
        dev = Device(host=device, user=username, password=password)
    else:
        dev = Device(host=device)

    try:
        dev.open()
        if debug:
            pp = pprint.PrettyPrinter(indent=4)
            pp.pprint(dev.facts)
    except ConnectError as err:
        print "Cannot connect to device: {0}".format(err)
        sys.exit(1)


    flow_args = {}
    if source_ip != None:
        flow_args['source_prefix'] = source_ip

    if destination_ip != None:
        flow_args['destination_prefix'] = destination_ip

    if destination_port != None:
        flow_args['destination_port'] = destination_port

    if protocol != None:
        flow_args['protocol'] = protocol

    flow_request = dev.rpc.get_flow_session_information(**flow_args)
    if debug:
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(flow_args)

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

        session_dict = {'session-id' : session_identifier.text,\
        'session-state' : session_state.text, 'policy' : policy.text, 'timeout' : timeout.text,\
		'start-time' : start_time.text, 'duration' : duration.text,
                        'configured-timeout' : configured_timeout.text}

        for flow in session.findall('./flow-information'):
            direction = flow.find('direction')
            source_address = flow.find('source-address')
            destination_address = flow.find('destination-address')
            source_port = flow.find('source-port')
            destination_port = flow.find('destination-port')
            protocol = flow.find('protocol')
            byte_count = flow.find('byte-cnt')

            session_dict.update({direction.text + ':source-address' :\
            source_address.text, direction.text + ':destination-address' :\
            destination_address.text, direction.text + ':source_port' :\
            source_port.text, direction.text + ':destination-port' :\
            destination_port.text, direction.text + ':protocol' :\
            protocol.text, direction.text + ':byte-count' : byte_count.text})


        if session_state.text == 'Active':
            session_list.append(session_dict.copy())
    return session_list




def main(argv):
    """# Main declares a standard parser and passes the arguments to get_session.  Once
    # the output is returned back to main, we evaluate if args.nagios is being used,
    # and if so, it returns output that will allow Nagios to evaluate the health of
    # the service, and also pass perf data after the '|' (pipe) delimiter.  If Nagios
    # is not specified, the main function returns a pretty printed version of the
    # session data."""

    parser = argparse.ArgumentParser()
    nagiosGroup = parser.add_mutually_exclusive_group()
    parser.add_argument("device", help="Specify the hostname or IP address of your Juniper SRX")
    parser.add_argument("--src_address", help="Source address or prefix of desired session(s)")
    parser.add_argument("--dst_address", help="Destination address or prefix of desired session(s)"\
    )
    parser.add_argument("--dst_port", help="Destination port of desired session(s)")
    parser.add_argument("--protocol", help="TCP or UDP, or any supported SRX protocol")
    nagiosGroup.add_argument("--nagios_bytes", dest="nagios_bytes", action="store_true",\
        help="Nagios formatted output to return byte counts")
    nagiosGroup.add_argument("--nagios_timeouts", dest="nagios_timeouts", action="store_true",\
        help="Nagios formatted output to return session timeouts")
    parser.add_argument("--username", help="Username to firewall, in the event ssh-keys are not\
     available")
    parser.add_argument("--password", help="Password to firewall, in the event ssh-keys are not\
     available")
    parser.add_argument("--debug", dest="debug", action="store_true", help="Debug connection and\
    flow information")

    args = parser.parse_args()

    session = get_session(args.src_address, args.dst_address, args.dst_port, args.protocol,\
              args.device, args.username, args.password, args.debug)

    if args.nagios_bytes:
        if len(session) == 0:
            print 'CRITICAL - No session found'
            sys.exit(2)

        print 'OK - Session ID ' + session[0].get('session-id') + ' | bytes_in=' + session[0].get\
            ('In:byte-count') + ';bytes_out=' + session[0].get('Out:byte-count')+ ';;'

        print 'Policy=' + session[0].get('policy') + ' Source=' + session[0].get\
            ('In:source-address') + ' Destination=' + session[0].get('In:destination-address') + \
            ' DestinationPort=' + session[0].get('In:destination-port')
        (sys.exit(0))

    elif args.nagios_timeouts:
        if len(session) == 0:
            print 'CRITICAL - No session found'
            sys.exit(2)

        print 'OK - Session ID ' + session[0].get('session-id') + ' | configured_timeout=' +\
        session[0].get('configured-timeout') + ';timeout=' + session[0].get('timeout') + ';;'

        print 'Policy=' + session[0].get('policy') + ' Source=' + session[0].get\
        ('In:source-address') + ' Destination=' + session[0].get('In:destination-address') + \
        ' DestinationPort=' + session[0].get('In:destination-port')
        (sys.exit(0))

    else:
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(session)


if __name__ == "__main__":
    main(sys.argv[1:])
