import gnlpy.netlink as netlink
import socket, struct
from pprint import pprint
MinutemanVIPAttrList = netlink.create_attr_list_type('MinutemanVIPAttrList',
  ('MINUTEMAN_ATTR_VIP', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_VIP_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_VIP_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_VIP_BE', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_BE', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_BE_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_BE_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_BE_REACH', netlink.U8Type),
  ('MINUTEMAN_ATTR_BE_CONSECUTIVE_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_LAST_FAILURE', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_PENDING', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_SUCCESSES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_NOW', netlink.U64Type),
)

MinutemanBEAttrList = netlink.create_attr_list_type('MinutemanBEAttrList',
  ('MINUTEMAN_ATTR_VIP', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_VIP_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_VIP_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_VIP_BE', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_BE', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_BE_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_BE_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_BE_REACH', netlink.U8Type),
  ('MINUTEMAN_ATTR_BE_CONSECUTIVE_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_LAST_FAILURE', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_PENDING', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_SUCCESSES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_NOW', netlink.U64Type),
)

MinutemanVIPBEAttrList = netlink.create_attr_list_type('MinutemanVIPBEAttrList',
  ('MINUTEMAN_ATTR_VIP', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_VIP_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_VIP_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_VIP_BE', netlink.IgnoreType),
  ('MINUTEMAN_ATTR_BE', netlink.RecursiveSelf),
  ('MINUTEMAN_ATTR_BE_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_BE_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_BE_REACH', netlink.U8Type),
  ('MINUTEMAN_ATTR_BE_CONSECUTIVE_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_LAST_FAILURE', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_PENDING', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_SUCCESSES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_NOW', netlink.U64Type),
)

MinutemanAttrList = netlink.create_attr_list_type('MinutemanAttrList',
  ('MINUTEMAN_ATTR_VIP', MinutemanVIPAttrList),
  ('MINUTEMAN_ATTR_VIP_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_VIP_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_VIP_BE', MinutemanVIPBEAttrList),
  ('MINUTEMAN_ATTR_BE', MinutemanBEAttrList),
  ('MINUTEMAN_ATTR_BE_IP', netlink.Net32Type),
  ('MINUTEMAN_ATTR_BE_PORT', netlink.Net16Type),
  ('MINUTEMAN_ATTR_BE_REACH', netlink.U8Type),
  ('MINUTEMAN_ATTR_BE_CONSECUTIVE_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_LAST_FAILURE', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_PENDING', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_FAILURES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_TOTAL_SUCCESSES', netlink.U64Type),
  ('MINUTEMAN_ATTR_BE_NOW', netlink.U64Type),
)


MinutemanMessage = netlink.create_genl_message_type(
  'Minuteman', 'MINUTEMAN',
  ('MINUTEMAN_CMD_NOOP', MinutemanAttrList),
  ('MINUTEMAN_CMD_ADD_VIP', MinutemanAttrList),
  ('MINUTEMAN_CMD_DEL_VIP', MinutemanAttrList),
  ('MINUTEMAN_CMD_ADD_BE', MinutemanAttrList),
  ('MINUTEMAN_CMD_DEL_BE', MinutemanAttrList),
  ('MINUTEMAN_CMD_SET_BE', MinutemanAttrList),
  ('MINUTEMAN_CMD_ATTACH_BE', MinutemanAttrList),
  ('MINUTEMAN_CMD_DETACH_BE', MinutemanAttrList),
)

be1_ip = struct.unpack('!I', socket.inet_aton("33.33.33.1"))[0]
be1_port = 3333
be2_ip = struct.unpack('!I', socket.inet_aton("33.33.33.1"))[0]
be2_port = 3334
be3_ip = struct.unpack('!I', socket.inet_aton("4.2.2.2"))[0]
be3_port = 3333
vip_ip = struct.unpack('!I', socket.inet_aton("1.2.3.4"))[0]
vip_port = 5000
sock = netlink.NetlinkSocket()

msg = MinutemanMessage('MINUTEMAN_CMD_NOOP', flags=netlink.MessageFlags.DUMP | netlink.MessageFlags.ACK_REQUEST)
print msg
print sock._send(msg)
reply = sock._recv()
pprint(reply)

