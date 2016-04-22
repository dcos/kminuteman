import gnlpy.netlink as netlink
import socket, struct
from pprint import pprint
MinutemanAttrList = netlink.create_attr_list_type('MinutemanAttrList',
  ('MINUTEMAN_ATTR_VIP', netlink.RecursiveSelf),
  ('MINUTEMAN_ATTR_VIP_IP', netlink.U32Type),
  ('MINUTEMAN_ATTR_VIP_PORT', netlink.U16Type),
  ('MINUTEMAN_ATTR_VIP_BE', netlink.RecursiveSelf),
  ('MINUTEMAN_ATTR_BE', netlink.RecursiveSelf),
  ('MINUTEMAN_ATTR_BE_IP', netlink.U32Type),
  ('MINUTEMAN_ATTR_BE_PORT', netlink.U16Type),
  ('MINUTEMAN_ATTR_BE_AVAIL', netlink.U8Type),
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

be1_ip = struct.unpack('I', socket.inet_aton("33.33.33.1"))[0]
be1_port = socket.htons(3333)
be2_ip = struct.unpack('I', socket.inet_aton("33.33.33.1"))[0]
be2_port = socket.htons(3334)
be3_ip = struct.unpack('I', socket.inet_aton("4.2.2.2"))[0]
be3_port = socket.htons(3333)
vip_ip = struct.unpack('I', socket.inet_aton("1.2.3.4"))[0]
vip_port = socket.htons(5000)
print vip_ip, vip_port
sock = netlink.NetlinkSocket()

try:
  print sock.execute(MinutemanMessage('MINUTEMAN_CMD_ADD_VIP', attr_list=MinutemanAttrList(minuteman_attr_vip_ip = vip_ip, minuteman_attr_vip_port = vip_port)))
except Exception as e: print e

try:
  print sock.execute(MinutemanMessage('MINUTEMAN_CMD_ADD_BE', attr_list=MinutemanAttrList(minuteman_attr_be_ip = be1_ip, minuteman_attr_be_port = be1_port)))
except Exception as e: print e

try:
  print sock.execute(MinutemanMessage('MINUTEMAN_CMD_ADD_BE', attr_list=MinutemanAttrList(minuteman_attr_be_ip = be2_ip, minuteman_attr_be_port = be2_port)))
except Exception as e: print e

try:
  print sock.execute(MinutemanMessage('MINUTEMAN_CMD_ADD_BE', attr_list=MinutemanAttrList(minuteman_attr_be_ip = be3_ip, minuteman_attr_be_port = be3_port)))
except Exception as e: print e

try:
  print sock.execute(MinutemanMessage('MINUTEMAN_CMD_ATTACH_BE', attr_list=MinutemanAttrList(minuteman_attr_vip_ip = vip_ip, minuteman_attr_vip_port = vip_port, minuteman_attr_be_ip = be1_ip, minuteman_attr_be_port = be1_port)))
except Exception as e: print e

try:
  print sock.execute(MinutemanMessage('MINUTEMAN_CMD_ATTACH_BE', attr_list=MinutemanAttrList(minuteman_attr_vip_ip = vip_ip, minuteman_attr_vip_port = vip_port, minuteman_attr_be_ip = be2_ip, minuteman_attr_be_port = be2_port)))
except Exception as e: print e

try:
  print sock.execute(MinutemanMessage('MINUTEMAN_CMD_ATTACH_BE', attr_list=MinutemanAttrList(minuteman_attr_vip_ip = vip_ip, minuteman_attr_vip_port = vip_port, minuteman_attr_be_ip = be3_ip, minuteman_attr_be_port = be3_port)))
except Exception as e: print e

msg = MinutemanMessage('MINUTEMAN_CMD_NOOP', flags=netlink.MessageFlags.DUMP | netlink.MessageFlags.ACK_REQUEST)
print msg
print sock._send(msg)
pprint(sock._recv())
