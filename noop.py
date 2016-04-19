import gnlpy.netlink as netlink
import socket, struct

AttrList = netlink.create_attr_list_type('Minuteman',
  ('MINUTEMAN_ATTR_VIP_IP', netlink.U32Type),
  ('MINUTEMAN_ATTR_VIP_PORT', netlink.U16Type),
  ('MINUTEMAN_ATTR_BE_IP', netlink.U32Type),
  ('MINUTEMAN_ATTR_BE_PORT', netlink.U16Type),
  ('MINUTEMAN_ATTR_BE_AVAIL', netlink.U8Type),
)

MinutemanMessage = netlink.create_genl_message_type(
  'Minuteman', 'MINUTEMAN',
  ('MINUTEMAN_CMD_NOOP', AttrList),
  ('MINUTEMAN_CMD_ADD_VIP', AttrList),
  ('MINUTEMAN_CMD_DEL_VIP', AttrList),
  ('MINUTEMAN_CMD_ADD_BE', AttrList),
  ('MINUTEMAN_CMD_DEL_BE', AttrList),
  ('MINUTEMAN_CMD_SET_BE', AttrList),
  ('MINUTEMAN_CMD_ATTACH_BE', AttrList),
  ('MINUTEMAN_CMD_DETACH_BE', AttrList),
)

be1_ip = struct.unpack('I', socket.inet_aton("33.33.33.1"))[0]
be1_port = socket.htons(3333)
be2_ip = struct.unpack('I', socket.inet_aton("33.33.33.1"))[0]
be2_port = socket.htons(3334)
vip_ip = struct.unpack('I', socket.inet_aton("1.2.3.4"))[0]
vip_port = socket.htons(5000)
print vip_ip, vip_port
sock = netlink.NetlinkSocket()

try:
  print sock.query(MinutemanMessage('MINUTEMAN_CMD_ADD_VIP', attr_list=AttrList(minuteman_attr_vip_ip = vip_ip, minuteman_attr_vip_port = vip_port)))
except Exception as e: print e

try:
  print sock.query(MinutemanMessage('MINUTEMAN_CMD_ADD_BE', attr_list=AttrList(minuteman_attr_be_ip = be1_ip, minuteman_attr_be_port = be1_port)))
except Exception as e: print e

try:
  print sock.query(MinutemanMessage('MINUTEMAN_CMD_ADD_BE', attr_list=AttrList(minuteman_attr_be_ip = be2_ip, minuteman_attr_be_port = be2_port)))
except Exception as e: print e

try:
  print sock.query(MinutemanMessage('MINUTEMAN_CMD_ATTACH_BE', attr_list=AttrList(minuteman_attr_vip_ip = vip_ip, minuteman_attr_vip_port = vip_port, minuteman_attr_be_ip = be1_ip, minuteman_attr_be_port = be1_port)))
except Exception as e: print e

try:
  print sock.query(MinutemanMessage('MINUTEMAN_CMD_ATTACH_BE', attr_list=AttrList(minuteman_attr_vip_ip = vip_ip, minuteman_attr_vip_port = vip_port, minuteman_attr_be_ip = be2_ip, minuteman_attr_be_port = be2_port)))
except Exception as e: print e

print sock.query(MinutemanMessage('MINUTEMAN_CMD_NOOP'))
