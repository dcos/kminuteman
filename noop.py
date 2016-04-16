import gnlpy.netlink as netlink

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
  ('MINUTEMAN_CMD_SET_BE', AttrList),
  ('MINUTEMAN_CMD_ADD_BE', AttrList),
  ('MINUTEMAN_CMD_DEL_BE', AttrList),
)

sock = netlink.NetlinkSocket()
print sock.query(MinutemanMessage('MINUTEMAN_CMD_NOOP'))
