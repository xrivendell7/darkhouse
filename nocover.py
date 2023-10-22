import idaapi

def _ida_refresh_nodes(address):
  """
  Refresh function node metadata against an open IDA database.
  """
  nodes = {}

  # getfunction & flowchart object from IDA database
  function  = idaapi.get_func(address)
  flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)
  for node_id in range(flowchart.size()):
    print(str(node_id)+" ", end="")
    node = flowchart[node_id]
    node_info = idaapi.node_info_t()
    # seems no reason to believe the return value of get_node_info
    if node.start_ea == node.end_ea:
      print("empty_node failed at", hex(node.start_ea))
      continue

    idaapi.get_node_info(node_info, function.start_ea, node_id)

    # if not node_info.valid_bg_color():
    #   return None


    # Green
    if node_info.bg_color == 0x96f096:
      print("alreadly done at", hex(node.start_ea))
      continue

    # print(node_id, hex(node.start_ea), hex(node_info.bg_color))

    #
    # the node current node appears to have a size of zero. This means
    # that another flowchart / function owns this node so we can just
    # ignore it...
    #

    if _ida_refresh_node(node.start_ea, node.end_ea):
      # create a node info object as our vehicle for setting the node color
      new_node_info = idaapi.node_info_t()
      new_node_info.bg_color = 0x96f096
      new_node_flags = idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
      idaapi.set_node_info(
        function.start_ea,
        node_id,
        new_node_info,
        new_node_flags)
      print("refersh succed at", hex(node.start_ea))
    else:
      print("#################")
      print("refersh failed at", hex(node.start_ea))

  return nodes

def _ida_refresh_node(start_ea, end_ea):
  """
  Collect node metadata from the underlying database.
  """
  def fuck_judge(addr):
    if "sanitizer_cov_trace_pc" in idaapi.tag_remove(idaapi.generate_disasm_line(addr)):
      print(hex(addr),"sanitizer_cov_trace_pc")
      return True
    return False

  def netnode_judge(addr):
    pass

  address = start_ea
  curr = address
  while curr <= end_ea:
    # print(hex(curr),idaapi.tag_remove(idaapi.generate_disasm_line(curr)))
    disasm = idaapi.tag_remove(idaapi.generate_disasm_line(curr))
    if "sanitizer_cov_trace_pc" in disasm:
      return True
    instruction_size = idaapi.get_item_end(curr) - curr
    # instructions[curr] = instruction_size
    curr += instruction_size
    # if fuck_judge(curr):
    #  return True
  return False

def _ida_refresh_func(addr):
  nodes = _ida_refresh_nodes(addr)
  idaapi.refresh_idaview_anyway()
  # print(nodes)

if __name__ == '__main__':

  ea = here()
  _ida_refresh_func(ea)
