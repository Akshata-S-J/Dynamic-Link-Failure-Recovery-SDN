import pox.openflow.libopenflow_01 as of
import time
import copy 
from pox.core import core
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str

log = core.getLogger()

mac_map = {
  "00:00:00:00:00:01": (1, 1),
  "00:00:00:00:00:02": (36, 1)
}

switches = {}
myswitches = []
adjacency = defaultdict(lambda: defaultdict(lambda: None))
ori_adjacency = defaultdict(lambda: defaultdict(lambda: None))
current_p = []
link_fail = []

def minimum_distance(distance, Q):
  min_dist = float('Inf')
  node = None
  for v in Q:
    if distance[v] < min_dist:
      min_dist = distance[v]
      node = v
  return node

def _get_raw_path(src, dst, adj):
  distance = {}
  previous = {}      
  sws = myswitches

  for dpid in sws:
    distance[dpid] = float('Inf')
    previous[dpid] = None

  distance[src] = 0
  Q = set(sws)

  while len(Q) > 0:
    u = minimum_distance(distance, Q)
    if u is None:
      break
    Q.remove(u)

    for p in sws:
      if adj[u][p] is not None:
        w = 1
        if distance[u] + w < distance[p]:
          distance[p] = distance[u] + w
          previous[p] = u

  r = []
  p = dst
  r.append(p)
  q = previous[p]

  while q is not None:
    if q == src:
      r.append(q)
      break
    p = q
    r.append(p)
    q = previous[p]

  r.reverse() 
  return r

class Switch (EventMixin):
  def __init__(self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__(self):
    return dpid_to_str(self.dpid)

  def _install2(self, in_port, out_port, match, dpid):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.actions.append(of.ofp_action_output(port=out_port))
    switches[dpid].connection.send(msg)

  def _install(self, in_port, out_port, match, buf=None):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.actions.append(of.ofp_action_output(port=out_port))
    msg.buffer_id = buf
    self.connection.send(msg)

  def _handle_PacketIn(self, event):
    global current_p, link_fail
    packet = event.parsed

    src_str = str(packet.src)
    dst_str = str(packet.dst)

    if src_str not in mac_map or dst_str not in mac_map:
      return

    path = _get_raw_path(mac_map[src_str][0], mac_map[dst_str][0], adjacency)
    current_p = copy.deepcopy(path)

    if len(link_fail) != 0 and self.dpid in link_fail:
      if self.dpid == link_fail[0]:
        p1 = _get_raw_path(link_fail[0], link_fail[1], adjacency)
        p2 = _get_raw_path(mac_map[src_str][0], mac_map[dst_str][0], ori_adjacency)
      else:
        p1 = _get_raw_path(link_fail[1], link_fail[0], adjacency)
        p2 = _get_raw_path(mac_map[src_str][0], mac_map[dst_str][0], ori_adjacency)

      print("p1 =", p1, "p2 =", p2)
      indx = p2.index(p1[0])
      p1 = p1[1:]

      for j, i in enumerate(p1):
        p2.insert(indx + j + 1, i)

      path = p2
      for j, i in enumerate(p1, 1):
        try:
          current_index = path.index(self.dpid)
          next = path[current_index + j + 1]
          output_port = adjacency[i][next]
          input_port = adjacency[path[current_index + j]][path[current_index + j - 1]]
          match = of.ofp_match.from_packet(packet)
          self._install2(input_port, output_port, match, i)
        except:
          continue

    if self.dpid not in path or path.index(self.dpid) + 1 >= len(path):
      return

    next = path[path.index(self.dpid) + 1]
    output_port = adjacency[self.dpid][next]
    match = of.ofp_match.from_packet(packet)
    self._install(event.port, output_port, match)

    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port=output_port))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

  def disconnect(self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect(self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid

    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

  def _handle_ConnectionDown(self, event):
    self.disconnect()

class l2_multi(EventMixin):
  def __init__(self):
    def startup():
      core.openflow.addListeners(self, priority=0)
      core.openflow_discovery.addListeners(self)
    core.call_when_ready(startup, ('openflow', 'openflow_discovery'))

  def _handle_ConnectionUp(self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
      myswitches.append(event.dpid)
    else:
      sw.connect(event.connection)

  def _handle_LinkEvent(self, event):
    global current_p, link_fail
    l = event.link
    sw1 = l.dpid1
    sw2 = l.dpid2
    pt1 = l.port1
    pt2 = l.port2

    no_edges = sum(1 for p in myswitches for q in myswitches if adjacency[p][q] is not None)
    print("number of edges =", no_edges / 2.0)
    print("current_p =", current_p)

    if len(myswitches) == 37 and (no_edges / 2.0) == 56:
      if event.removed:
        print(sw1, "----", sw2, " is removed")
        clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        link_fail = [sw1, sw2]
        for dpid in link_fail:
          if switches[dpid].connection is None:
            continue
          switches[dpid].connection.send(clear)

    if event.added:
      if adjacency[sw1][sw2] is None:
        adjacency[sw1][sw2] = pt1
        adjacency[sw2][sw1] = pt2
      if ori_adjacency[sw1][sw2] is None:
        ori_adjacency[sw1][sw2] = pt1
        ori_adjacency[sw2][sw1] = pt2

    if event.removed:
      try:
        if sw2 in adjacency[sw1]:
          del adjacency[sw1][sw2]
        if sw1 in adjacency[sw2]:
          del adjacency[sw2][sw1]
      except Exception as e:
        print("remove edge error:", e)

def launch():
  core.registerNew(l2_multi)
