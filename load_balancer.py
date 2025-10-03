"""
POX SDN Load Balancer
Supports: Random Selection or Round Robin
Usage:
  ./pox.py log.level --DEBUG misc.load_balancer --ip=<service_ip> --servers=<server1,server2,...> --algorithm=random|roundrobin
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import time
import random

log = core.getLogger("LoadBalancer")

FLOW_IDLE_TIMEOUT = 10
FLOW_MEMORY_TIMEOUT = 60 * 5

class MemoryEntry:
    def __init__(self, server, first_packet, client_port):
        self.server = server
        self.first_packet = first_packet
        self.client_port = client_port
        self.refresh()
    
    def refresh(self):
        self.timeout = time.time() + FLOW_MEMORY_TIMEOUT
    
    @property
    def is_expired(self):
        return time.time() > self.timeout
    
    @property
    def key1(self):
        ipp = self.first_packet.find('ipv4')
        tcpp = self.first_packet.find('tcp')
        return ipp.srcip, ipp.dstip, tcpp.srcport, tcpp.dstport
    
    @property
    def key2(self):
        ipp = self.first_packet.find('ipv4')
        tcpp = self.first_packet.find('tcp')
        return self.server, ipp.srcip, tcpp.dstport, ipp.srcport

class LoadBalancer:
    def __init__(self, connection, service_ip, servers, algorithm='random'):
        self.con = connection
        self.service_ip = service_ip
        self.servers = servers
        self.algorithm = algorithm
        self.mac = EthAddr("00:00:00:11:22:33")
        self.live_servers = {}       # IP -> (MAC, port)
        self.memory = {}             # (srcip,dstip,srcport,dstport) -> MemoryEntry
        self.outstanding_probes = {} # IP -> expiry
        self.probe_cycle_time = 5
        self.arp_timeout = 3
        self.selected_index = 0

        self._do_probe()
        connection.addListeners(self)

    def _do_expire(self):
        t = time.time()
        # Expire probes
        for ip, expire_at in list(self.outstanding_probes.items()):
            if t > expire_at:
                self.outstanding_probes.pop(ip, None)
                if ip in self.live_servers:
                    log.warn("Server %s down", ip)
                    del self.live_servers[ip]
        # Expire old flows
        self.memory = {k: v for k, v in self.memory.items() if not v.is_expired}

    def _do_probe(self):
        self._do_expire()
        for server in self.servers:
            r = arp()
            r.hwtype = r.HW_TYPE_ETHERNET
            r.prototype = r.PROTO_TYPE_IP
            r.opcode = r.REQUEST
            r.hwdst = ETHER_BROADCAST
            r.protodst = server
            r.hwsrc = self.mac
            r.protosrc = self.service_ip
            e = ethernet(type=ethernet.ARP_TYPE, src=self.mac, dst=ETHER_BROADCAST)
            e.set_payload(r)
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = of.OFPP_NONE
            self.con.send(msg)
            self.outstanding_probes[server] = time.time() + self.arp_timeout
        core.callDelayed(self.probe_cycle_time, self._do_probe)

    def _pick_server(self, key):
        if self.algorithm == 'random':
            return random.choice(list(self.live_servers.keys()))
        elif self.algorithm == 'roundrobin':
            if not self.live_servers:
                return None
            servers = list(self.live_servers.keys())
            server = servers[self.selected_index % len(servers)]
            self.selected_index += 1
            return server

    def _handle_PacketIn(self, event):
        packet = event.parsed
        inport = event.port

        tcpp = packet.find('tcp')
        arpp = packet.find('arp')

        # Handle ARP replies
        if arpp:
            if arpp.opcode == arp.REPLY:
                self.live_servers[arpp.protosrc] = (arpp.hwsrc, inport)
                if arpp.protosrc in self.outstanding_probes:
                    del self.outstanding_probes[arpp.protosrc]
            return

        if not tcpp:
            return

        ipp = packet.find('ipv4')

        # Reverse flows from servers to clients
        if ipp.srcip in self.servers:
            key = (ipp.srcip, ipp.dstip, tcpp.srcport, tcpp.dstport)
            entry = self.memory.get(key)
            if entry:
                entry.refresh()
                mac, port = self.live_servers[entry.server]
                actions = [
                    of.ofp_action_dl_addr.set_src(self.mac),
                    of.ofp_action_nw_addr.set_src(self.service_ip),
                    of.ofp_action_output(port=entry.client_port)
                ]
                match = of.ofp_match.from_packet(packet, inport)
                msg = of.ofp_flow_mod(command=of.OFPFC_ADD, idle_timeout=FLOW_IDLE_TIMEOUT,
                                      hard_timeout=of.OFP_FLOW_PERMANENT, data=event.ofp,
                                      actions=actions, match=match)
                self.con.send(msg)
            return

        # Traffic to service IP
        if ipp.dstip == self.service_ip:
            key = (ipp.srcip, ipp.dstip, tcpp.srcport, tcpp.dstport)
            entry = self.memory.get(key)
            if entry is None or entry.server not in self.live_servers:
                server = self._pick_server(key)
                if server is None:
                    log.warn("No live servers!")
                    return
                entry = MemoryEntry(server, packet, inport)
                self.memory[entry.key1] = entry
                self.memory[entry.key2] = entry
            entry.refresh()
            mac, port = self.live_servers[entry.server]
            actions = [
                of.ofp_action_dl_addr.set_dst(mac),
                of.ofp_action_nw_addr.set_dst(entry.server),
                of.ofp_action_output(port=port)
            ]
            match = of.ofp_match.from_packet(packet, inport)
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD, idle_timeout=FLOW_IDLE_TIMEOUT,
                                  hard_timeout=of.OFP_FLOW_PERMANENT, data=event.ofp,
                                  actions=actions, match=match)
            self.con.send(msg)

# POX launch function
def launch(ip=None, servers=None, algorithm='random'):
    if ip is None or servers is None:
        log.error("Usage: --ip=<service_ip> --servers=<server1,server2,...> [--algorithm=random|roundrobin]")
        return

    service_ip = IPAddr(ip)
    servers = [IPAddr(x) for x in servers.replace(",", " ").split()]

    def _handle_ConnectionUp(event):
        log.info("Load Balancer connected to switch %s", event.dpid)
        if not core.hasComponent('load_balancer'):
            core.registerNew(LoadBalancer, event.connection, service_ip, servers, algorithm)

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
