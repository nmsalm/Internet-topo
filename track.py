#conding=utf-8
import logging
import struct
import copy
import networkx as nx
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import mpls
from ryu.lib.packet import vlan
from ryu.lib import hub
from ryu.lib import pcaplib
from ryu.ofproto import ether
from ryu.ofproto import inet

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
#import setting


CONF = cfg.CONF

class Track(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Track,self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.name = 'track'
        self.link_to_port = {}   #(src_dpid,dst_dpid)->(src_port,dst_port)
        self.access_table = {}   #{(sw,port),:[host_ip]}
        self.switch_port_table = {}
        self.access_ports = {}
        self.interior_ports = {}
        self.datapaths = {}
        self.switches = []
        self.label_mapping = {}
        self.currentlabel = 100
        self.colortag = {}
        self.pcap_pen = pcaplib.Writer(open('mypcap.pcap','wb'))

        self.graph = nx.DiGraph()
        self.pre_graph = nx.DiGraph()
        self.pre_access_table = {}
        self.pre_link_to_port = {}
        self.shortest_paths = None

        self.discover_thread = hub.spawn(self._discover)
        self.tracing_thread = hub.spawn(self._tracing)

    #forwarding

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
            Initial operation, send miss-table flow entry to datapaths.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #actions.append(parser.OFPActionOutput(ofproto.OFPP_FLOOD,ofproto.OFPCML_NO_BUFFER))
        self.add_flow(datapath,0,  match, actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=15, hard_timeout=60):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)
 
    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=0, hard_timeout=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
            Hanle the packet in packet, and register the access info.
        """
        msg = ev.msg
        datapath = msg.datapath
        #print self.label_mapping
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_type = pkt.get_protocol(ethernet.ethernet).ethertype
        #print eth_type
        #mpls_pkt = pkt.get_protocol(mpls.mpls)
        vlan_pkt = pkt.get_protocol(vlan.vlan)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        #print self.link_to_port.get((2,3)), self.link_to_port
        #self.logger.info("packet in %s %s %s %s", datapath.id, pkt.get_protocols(ethernet.ethernet)[0].src, pkt.get_protocols(ethernet.ethernet)[0].dst, msg.match['in_port'])
        if eth_type == 0x8847:
            pkt_mpls = pkt.get_protocol(mpls.mpls)
            #self.logger.info("current hop is : %s", datapath.id)
            #self.logger.info("Label:{}, TTL: {}".format(pkt_mpls.label, pkt_mpls.ttl))
            self.receiveprobe(msg)
            #self.pcap_pen.write_pkt(msg.data)

        elif arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac    
            # Record the access info
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)
            self.logger.debug("ARP Processing")
            self.arp_forwarding(msg,arp_src_ip,arp_dst_ip)
        if ip_pkt:
            ipv4_src_ip = ip_pkt.src
            ipv4_dst_ip = ip_pkt.dst
            if tcp_pkt:
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
                self.shortest_forwarding(msg,eth_type,ipv4_src_ip,ipv4_dst_ip)
                #self.setup_flow_entry(msg,ipv4_src_ip,ipv4_dst_ip,src_port,dst_port)

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (
                             src_dpid, dst_dpid))
            return None

    def install_flow(self, datapaths, link_to_port, access_table, path,
                     flow_info, buffer_id, data=None):
        ''' 
            Install flow entires for roundtrip: go and back.
            @parameter: path=[dpid1, dpid2...]
                        flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        # inter_link
        if len(path) > 2:
            for i in xrange(1, len(path)-1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i-1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i+1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)
                    self.logger.debug("inter_link flow install")
        if len(path) > 1:
            # the last flow entry: tor -> host
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            src_port = port_pair[1]

            dst_port = self.get_port(flow_info[2], access_table)
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return

            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # the first flow entry
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

        # src and dst on the same datapath
        else:
            out_port = self.get_port(flow_info[2], access_table)
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)
    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            To calculate shortest forwarding path and install them into datapaths.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # Path has already calculated, just get it.
                path = self.get_path(src_sw, dst_sw)
                self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                flow_info = (eth_type, ip_src, ip_dst, in_port)
                # install flow entries to datapath along side the path.
                self.install_flow(self.datapaths,
                                  self.link_to_port,
                                  self.access_table, path,
                                  flow_info, msg.buffer_id, msg.data)
        return
 



    # MPLS based routing
    @classmethod
    def set_label_alloc(self, src_ip, dst_ip, src_port, dst_port):
        if self.mplslabel[(src_ip,dst_ip,src_port,dst_port)]: 
            return self.mplslabel[(src_ip,dst_ip,src_port,dst_port)]
        else:
            self.mplslabel.setdefault((src_ip,dst_ip,src_port,dst_port),None)
            self.mplslabel[(src_ip,dst_ip,src_port,dst_port)] = self.currentlabel
            self.currentlabel = currentlabel + 1
            return self.mplslabel[(src_ip,dst_ip,src_port,dst_port)]


    def setup_flow_entry(self,msg,src_ip,dst_ip,src_port,dst_port):
        src_dpid = self.get_host_location(src_ip)
        dst_dpid = self.get_host_location(dst_ip)
        self.logger.info("setup the path for flow: %s %s %s %s",src_ip,src_port,dst_ip,dst_port)
        path = self.shortest_paths[src_dpid[0]][dst_dpid[0]][0]
        length = len(path)
        datapath = msg.datapath
        ofproto = datapath.ofproto_parser
        in_port = msg.match['in_port']
        label = 0
        #self.currentlabel = self.currentlabel + 1
        if (src_ip,dst_ip,src_port,dst_port) in self.label_mapping:
            label = self.label_mapping[(src_ip,dst_ip,src_port,dst_port)] 
        else:
            self.label_mapping.setdefault((src_ip,dst_ip,src_port,dst_port), None)
            self.label_mapping[(src_ip,dst_ip,src_port,dst_port)] = self.currentlabel
            label = self.currentlabel
            self.currentlabel = self.currentlabel + 1    
        print path,range(length)
        #print path, self.currentlabel, self.label_mapping
        for i in range(length):
            if i == 0:
                #print datapath,self.datapaths[path[i]].id,src_ip,dst_ip,src_port,dst_port,label
                if length == 1:
                    self.logger.info('pushing label at dpid: %016x', self.datapaths[path[i]].id)
                    self.pushlabel(datapath,src_ip,dst_ip,src_port,dst_port,None,in_port)
                else:
                    port_pair = self.get_port_pair_from_link(self.link_to_port,
                                                     path[i], path[i+1])
                    self.logger.info('pushing label at dpid: %016x', self.datapaths[path[i]].id)
                    self.pushlabel(datapath,src_ip,dst_ip,src_port,dst_port,label,port_pair[0])  
                #self.send_packet_out(datapath,msg.buffer_id,in_port,port_pair[0],msg.data)
                #print "send packet out"
            elif i == (length-1):
                outport = self.get_port(dst_ip,self.access_table) 
                self.logger.info('pop label at dpid: %016x', self.datapaths[path[i]].id)
                self.poplabel(self.datapaths[path[i]],label,outport)
            else:
                outport = self.get_port_pair_from_link(self.link_to_port,path[i],path[i+1])
                self.logger.info('forwarding label at dpid: %016x', self.datapaths[path[i]].id)
                self.forwardlabel(self.datapaths[path[i]],label,outport[0])

    def pushlabel(self, datapath,src_ip,dst_ip,src_port,dst_port, label, outPort):
        eth_MPLS = ether.ETH_TYPE_MPLS
        match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,ip_proto=6,
                ipv4_dst=dst_ip, ipv4_src=src_ip, tcp_src=src_port, tcp_dst=dst_port)
        if label:
            actions = [datapath.ofproto_parser.OFPActionPushMpls(0x8847),
                    datapath.ofproto_parser.OFPActionSetField(mpls_label=label),
                    datapath.ofproto_parser.OFPActionSetField(mpls_tc=1),
                    datapath.ofproto_parser.OFPActionOutput(outPort, 0),
                    datapath.ofproto_parser.OFPActionSetMplsTtl(255),
                    datapath.ofproto_parser.OFPActionDecMplsTtl()]
        else:
            actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        self.add_flow(datapath, 15, match, actions)
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=datapath.ofproto.OFPFC_ADD,
                datapath=datapath,
                idle_timeout=0,
                hard_timeout=0,
                priority=0xef,
                #buffer_id=0xffffffff,
                out_port=outPort,
                out_group=datapath.ofproto.OFPG_ANY,
                flags=0,
                match=match,
                instructions=inst)
        print 'in %s switch pushing label' %(datapath.id)
        #datapath.send_msg(mod)
        #print "done pushing mpls label"

    @classmethod
    def poplabel(self, datapath, label, outport):
        match = datapath.ofproto_parser.OFPMatch(
                eth_type=0x8847,
                mpls_label=label)
        actions =[datapath.ofproto_parser.OFPActionPopMpls(ether.ETH_TYPE_IP),
                datapath.ofproto_parser.OFPActionOutput(outport, 0),
                datapath.ofproto_parser.OFPActionDecNwTtl()]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=datapath.ofproto.OFPFC_ADD,
                datapath=datapath,
                idle_timeout=0,
                hard_timeout=0,
                priority=0xe,
                # buffer_id=0xffffffff,
                out_port=outport,
                out_group=datapath.ofproto.OFPG_ANY,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)

    @classmethod
    def forwardlabel(cls, datapath, label, outPort):
        match = datapath.ofproto_parser.OFPMatch(
                eth_type=0x8847,
                mpls_label=label)
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0),
                datapath.ofproto_parser.OFPActionDecMplsTtl()]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=datapath.ofproto.OFPFC_ADD,
                datapath=datapath,
                idle_timeout=0,
                hard_timeout=0,
                priority=0xff,
                # buffer_id=0xffffffff,
                out_port=outPort,
                out_group=datapath.ofproto.OFPG_ANY,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        port = msg.match['in_port']
        result = self.get_host_location(dst_ip)
        #print result
        if result:  # host record in access table.
            pkt = packet.Packet(data=msg.data)
            arp_dstip,arp_mac = self.access_table[result]
            self.logger.info("%s" %pkt)
            pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
            pkt_arp = pkt.get_protocol(arp.arp)
            if pkt_arp.opcode != arp.ARP_REQUEST:
                return
            arp_Reply = packet.Packet()
            arp_Reply.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst= pkt_ethernet.src,src=arp_mac))
            arp_Reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,src_mac=arp_mac,src_ip=arp_dstip,dst_mac=pkt_arp.src_mac,dst_ip=pkt_arp.src_ip))
            self._send_packet(datapath, port, arp_Reply )

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
        datapath.send_msg(out) 

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None 

    #topology discovery

    def register_access_info(self, dpid, in_port, ip, mac):
        """
            Register access host info into access table.
        """
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    # List the event list should be listened.
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    @set_ev_cls(events)
    def get_topology(self,ev):
        """
            get the whole network topology
        """
        switch_list = get_switch(self.topology_api_app,None)  #Ryu api
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self.topology_api_app, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.get_graph(self.link_to_port.keys())
        self.shortest_paths = self.all_k_shortest_paths(
            self.graph, weight='weight')
        #print self.shortest_paths[2][8]
        #print self.switches

    def create_port_map(self, switch_list):
        """
            Create interior_port table and access_port table. 
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def get_path(self, src, dst):
        return self.shortest_paths.get(src).get(dst)[0]

    def get_switches(self):
        return self.switches    

    def get_links(self):
        return self.link_to_port

    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None

        src_location = self.get_host_location(src)
        if in_port in self.access_ports[dpid]:
            if (dpid,  in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None

        dst_location = self.get_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]

        return src_sw, dst_sw

    def create_interior_links(self, link_list):
        """
            Get links`srouce port to dst port  from link_list,
            link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
        """
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # Find the access ports and interiorior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        """
            Get ports without link into access_ports
        """
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    def get_graph(self, link_list):
        """
            Get Adjacency matrix from link_to_port
        """
        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    self.graph.add_edge(src, dst, weight=0)
                elif (src, dst) in link_list:
                    self.graph.add_edge(src, dst, weight=1)
        return self.graph

    def get_host_location(self, host_ip):
        """
            Get host location info:(datapath, port) according to host ip.
        """
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.info("%s location is not found." % host_ip)
        return None

    def k_shortest_paths(self, graph, src, dst, weight='weight', k=1):
        """
            Great K shortest paths of src to dst.
        """
        generator = nx.shortest_simple_paths(graph, source=src,
                                             target=dst, weight=weight)
        shortest_paths = []
        try:
            for path in generator:
                if k <= 0:
                    break
                shortest_paths.append(path)
                k -= 1
            return shortest_paths
        except:
            self.logger.debug("No path between %s and %s" % (src, dst))

    def all_k_shortest_paths(self, graph, weight='weight', k=1):
        """
            Creat all K shortest paths between datapaths.
        """
        _graph = copy.deepcopy(graph)
        paths = {}

        # Find ksp in graph.
        for src in _graph.nodes():
            paths.setdefault(src, {src: [[src] for i in xrange(k)]})
            for dst in _graph.nodes():
                if src == dst:
                    continue
                paths[src].setdefault(dst, [])
                paths[src][dst] = self.k_shortest_paths(_graph, src, dst,
                                                        weight=weight, k=k)
        return paths

    def _discover(self):
        i = 0
        while True:
            #print self.access_table
	    #self.show_topology()
            if i == 5:
                self.get_topology(None)
                i = 0
            hub.sleep(10)
            i = i + 1
            self.decideswcolor()


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Collect datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    #color-tag
    def decideswcolor(self):
        self.colortag.clear()
        #print self.switches,self.colortag
        for sw in self.switches:
            self.colortag[sw] = 0
        links = self.link_to_port.keys()
        #print links
        #creating color tag
        index = 1
        color = 1
        #print self.link_to_port.keys()
        for sw in self.switches:
            #print sw,index,self.link_to_port.has_key((sw,self.switches[0]))
            while index <= len(self.switches):
                if self.link_to_port.has_key((sw,self.switches[index-1])):
                    if color == self.colortag[self.switches[index-1]]:
                        #print "inside"
                        color = color + 1
                        index = 1
                    else:
                        index = index + 1
                index = index + 1
            self.colortag[sw] = color
            color = 1 
            index = 1
            continue
        l = self.colortag.values()
        colorlist = {}.fromkeys(l).keys()
        #print self.colortag
        for dpid in range(len(self.datapaths)):
            for color in colorlist:
                if color == self.colortag[(dpid+1)]:
                    continue
                parser = self.datapaths[(dpid+1)].ofproto_parser
                ofproto = self.datapaths[dpid+1].ofproto
                #print self.colortag[dpid+1]
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
                match = parser.OFPMatch(eth_type=0x8847,mpls_label=color)
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)] 
                mod = parser.OFPFlowMod(command=ofproto.OFPFC_ADD,datapath=self.datapaths[dpid+1],buffer_id=ofproto.OFP_NO_BUFFER,idle_timeout=0,hard_timeout=0,priority=30000,match=match,instructions=inst)
                #print mod
                self.datapaths[dpid+1].send_msg(mod)
                #print "done"
    #correlation


    #tracing
    def _tracing(self):
        hub.sleep(15)
        srcip = '10.0.0.1'
        dstip = '10.0.0.10'
        srcport = 30000
        dstport = 5001
        #data = 'helloworld'
        srcdp = self.get_host_location(srcip)
        dstdp = self.get_host_location(dstip)
        dstmac = self.access_table[dstdp]
        srcmac = self.access_table[srcdp]
        #print dstmac,srcmac
        ofproto = self.datapaths[srcdp[0]].ofproto
        parser = self.datapaths[srcdp[0]].ofproto_parser
        count = 5
        """
        while count:
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_IP,dst=dstmac[1],src=srcmac[1]))
        
            pkt.add_protocol(ipv4.ipv4(dst=dstip,src=srcip,proto=6))
            pkt.add_protocol(tcp.tcp(src_port=srcport,dst_port=dstport))
            pkt.serialize()
            data = pkt.data
            actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
            out = parser.OFPPacketOut(datapath=self.datapaths[srcdp[0]],buffer_id=ofproto.OFP_NO_BUFFER,in_port=srcdp[1],actions=actions,data=data)
            self.datapaths[srcdp[1]].send_msg(out)
            count = count - 1
        """
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dst=dstmac[1],src=srcmac[1],ethertype=0x8847))
        pkt.add_protocol(mpls.mpls(label=self.colortag[self.datapaths[1].id]))
        pkt.add_protocol(ipv4.ipv4(proto=6,src=srcip,dst=dstip))
        pkt.add_protocol(tcp.tcp(src_port=srcport,dst_port=dstport))
        #print srcdp[1]
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
        out = parser.OFPPacketOut(datapath=self.datapaths[srcdp[0]],buffer_id=ofproto.OFP_NO_BUFFER,in_port=srcdp[1],actions=actions,data=data)
        self.datapaths[1].send_msg(out)
        #print "done"
        self.logger.info("current hop is : %s", self.datapaths[1].id)

    def receiveprobe(self,msg):
        dp = msg.datapath
        #print msg.data
        in_port = msg.match['in_port']
        dpid = dp.id
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
       

        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_mpls = pkt.get_protocol(mpls.mpls)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        #print pkt_mpls
        if pkt_mpls.label == self.colortag[dpid]:
            return
        dstip = pkt_ipv4.dst
        #print dstip
        dstdp = self.get_host_location(dstip) 
        if dpid == dstdp[0]:
            self.logger.info("current hop is : %s", dp.id)
            print "tracing is over"
            return
        #print dpid,in_port
        self.logger.info("current hop is : %s", dp.id)
        probe = packet.Packet()
        probe.add_protocol(ethernet.ethernet(dst=pkt_ethernet.dst,src=pkt_ethernet.src,ethertype=0x8847))
        probe.add_protocol(mpls.mpls(label=self.colortag[dpid]))
        probe.add_protocol(ipv4.ipv4(proto=6,src=pkt_ipv4.src,dst=pkt_ipv4.dst))
        probe.add_protocol(tcp.tcp(src_port=pkt_tcp.src_port,dst_port=pkt_tcp.dst_port))
        #print "this dp's color is: ",self.colortag[dpid]
        #print probe
        probe.serialize()
        data = probe.data
        #self.pcap_pen.write_pkt(data)
        #print "re-send"
        #print 'current dpid: ',dp.id
        actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
        out = parser.OFPPacketOut(datapath=dp,buffer_id=ofproto.OFP_NO_BUFFER,in_port=in_port,actions=actions,data=data)
        dp.send_msg(out)
        #print out
        #print 'done'
        #self._send_packet(dp, in_port, probe )
