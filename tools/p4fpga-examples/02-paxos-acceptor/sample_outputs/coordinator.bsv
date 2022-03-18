
import BUtils::*;
import BuildVector::*;
import CBus::*;
import ClientServer::*;
import Connectable::*;
import DbgDefs::*;
import DefaultValue::*;
import Ethernet::*;
import FIFO::*;
import FIFOF::*;
import FShow::*;
import GetPut::*;
import List::*;
import MIMO::*;
import MatchTable::*;
import PacketBuffer::*;
import Pipe::*;
import Register::*;
import SpecialFIFOs::*;
import StmtFSM::*;
import TxRx::*;
import Utils::*;
import Vector::*;
typedef struct {
  Bit#(9) ingress_port;
  Bit#(32) packet_length;
  Bit#(9) egress_spec;
  Bit#(9) egress_port;
  Bit#(32) egress_instance;
  Bit#(32) instance_type;
  Bit#(32) clone_spec;
  Bit#(5) _padding;
} StandardMetadataT deriving (Bits, Eq);
instance DefaultValue#(StandardMetadataT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(StandardMetadataT);
  defaultMask = unpack(maxBound);
endinstance
function StandardMetadataT extract_standard_metadata_t(Bit#(160) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(48) dstAddr;
  Bit#(48) srcAddr;
  Bit#(16) etherType;
} EthernetT deriving (Bits, Eq);
instance DefaultValue#(EthernetT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(EthernetT);
  defaultMask = unpack(maxBound);
endinstance
function EthernetT extract_ethernet_t(Bit#(112) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(16) hrd;
  Bit#(16) pro;
  Bit#(8) hln;
  Bit#(8) pln;
  Bit#(16) op;
  Bit#(48) sha;
  Bit#(32) spa;
  Bit#(48) tha;
  Bit#(32) tpa;
} ArpT deriving (Bits, Eq);
instance DefaultValue#(ArpT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(ArpT);
  defaultMask = unpack(maxBound);
endinstance
function ArpT extract_arp_t(Bit#(224) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(4) version;
  Bit#(4) ihl;
  Bit#(8) diffserv;
  Bit#(16) totalLen;
  Bit#(16) identification;
  Bit#(3) flags;
  Bit#(13) fragOffset;
  Bit#(8) ttl;
  Bit#(8) protocol;
  Bit#(16) hdrChecksum;
  Bit#(32) srcAddr;
  Bit#(32) dstAddr;
} Ipv4T deriving (Bits, Eq);
instance DefaultValue#(Ipv4T);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(Ipv4T);
  defaultMask = unpack(maxBound);
endinstance
function Ipv4T extract_ipv4_t(Bit#(160) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(4) version;
  Bit#(8) trafficClass;
  Bit#(20) flowLabel;
  Bit#(16) payloadLen;
  Bit#(8) nextHdr;
  Bit#(8) hopLimit;
  Bit#(128) srcAddr;
  Bit#(128) dstAddr;
} Ipv6T deriving (Bits, Eq);
instance DefaultValue#(Ipv6T);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(Ipv6T);
  defaultMask = unpack(maxBound);
endinstance
function Ipv6T extract_ipv6_t(Bit#(320) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(16) srcPort;
  Bit#(16) dstPort;
  Bit#(16) length_;
  Bit#(16) checksum;
} UdpT deriving (Bits, Eq);
instance DefaultValue#(UdpT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(UdpT);
  defaultMask = unpack(maxBound);
endinstance
function UdpT extract_udp_t(Bit#(64) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(16) msgtype;
  Bit#(32) inst;
  Bit#(16) rnd;
  Bit#(16) vrnd;
  Bit#(16) acptid;
  Bit#(256) paxosval;
} PaxosT deriving (Bits, Eq, FShow);
instance DefaultValue#(PaxosT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(PaxosT);
  defaultMask = unpack(maxBound);
endinstance
function PaxosT extract_paxos_t(Bit#(352) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  PacketInstance pkt;
  MetadataT meta;
} MetadataRequest deriving (Bits, Eq, FShow);
typedef union tagged {
  struct {
    PacketInstance pkt;
    MetadataT meta;
  } ForwardTblForwardRspT;
  struct {
    PacketInstance pkt;
    MetadataT meta;
  } ForwardTblDropRspT;
  struct {
    PacketInstance pkt;
    MetadataT meta;
  } SequenceTblIncreaseInstanceRspT;
  struct {
    PacketInstance pkt;
    MetadataT meta;
  } SequenceTblNopRspT;
} MetadataResponse deriving (Bits, Eq, FShow);
typedef struct {
  Maybe#(Bit#(9)) standard_metadata$egress_spec;
  Maybe#(Bit#(9)) runtime_port;
  Maybe#(Bit#(32)) paxos$inst;
  Maybe#(Bit#(16)) udp$dstPort;
  Maybe#(Bit#(16)) udp$checksum;
  Maybe#(Bit#(9)) standard_metadata$ingress_port;
  Maybe#(Bit#(16)) paxos$msgtype;
  Maybe#(Bit#(0)) valid_ipv4;
  Maybe#(Bit#(0)) valid_paxos;
} MetadataT deriving (Bits, Eq, FShow);
instance DefaultValue#(MetadataT);
  defaultValue = unpack(0);
endinstance
// ====== PARSER ======

typedef enum {
  StateStart,
  StateParseEthernet,
  StateParseArp,
  StateParseIpv4,
  StateParseIpv6,
  StateParseUdp,
  StateParsePaxos
} ParserState deriving (Bits, Eq, FShow);
interface Parser;
  interface Put#(EtherData) frameIn;
  interface Get#(MetadataT) meta;
  interface Put#(int) verbosity;
  method ParserPerfRec read_perf_info ();
endinterface
module mkParser  (Parser);
  PulseWire w_parse_ipv6_start <- mkPulseWireOR();
  PulseWire w_parse_ipv4_start <- mkPulseWireOR();
  PulseWire w_parse_ethernet_parse_ipv6 <- mkPulseWireOR();
  PulseWire w_parse_ipv4_parse_udp <- mkPulseWireOR();
  PulseWire w_parse_ethernet_parse_ipv4 <- mkPulseWireOR();
  PulseWire w_parse_ethernet_parse_arp <- mkPulseWireOR();
  PulseWire w_parse_udp_parse_paxos <- mkPulseWireOR();
  PulseWire w_parse_paxos_start <- mkPulseWireOR();
  PulseWire w_parse_ethernet_start <- mkPulseWireOR();
  PulseWire w_start_parse_ethernet <- mkPulseWireOR();
  PulseWire w_parse_udp_start <- mkPulseWireOR();
  PulseWire w_parse_arp_start <- mkPulseWireOR();
  Reg#(Bool) parse_done[2] <- mkCReg(2, True);
  Reg#(int) cr_verbosity[2] <- mkCRegU(2);
  FIFOF#(int) cr_verbosity_ff <- mkFIFOF;
  rule set_verbosity;
    let x = cr_verbosity_ff.first;
    cr_verbosity_ff.deq;
    cr_verbosity[1] <= x;
  endrule

  FIFO#(ParserState) parse_state_ff <- mkPipelineFIFO();
  FIFOF#(Maybe#(Bit#(128))) data_ff <- mkDFIFOF(tagged Invalid);
  FIFOF#(EtherData) data_in_ff <- mkFIFOF;
  FIFOF#(MetadataT) meta_in_ff <- mkFIFOF;
  PulseWire w_parse_header_done <- mkPulseWireOR();
  PulseWire w_load_header <- mkPulseWireOR();
  Reg#(Bit#(32)) rg_next_header_len[3] <- mkCReg(3, 0);
  Reg#(Bit#(32)) rg_buffered[3] <- mkCReg(3, 0);
  Reg#(Bit#(32)) rg_shift_amt[3] <- mkCReg(3, 0);
  Reg#(Bit#(512)) rg_tmp[2] <- mkCReg(2, 0);
  function Action dbg3(Fmt msg);
    action
      if (cr_verbosity[0] > 3) begin
        $display("(%0d) ", $time, msg);
      end
    endaction
  endfunction
  function Action succeed_and_next(Bit#(32) offset);
    action
      rg_buffered[0] <= rg_buffered[0] - offset;
      rg_shift_amt[0] <= rg_buffered[0] - offset;
      dbg3($format("succeed_and_next subtract offset = %d shift_amt/buffered = %d", offset, rg_buffered[0] - offset));
    endaction
  endfunction
  function Action fetch_next_header0(Bit#(32) len);
    action
      rg_next_header_len[0] <= len;
      w_parse_header_done.send();
    endaction
  endfunction
  function Action fetch_next_header1(Bit#(32) len);
    action
      rg_next_header_len[1] <= len;
      w_parse_header_done.send();
    endaction
  endfunction
  function Action move_shift_amt(Bit#(32) len);
    action
      rg_shift_amt[0] <= rg_shift_amt[0] + len;
      w_load_header.send();
    endaction
  endfunction
  function Action failed_and_trap(Bit#(32) offset);
    action
      rg_buffered[0] <= 0;
    endaction
  endfunction
  function Action report_parse_action(ParserState state, Bit#(32) offset, Bit#(128) data, Bit#(512) buff);
    action
      if (cr_verbosity[0] > 3) begin
        $display("(%0d) Parser State %h buffered %d, %h, %h", $time, state, offset, data, buff);
      end
    endaction
  endfunction
  let sop_this_cycle = data_in_ff.first.sop;
  let eop_this_cycle = data_in_ff.first.eop;
  let data_this_cycle = data_in_ff.first.data;
  function Action compute_next_state_parse_ethernet(Bit#(16) etherType);
    action
      let v = {etherType};
      if (v == 'h0806) begin
        dbg3($format("transit to parse_arp"));
        w_parse_ethernet_parse_arp.send();
      end
      else if (v == 'h0800) begin
        dbg3($format("transit to parse_ipv4"));
        w_parse_ethernet_parse_ipv4.send();
      end
      else if (v == 'h86dd) begin
        dbg3($format("transit to parse_ipv6"));
        w_parse_ethernet_parse_ipv6.send();
      end
      else begin
        dbg3($format("transit to start"));
        w_parse_ethernet_start.send();
      end
    endaction
  endfunction
  function Action compute_next_state_parse_arp();
    action
      dbg3($format("transit to start"));
      w_parse_arp_start.send();
    endaction
  endfunction
  function Action compute_next_state_parse_ipv4(Bit#(8) protocol);
    action
      let v = {protocol};
      if (v == 'h11) begin
        dbg3($format("transit to parse_udp"));
        w_parse_ipv4_parse_udp.send();
      end
      else begin
        dbg3($format("transit to start"));
        w_parse_ipv4_start.send();
      end
    endaction
  endfunction
  function Action compute_next_state_parse_ipv6();
    action
      dbg3($format("transit to start"));
      w_parse_ipv6_start.send();
    endaction
  endfunction
  function Action compute_next_state_parse_udp(Bit#(16) dstPort);
    action
      let v = {dstPort};
      if (v == 'h8888) begin
        dbg3($format("transit to parse_paxos"));
        w_parse_udp_parse_paxos.send();
      end
      else if (v == 'h8889) begin
        dbg3($format("transit to parse_paxos"));
        w_parse_udp_parse_paxos.send();
      end
      else begin
        dbg3($format("transit to start"));
        w_parse_udp_start.send();
      end
    endaction
  endfunction
  function Action compute_next_state_parse_paxos();
    action
      dbg3($format("transit to start"));
      w_parse_paxos_start.send();
    endaction
  endfunction
  rule rl_data_ff_load if ((!parse_done[1] && rg_buffered[2] < rg_next_header_len[2]) && (w_parse_header_done || w_load_header));
    let v = data_in_ff.first.data;
    data_in_ff.deq;
    rg_buffered[2] <= rg_buffered[2] + 128;
    data_ff.enq(tagged Valid v);
    dbg3($format("dequeue data %d %d", rg_buffered[2], rg_next_header_len[2]));
  endrule

  rule rl_start_state_deq if (parse_done[1] && sop_this_cycle && !w_parse_header_done);
    let v = data_in_ff.first.data;
    data_ff.enq(tagged Valid v);
    rg_buffered[2] <= 128;
    rg_shift_amt[2] <= 0;
    parse_done[1] <= False;
    parse_state_ff.enq(StateStart);
  endrule

  rule rl_start_state_idle if (parse_done[1] && (!sop_this_cycle || w_parse_header_done));
    data_in_ff.deq;
  endrule

  rule rl_start_parse_ethernet if ((w_start_parse_ethernet));
    parse_state_ff.enq(StateParseEthernet);
    dbg3($format("%s -> %s", "start", "parse_ethernet"));
    fetch_next_header1(112);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ethernet_load if ((parse_state_ff.first == StateParseEthernet) && (rg_buffered[0] < 112));
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, rg_tmp[0]);
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      let data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
      rg_tmp[0] <= zeroExtend(data);
      move_shift_amt(128);
    end
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ethernet_extract if ((parse_state_ff.first == StateParseEthernet) && (rg_buffered[0] >= 112));
    let data = rg_tmp[0];
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
    end
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, data);
    let ethernet_t = extract_ethernet_t(truncate(data));
    compute_next_state_parse_ethernet(ethernet_t.etherType);
    rg_tmp[0] <= zeroExtend(data >> 112);
    succeed_and_next(112);
    dbg3($format("extract %s", "parse_ethernet"));
    parse_state_ff.deq;
  endrule

  (* mutually_exclusive="rl_parse_ethernet_parse_arp, rl_parse_ethernet_parse_ipv4, rl_parse_ethernet_parse_ipv6, rl_parse_ethernet_start" *)
  rule rl_parse_ethernet_parse_arp if ((w_parse_ethernet_parse_arp));
    parse_state_ff.enq(StateParseArp);
    dbg3($format("%s -> %s", "parse_ethernet", "parse_arp"));
    fetch_next_header0(224);
  endrule

  rule rl_parse_ethernet_parse_ipv4 if ((w_parse_ethernet_parse_ipv4));
    parse_state_ff.enq(StateParseIpv4);
    dbg3($format("%s -> %s", "parse_ethernet", "parse_ipv4"));
    fetch_next_header0(160);
  endrule

  rule rl_parse_ethernet_parse_ipv6 if ((w_parse_ethernet_parse_ipv6));
    parse_state_ff.enq(StateParseIpv6);
    dbg3($format("%s -> %s", "parse_ethernet", "parse_ipv6"));
    fetch_next_header0(320);
  endrule

  rule rl_parse_ethernet_start if ((w_parse_ethernet_start));
    parse_done[0] <= True;
    dbg3($format("%s -> %s", "parse_ethernet", "start"));
    fetch_next_header0(0);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_arp_load if ((parse_state_ff.first == StateParseArp) && (rg_buffered[0] < 224));
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, rg_tmp[0]);
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      let data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
      rg_tmp[0] <= zeroExtend(data);
      move_shift_amt(128);
    end
  endrule

  (* fire_when_enabled *)
  rule rl_parse_arp_extract if ((parse_state_ff.first == StateParseArp) && (rg_buffered[0] >= 224));
    let data = rg_tmp[0];
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
    end
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, data);
    compute_next_state_parse_arp();
    rg_tmp[0] <= zeroExtend(data >> 224);
    succeed_and_next(224);
    dbg3($format("extract %s", "parse_arp"));
    parse_state_ff.deq;
  endrule

  (* mutually_exclusive="rl_parse_arp_start" *)
  rule rl_parse_arp_start if ((w_parse_arp_start));
    parse_done[0] <= True;
    dbg3($format("%s -> %s", "parse_arp", "start"));
    fetch_next_header0(0);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ipv4_load if ((parse_state_ff.first == StateParseIpv4) && (rg_buffered[0] < 160));
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, rg_tmp[0]);
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      let data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
      rg_tmp[0] <= zeroExtend(data);
      move_shift_amt(128);
    end
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ipv4_extract if ((parse_state_ff.first == StateParseIpv4) && (rg_buffered[0] >= 160));
    let data = rg_tmp[0];
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
    end
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, data);
    let ipv4_t = extract_ipv4_t(truncate(data));
    compute_next_state_parse_ipv4(ipv4_t.protocol);
    rg_tmp[0] <= zeroExtend(data >> 160);
    succeed_and_next(160);
    dbg3($format("extract %s", "parse_ipv4"));
    parse_state_ff.deq;
  endrule

  (* mutually_exclusive="rl_parse_ipv4_parse_udp, rl_parse_ipv4_start" *)
  rule rl_parse_ipv4_parse_udp if ((w_parse_ipv4_parse_udp));
    parse_state_ff.enq(StateParseUdp);
    dbg3($format("%s -> %s", "parse_ipv4", "parse_udp"));
    fetch_next_header0(64);
  endrule

  rule rl_parse_ipv4_start if ((w_parse_ipv4_start));
    parse_done[0] <= True;
    dbg3($format("%s -> %s", "parse_ipv4", "start"));
    fetch_next_header0(0);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ipv6_load if ((parse_state_ff.first == StateParseIpv6) && (rg_buffered[0] < 320));
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, rg_tmp[0]);
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      let data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
      rg_tmp[0] <= zeroExtend(data);
      move_shift_amt(128);
    end
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ipv6_extract if ((parse_state_ff.first == StateParseIpv6) && (rg_buffered[0] >= 320));
    let data = rg_tmp[0];
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
    end
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, data);
    compute_next_state_parse_ipv6();
    rg_tmp[0] <= zeroExtend(data >> 320);
    succeed_and_next(320);
    dbg3($format("extract %s", "parse_ipv6"));
    parse_state_ff.deq;
  endrule

  (* mutually_exclusive="rl_parse_ipv6_start" *)
  rule rl_parse_ipv6_start if ((w_parse_ipv6_start));
    parse_done[0] <= True;
    dbg3($format("%s -> %s", "parse_ipv6", "start"));
    fetch_next_header0(0);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_udp_load if ((parse_state_ff.first == StateParseUdp) && (rg_buffered[0] < 64));
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, rg_tmp[0]);
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      let data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
      rg_tmp[0] <= zeroExtend(data);
      move_shift_amt(128);
    end
  endrule

  (* fire_when_enabled *)
  rule rl_parse_udp_extract if ((parse_state_ff.first == StateParseUdp) && (rg_buffered[0] >= 64));
    let data = rg_tmp[0];
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
    end
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, data);
    let udp_t = extract_udp_t(truncate(data));
    compute_next_state_parse_udp(udp_t.dstPort);
    rg_tmp[0] <= zeroExtend(data >> 64);
    succeed_and_next(64);
    dbg3($format("extract %s", "parse_udp"));
    parse_state_ff.deq;
  endrule

  (* mutually_exclusive="rl_parse_udp_parse_paxos, rl_parse_udp_parse_paxos, rl_parse_udp_start" *)
  rule rl_parse_udp_parse_paxos if ((w_parse_udp_parse_paxos));
    parse_state_ff.enq(StateParsePaxos);
    dbg3($format("%s -> %s", "parse_udp", "parse_paxos"));
    fetch_next_header0(352);
  endrule

  rule rl_parse_udp_start if ((w_parse_udp_start));
    parse_done[0] <= True;
    dbg3($format("%s -> %s", "parse_udp", "start"));
    fetch_next_header0(0);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_paxos_load if ((parse_state_ff.first == StateParsePaxos) && (rg_buffered[0] < 352));
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, rg_tmp[0]);
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      let data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
      rg_tmp[0] <= zeroExtend(data);
      move_shift_amt(128);
    end
  endrule

  (* fire_when_enabled *)
  rule rl_parse_paxos_extract if ((parse_state_ff.first == StateParsePaxos) && (rg_buffered[0] >= 352));
    let data = rg_tmp[0];
    if (isValid(data_ff.first)) begin
      data_ff.deq;
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp[0];
    end
    report_parse_action(parse_state_ff.first, rg_buffered[0], data_this_cycle, data);
    compute_next_state_parse_paxos();
    rg_tmp[0] <= zeroExtend(data >> 352);
    succeed_and_next(352);
    dbg3($format("extract %s", "parse_paxos"));
    parse_state_ff.deq;
  endrule

  (* mutually_exclusive="rl_parse_paxos_start" *)
  rule rl_parse_paxos_start if ((w_parse_paxos_start));
    parse_done[0] <= True;
    dbg3($format("%s -> %s", "parse_paxos", "start"));
    fetch_next_header0(0);
  endrule

  interface frameIn = toPut(data_in_ff);
  interface meta = toGet(meta_in_ff);
  interface verbosity = toPut(cr_verbosity_ff);
endmodule

// ====== DEPARSER ======

typedef enum {
  StateDeparseStart,
  StateEthernet,
  StateIpv6,
  StateIpv4,
  StateArp,
  StateUdp,
  StatePaxos
} DeparserState deriving (Bits, Eq);
interface Deparser;
  interface PipeIn#(MetadataT) metadata;
  interface PktWriteServer writeServer;
  interface PktWriteClient writeClient;
  interface Put#(int) verbosity;
  method DeparserPerfRec read_perf_info ();
endinterface
module mkDeparser  (Deparser);
  Reg#(int) cr_verbosity[2] <- mkCRegU(2);
  FIFOF#(int) cr_verbosity_ff <- mkFIFOF;
  rule set_verbosity;
    let x = cr_verbosity_ff.first;
    cr_verbosity_ff.deq;
    cr_verbosity[1] <= x;
  endrule

  FIFOF#(EtherData) data_in_ff <- mkFIFOF;
  FIFOF#(EtherData) data_out_ff <- mkFIFOF;
  FIFOF#(MetadataT) meta_in_ff <- mkFIFOF;
  Reg#(Bit#(32)) rg_offset <- mkReg(0);
  Reg#(Bit#(128)) rg_buff <- mkReg(0);
  Reg#(DeparserState) rg_deparse_state <- mkReg(StateDeparseStart);
  let din = data_in_ff.first;
  let meta = meta_in_ff.first;
  function Action report_deparse_action(DeparserState state, Bit#(32) offset);
    action
      if (cr_verbosity[0] > 0) begin
        $display("(%d) Deparse State %h offset %h", $time, state, offset);
      end
    endaction
  endfunction
  function Action succeed_and_next(Bit#(32) offset);
    action
      data_in_ff.deq;
      rg_offset <= offset;
    endaction
  endfunction
  function Action failed_and_trap(Bit#(32) offset);
    action
      data_in_ff.deq;
      rg_offset <= 0;
    endaction
  endfunction
  function DeparserState compute_next_state(DeparserState state);
    DeparserState nextState = StateDeparseStart;
    return nextState;
  endfunction
  function Bit#(l) read_data(UInt#(8) lhs, UInt#(8) rhs)
   provisos (Add#(a__, l, 128));
    Bit#(l) ldata = truncate(din.data) << (fromInteger(valueOf(l))-lhs);
    Bit#(l) rdata = truncate(rg_buff) >> (fromInteger(valueOf(l))-rhs);
    Bit#(l) cdata = ldata | rdata;
    return cdata;
  endfunction
  function Bit#(max) create_mask(UInt#(max) count);
    Bit#(max) v = 1 << count - 1;
    return v;
  endfunction
  rule rl_start_state if (rg_deparse_state == StateDeparseStart);
    let v = data_in_ff.first;
    if (v.sop) begin
      rg_deparse_state <= StateEthernet;
    end
    else begin
      data_in_ff.deq;
      data_out_ff.enq(v);
    end
  endrule

  function Rules build_deparse_rule_no_opt(DeparserState state, int offset, Tuple2#(Bit#(n), Bit#(n)) m, UInt#(8) clen, UInt#(8) plen)
   provisos (Mul#(TDiv#(n, 8), 8, n), Add#(a__, n, 128));
    Rules d = 
    rules
      rule rl_deparse if ((rg_deparse_state == state) && (rg_offset == unpack(pack(offset))));
        report_deparse_action(rg_deparse_state, rg_offset);
        match {.meta, .mask} = m;
        Vector#(n, Bit#(1)) curr_meta = takeAt(0, unpack(byteSwap(meta)));
        Vector#(n, Bit#(1)) curr_mask = takeAt(0, unpack(byteSwap(mask)));
        Bit#(n) curr_data = read_data (clen, plen);
        $display ("read_data %h", curr_data);
        let data = apply_changes (curr_data, pack(curr_meta), pack(curr_mask));
        let data_this_cycle = EtherData { sop: din.sop, eop: din.eop, data: zeroExtend(data), mask: create_mask(cExtend(fromInteger(valueOf(n)))) };
        data_out_ff.enq (data_this_cycle);
        DeparserState next_state = compute_next_state(state);
        $display ("next_state %h", next_state);
        rg_deparse_state <= next_state;
        rg_buff <= din.data;
        // apply header removal by marking mask zero
        // apply added header by setting field at offset.
        succeed_and_next (rg_offset + cExtend(clen) + cExtend(plen));
      endrule

    endrules;
    return d;
  endfunction
  interface metadata = toPipeIn(meta_in_ff);
  interface PktWriteServer writeServer;
    interface writeData = toPut(data_in_ff);
  endinterface
  interface PktWriteClient writeClient;
    interface writeData = toGet(data_out_ff);
  endinterface
  interface verbosity = toPut(cr_verbosity_ff);
endmodule
typedef union tagged {
  struct {
    PacketInstance pkt;
  } DropReqT;
  struct {
    PacketInstance pkt;
  } NopReqT;
  struct {
    PacketInstance pkt;
    Bit#(9) runtime_port;
  } ForwardReqT;
  struct {
    PacketInstance pkt;
    Bit#(32) paxos$inst;
  } IncreaseInstanceReqT;
} BBRequest deriving (Bits, Eq);
typedef union tagged {
  struct {
    PacketInstance pkt;
  } DropRspT;
  struct {
    PacketInstance pkt;
  } NopRspT;
  struct {
    PacketInstance pkt;
    Bit#(9) standard_metadata$egress_spec;
  } ForwardRspT;
  struct {
    PacketInstance pkt;
    Bit#(32) paxos$inst;
    Bit#(16) udp$dstPort;
    Bit#(16) udp$checksum;
  } IncreaseInstanceRspT;
} BBResponse deriving (Bits, Eq);

// ====== _DROP ======

interface Drop;
  interface Server#(BBRequest, BBResponse) prev_control_state;
endinterface
module mkDrop  (Drop);
  RX #(BBRequest) rx_prev_control_state <- mkRX;
  TX #(BBResponse) tx_prev_control_state <- mkTX;
  let rx_info_prev_control_state = rx_prev_control_state.u;
  let tx_info_prev_control_state = tx_prev_control_state.u;
  FIFOF#(PacketInstance) curr_packet_ff <- mkFIFOF;
  rule _drop_request;
    let v = rx_info_prev_control_state.first;
    rx_info_prev_control_state.deq;
    case (v) matches
      tagged DropReqT {pkt: .pkt}: begin
        curr_packet_ff.enq(pkt);
      end
    endcase
  endrule

  rule _drop_response;
    let pkt <- toGet(curr_packet_ff).get;
    BBResponse rsp = tagged DropRspT {pkt: pkt};
    tx_info_prev_control_state.enq(rsp);
  endrule

  interface prev_control_state = toServer(rx_prev_control_state.e, tx_prev_control_state.e);
endmodule

// ====== _NOP ======

interface Nop;
  interface Server#(BBRequest, BBResponse) prev_control_state;
endinterface
module mkNop  (Nop);
  RX #(BBRequest) rx_prev_control_state <- mkRX;
  TX #(BBResponse) tx_prev_control_state <- mkTX;
  let rx_info_prev_control_state = rx_prev_control_state.u;
  let tx_info_prev_control_state = tx_prev_control_state.u;
  FIFOF#(PacketInstance) curr_packet_ff <- mkFIFOF;
  rule _nop_request;
    let v = rx_info_prev_control_state.first;
    rx_info_prev_control_state.deq;
    case (v) matches
      tagged NopReqT {pkt: .pkt}: begin
        curr_packet_ff.enq(pkt);
      end
    endcase
  endrule

  rule _nop_response;
    let pkt <- toGet(curr_packet_ff).get;
    BBResponse rsp = tagged NopRspT {pkt: pkt};
    tx_info_prev_control_state.enq(rsp);
  endrule

  interface prev_control_state = toServer(rx_prev_control_state.e, tx_prev_control_state.e);
endmodule

// ====== FORWARD ======

interface Forward;
  interface Server#(BBRequest, BBResponse) prev_control_state;
endinterface
module mkForward  (Forward);
  RX #(BBRequest) rx_prev_control_state <- mkRX;
  TX #(BBResponse) tx_prev_control_state <- mkTX;
  let rx_info_prev_control_state = rx_prev_control_state.u;
  let tx_info_prev_control_state = tx_prev_control_state.u;
  FIFOF#(PacketInstance) curr_packet_ff <- mkFIFOF;
  Reg#(Bit#(9)) standard_metadata$egress_spec <- mkReg(0);
  rule forward_request;
    let v = rx_info_prev_control_state.first;
    rx_info_prev_control_state.deq;
    case (v) matches
      tagged ForwardReqT {pkt: .pkt, runtime_port: .runtime_port}: begin
        standard_metadata$egress_spec <= runtime_port;
        curr_packet_ff.enq(pkt);
      end
    endcase
  endrule

  rule forward_response;
    let pkt <- toGet(curr_packet_ff).get;
    BBResponse rsp = tagged ForwardRspT {pkt: pkt, standard_metadata$egress_spec: standard_metadata$egress_spec};
    tx_info_prev_control_state.enq(rsp);
  endrule

  interface prev_control_state = toServer(rx_prev_control_state.e, tx_prev_control_state.e);
endmodule

// ====== INCREASE_INSTANCE ======

interface IncreaseInstance;
  interface Client#(RegRequest#(1, 32), RegResponse#(32)) instance_register;
  interface Server#(BBRequest, BBResponse) prev_control_state;
endinterface
module mkIncreaseInstance  (IncreaseInstance);
  RX #(BBRequest) rx_prev_control_state <- mkRX;
  TX #(BBResponse) tx_prev_control_state <- mkTX;
  let rx_info_prev_control_state = rx_prev_control_state.u;
  let tx_info_prev_control_state = tx_prev_control_state.u;
  FIFOF#(PacketInstance) curr_packet_ff <- mkFIFOF;
  TX #(RegRequest#(1, 32)) tx_instance_register <- mkTX;
  RX #(RegResponse#(32)) rx_instance_register <- mkRX;
  let tx_info_instance_register = tx_instance_register.u;
  let rx_info_instance_register = rx_instance_register.u;
  Reg#(Bit#(32)) rg_paxos$inst <- mkReg(0);
  Reg#(Bit#(16)) udp$dstPort <- mkReg(0);
  Reg#(Bit#(16)) udp$checksum <- mkReg(0);
  rule increase_instance_request;
    let v = rx_info_prev_control_state.first;
    rx_info_prev_control_state.deq;
    case (v) matches
      tagged IncreaseInstanceReqT {pkt: .pkt, paxos$inst: .paxos$inst}: begin
        let instance_register_req = RegRequest { addr: 0, data: paxos$inst, write: True };
        tx_info_instance_register.enq(instance_register_req);
        rg_paxos$inst <= paxos$inst;
        udp$dstPort <= 'h8889;
        udp$checksum <= 'h0;
        curr_packet_ff.enq(pkt);
      end
    endcase
  endrule

  rule increase_instance_response;
    let v_paxos$inst = rx_info_instance_register.first;
    rx_info_instance_register.deq;
    let paxos$inst = v_paxos$inst.data;
    let pkt <- toGet(curr_packet_ff).get;
    BBResponse rsp = tagged IncreaseInstanceRspT {pkt: pkt, paxos$inst: paxos$inst, udp$dstPort: udp$dstPort, udp$checksum: udp$checksum};
    tx_info_prev_control_state.enq(rsp);
  endrule

  interface instance_register = toClient(tx_instance_register.e, rx_instance_register.e);
  interface prev_control_state = toServer(rx_prev_control_state.e, tx_prev_control_state.e);
endmodule

// ====== SEQUENCE_TBL ======

typedef struct {
  Bit#(16) paxos$msgtype;
  Bit#(2) padding;
} SequenceTblReqT deriving (Bits, Eq);
typedef enum {
  DEFAULT_SEQUENCE_TBL,
  INCREASE_INSTANCE,
  NOP
} SequenceTblActionT deriving (Bits, Eq);
typedef struct {
  SequenceTblActionT _action;
} SequenceTblRspT deriving (Bits, Eq);
import "BDPI" function ActionValue#(Bit#(2)) matchtable_read_sequence_tbl(Bit#(18) msgtype);
import "BDPI" function Action matchtable_write_sequence_tbl(Bit#(18) msgtype, Bit#(2) data);
instance MatchTableSim#(1, 18, 2);
  function ActionValue#(Bit#(2)) matchtable_read(Bit#(1) id, Bit#(18) key);
    actionvalue
      let v <- matchtable_read_sequence_tbl(key);
      return v;
    endactionvalue
  endfunction
  function Action matchtable_write(Bit#(1) id, Bit#(18) key, Bit#(2) data);
    action
      matchtable_write_sequence_tbl(key, data);
    endaction
  endfunction
endinstance
interface SequenceTbl;
  interface Server #(MetadataRequest, MetadataResponse) prev_control_state_0;
  interface Client #(BBRequest, BBResponse) next_control_state_0;
  interface Client #(BBRequest, BBResponse) next_control_state_1;
endinterface
module mkSequenceTbl  (SequenceTbl);
  RX #(MetadataRequest) rx_metadata <- mkRX;
  let rx_info_metadata = rx_metadata.u;
  TX #(MetadataResponse) tx_metadata <- mkTX;
  let tx_info_metadata = tx_metadata.u;
  Vector#(2, FIFOF#(BBRequest)) bbReqFifo <- replicateM(mkFIFOF);
  Vector#(2, FIFOF#(BBResponse)) bbRspFifo <- replicateM(mkFIFOF);
  FIFOF#(PacketInstance) packet_ff <- mkFIFOF;
  MatchTable#(1, 256, SizeOf#(SequenceTblReqT), SizeOf#(SequenceTblRspT)) matchTable <- mkMatchTable("sequence_tbl.dat");
  Vector#(2, Bool) readyBits = map(fifoNotEmpty, bbRspFifo);
  Bool interruptStatus = False;
  Bit#(2) readyChannel = -1;
  for (Integer i=1; i>=0; i=i-1) begin
      if (readyBits[i]) begin
          interruptStatus = True;
          readyChannel = fromInteger(i);
      end
  end

  Vector#(2, FIFOF#(MetadataT)) metadata_ff <- replicateM(mkFIFOF);
  rule rl_handle_request;
    let data = rx_info_metadata.first;
    rx_info_metadata.deq;
    let meta = data.meta;
    let pkt = data.pkt;
    let paxos$msgtype = fromMaybe(?, meta.paxos$msgtype);
    SequenceTblReqT req = SequenceTblReqT {paxos$msgtype: paxos$msgtype};
    matchTable.lookupPort.request.put(pack(req));
    packet_ff.enq(pkt);
    metadata_ff[0].enq(meta);
  endrule

  rule rl_handle_execute;
    let rsp <- matchTable.lookupPort.response.get;
    let pkt <- toGet(packet_ff).get;
    let meta <- toGet(metadata_ff[0]).get;
    let paxos$inst = fromMaybe(?, meta.paxos$inst);
    if (rsp matches tagged Valid .data) begin
      SequenceTblRspT resp = unpack(data);
      case (resp._action) matches
        INCREASE_INSTANCE: begin
          BBRequest req = tagged IncreaseInstanceReqT {pkt: pkt, paxos$inst: paxos$inst};
          bbReqFifo[0].enq(req); //FIXME: replace with RXTX.
        end
        NOP: begin
          BBRequest req = tagged NopReqT {pkt: pkt};
          bbReqFifo[1].enq(req); //FIXME: replace with RXTX.
        end
      endcase
      // forward metadata to next stage.
      metadata_ff[1].enq(meta);
    end
  endrule

  rule rl_handle_response if (interruptStatus);
    let v <- toGet(bbRspFifo[readyChannel]).get;
    let meta <- toGet(metadata_ff[1]).get;
    case (v) matches
      tagged IncreaseInstanceRspT {pkt: .pkt, paxos$inst: .paxos$inst, udp$dstPort: .udp$dstPort, udp$checksum: .udp$checksum}: begin
        meta.paxos$inst = tagged Valid paxos$inst;
        meta.udp$dstPort = tagged Valid udp$dstPort;
        meta.udp$checksum = tagged Valid udp$checksum;
        MetadataResponse rsp = tagged SequenceTblIncreaseInstanceRspT {pkt: pkt, meta: meta};
        tx_info_metadata.enq(rsp);
      end
      tagged NopRspT {pkt: .pkt}: begin
        MetadataResponse rsp = tagged SequenceTblNopRspT {pkt: pkt, meta: meta};
        tx_info_metadata.enq(rsp);
      end
    endcase
  endrule

  interface prev_control_state_0 = toServer(rx_metadata.e, tx_metadata.e);
  interface next_control_state_0 = toClient(bbReqFifo[0], bbRspFifo[0]);
  interface next_control_state_1 = toClient(bbReqFifo[1], bbRspFifo[1]);
endmodule

// ====== FORWARD_TBL ======

typedef struct {
  Bit#(9) standard_metadata$ingress_port;
} ForwardTblReqT deriving (Bits, Eq);
typedef enum {
  DEFAULT_FORWARD_TBL,
  FORWARD,
  DROP
} ForwardTblActionT deriving (Bits, Eq);
typedef struct {
  ForwardTblActionT _action;
  Bit#(9) runtime_port;
} ForwardTblRspT deriving (Bits, Eq);
import "BDPI" function ActionValue#(Bit#(11)) matchtable_read_forward_tbl(Bit#(9) msgtype);
import "BDPI" function Action matchtable_write_forward_tbl(Bit#(9) msgtype, Bit#(11) data);
instance MatchTableSim#(0, 9, 11);
  function ActionValue#(Bit#(11)) matchtable_read(Bit#(0) id, Bit#(9) key);
    actionvalue
      let v <- matchtable_read_forward_tbl(key);
      return v;
    endactionvalue
  endfunction
  function Action matchtable_write(Bit#(0) id, Bit#(9) key, Bit#(11) data);
    action
      matchtable_write_forward_tbl(key, data);
    endaction
  endfunction
endinstance
interface ForwardTbl;
  interface Server #(MetadataRequest, MetadataResponse) prev_control_state_0;
  interface Client #(BBRequest, BBResponse) next_control_state_0;
  interface Client #(BBRequest, BBResponse) next_control_state_1;
endinterface
module mkForwardTbl  (ForwardTbl);
  RX #(MetadataRequest) rx_metadata <- mkRX;
  let rx_info_metadata = rx_metadata.u;
  TX #(MetadataResponse) tx_metadata <- mkTX;
  let tx_info_metadata = tx_metadata.u;
  Vector#(2, FIFOF#(BBRequest)) bbReqFifo <- replicateM(mkFIFOF);
  Vector#(2, FIFOF#(BBResponse)) bbRspFifo <- replicateM(mkFIFOF);
  FIFOF#(PacketInstance) packet_ff <- mkFIFOF;
  MatchTable#(0, 256, SizeOf#(ForwardTblReqT), SizeOf#(ForwardTblRspT)) matchTable <- mkMatchTable("forward_tbl.dat");
  Vector#(2, Bool) readyBits = map(fifoNotEmpty, bbRspFifo);
  Bool interruptStatus = False;
  Bit#(2) readyChannel = -1;
  for (Integer i=1; i>=0; i=i-1) begin
      if (readyBits[i]) begin
          interruptStatus = True;
          readyChannel = fromInteger(i);
      end
  end

  Vector#(2, FIFOF#(MetadataT)) metadata_ff <- replicateM(mkFIFOF);
  rule rl_handle_request;
    let data = rx_info_metadata.first;
    rx_info_metadata.deq;
    let meta = data.meta;
    let pkt = data.pkt;
    let standard_metadata$ingress_port = fromMaybe(?, meta.standard_metadata$ingress_port);
    ForwardTblReqT req = ForwardTblReqT {standard_metadata$ingress_port: standard_metadata$ingress_port};
    matchTable.lookupPort.request.put(pack(req));
    packet_ff.enq(pkt);
    metadata_ff[0].enq(meta);
  endrule

  rule rl_handle_execute;
    let rsp <- matchTable.lookupPort.response.get;
    let pkt <- toGet(packet_ff).get;
    let meta <- toGet(metadata_ff[0]).get;
    if (rsp matches tagged Valid .data) begin
      ForwardTblRspT resp = unpack(data);
      case (resp._action) matches
        FORWARD: begin
          BBRequest req = tagged ForwardReqT {pkt: pkt, runtime_port: resp.runtime_port};
          bbReqFifo[0].enq(req); //FIXME: replace with RXTX.
        end
        DROP: begin
          BBRequest req = tagged DropReqT {pkt: pkt};
          bbReqFifo[1].enq(req); //FIXME: replace with RXTX.
        end
      endcase
      // forward metadata to next stage.
      metadata_ff[1].enq(meta);
    end
  endrule

  rule rl_handle_response if (interruptStatus);
    let v <- toGet(bbRspFifo[readyChannel]).get;
    let meta <- toGet(metadata_ff[1]).get;
    case (v) matches
      tagged ForwardRspT {pkt: .pkt, standard_metadata$egress_spec: .standard_metadata$egress_spec}: begin
        meta.standard_metadata$egress_spec = tagged Valid standard_metadata$egress_spec;
        MetadataResponse rsp = tagged ForwardTblForwardRspT {pkt: pkt, meta: meta};
        tx_info_metadata.enq(rsp);
      end
      tagged DropRspT {pkt: .pkt}: begin
        MetadataResponse rsp = tagged ForwardTblDropRspT {pkt: pkt, meta: meta};
        tx_info_metadata.enq(rsp);
      end
    endcase
  endrule

  interface prev_control_state_0 = toServer(rx_metadata.e, tx_metadata.e);
  interface next_control_state_0 = toClient(bbReqFifo[0], bbRspFifo[0]);
  interface next_control_state_1 = toClient(bbReqFifo[1], bbRspFifo[1]);
endmodule

// ====== INGRESS ======

interface Ingress;
  interface Client#(MetadataRequest, MetadataResponse) next;
endinterface
module mkIngress #(Vector#(numClients, Client#(MetadataRequest, MetadataResponse)) mdc) (Ingress);
  FIFOF#(MetadataRequest) default_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) default_rsp_ff <- mkFIFOF;
  FIFOF#(MetadataRequest) forward_tbl_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) forward_tbl_rsp_ff <- mkFIFOF;
  FIFOF#(MetadataRequest) sequence_tbl_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) sequence_tbl_rsp_ff <- mkFIFOF;
  FIFOF#(MetadataRequest) next_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) next_rsp_ff <- mkFIFOF;
  Vector#(numClients, Server#(MetadataRequest, MetadataResponse)) mds = replicate(toServer(default_req_ff, default_rsp_ff));
  mkConnection(mds, mdc);
  ForwardTbl forward_tbl <- mkForwardTbl();
  SequenceTbl sequence_tbl <- mkSequenceTbl();
  mkConnection(toClient(forward_tbl_req_ff, forward_tbl_rsp_ff), forward_tbl.prev_control_state_0);
  mkConnection(toClient(sequence_tbl_req_ff, sequence_tbl_rsp_ff), sequence_tbl.prev_control_state_0);
  // Basic Blocks
  Forward forward_0 <- mkForward();
  Drop _drop_0 <- mkDrop();
  IncreaseInstance increase_instance_0 <- mkIncreaseInstance();
  Nop _nop_0 <- mkNop();
  RegisterIfc#(1, 32) instance_register <- mkP4Register(vec(increase_instance_0.instance_register));
  mkChan(mkFIFOF, mkFIFOF, forward_tbl.next_control_state_0, forward_0.prev_control_state);
  mkChan(mkFIFOF, mkFIFOF, forward_tbl.next_control_state_1, _drop_0.prev_control_state);
  mkChan(mkFIFOF, mkFIFOF, sequence_tbl.next_control_state_0, increase_instance_0.prev_control_state);
  mkChan(mkFIFOF, mkFIFOF, sequence_tbl.next_control_state_1, _nop_0.prev_control_state);
  rule default_next_state if (default_req_ff.notEmpty);
    default_req_ff.deq;
    let _req = default_req_ff.first;
    let meta = _req.meta;
    let pkt = _req.pkt;
    if (isValid(meta.valid_ipv4)) begin
      MetadataRequest req = MetadataRequest {pkt: pkt, meta: meta};
      forward_tbl_req_ff.enq(req);
    end
  endrule

  rule forward_tbl_next_state if (forward_tbl_rsp_ff.notEmpty);
    forward_tbl_rsp_ff.deq;
    let _rsp = forward_tbl_rsp_ff.first;
    case (_rsp) matches
      tagged ForwardTblForwardRspT {meta: .meta, pkt: .pkt}: begin
        if (isValid(meta.valid_paxos)) begin
          MetadataRequest req = MetadataRequest {pkt: pkt, meta: meta};
          sequence_tbl_req_ff.enq(req);
        end
      end
      tagged ForwardTblDropRspT {meta: .meta, pkt: .pkt}: begin
        if (isValid(meta.valid_paxos)) begin
          MetadataRequest req = MetadataRequest {pkt: pkt, meta: meta};
          sequence_tbl_req_ff.enq(req);
        end
      end
    endcase
  endrule

  rule sequence_tbl_next_state if (sequence_tbl_rsp_ff.notEmpty);
    sequence_tbl_rsp_ff.deq;
    let _rsp = sequence_tbl_rsp_ff.first;
    case (_rsp) matches
      tagged SequenceTblIncreaseInstanceRspT {meta: .meta, pkt: .pkt}: begin
        MetadataRequest req = MetadataRequest {pkt: pkt, meta: meta};
        next_req_ff.enq(req);
      end
      tagged SequenceTblNopRspT {meta: .meta, pkt: .pkt}: begin
        MetadataRequest req = MetadataRequest {pkt: pkt, meta: meta};
        next_req_ff.enq(req);
      end
    endcase
  endrule

  interface next = (interface Client#(MetadataRequest, MetadataResponse);
    interface request = toGet(next_req_ff);
    interface response = toPut(next_rsp_ff);
  endinterface);
endmodule

// ====== EGRESS ======

interface Egress;
  interface Client#(MetadataRequest, MetadataResponse) next;
endinterface
module mkEgress #(Vector#(numClients, Client#(MetadataRequest, MetadataResponse)) mdc) (Egress);
  FIFOF#(MetadataRequest) default_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) default_rsp_ff <- mkFIFOF;
  FIFOF#(MetadataRequest) next_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) next_rsp_ff <- mkFIFOF;
  Vector#(numClients, Server#(MetadataRequest, MetadataResponse)) mds = replicate(toServer(default_req_ff, default_rsp_ff));
  mkConnection(mds, mdc);
  // Basic Blocks
  //RegisterIfc#(1, 32) instance_register <- mkP4Register(nil);
  rule default_next_state if (default_req_ff.notEmpty);
    default_req_ff.deq;
    let _req = default_req_ff.first;
    let meta = _req.meta;
    let pkt = _req.pkt;
    MetadataRequest req = MetadataRequest {pkt: pkt, meta: meta};
    next_req_ff.enq(req);
  endrule

  interface next = (interface Client#(MetadataRequest, MetadataResponse);
    interface request = toGet(next_req_ff);
    interface response = toPut(next_rsp_ff);
  endinterface);
endmodule
// Copyright (c) 2016 P4FPGA Project

// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
