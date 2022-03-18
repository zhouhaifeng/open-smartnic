
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
  Bit#(3) packetType;
  Bit#(2) headerVersion;
  Bit#(2) packetVersion;
  Bit#(1) pad1;
  Bit#(3) fabricColor;
  Bit#(5) fabricQos;
  Bit#(8) dstDevice;
  Bit#(16) dstPortOrGroup;
} FabricHeaderT deriving (Bits, Eq);
instance DefaultValue#(FabricHeaderT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(FabricHeaderT);
  defaultMask = unpack(maxBound);
endinstance
function FabricHeaderT extract_fabric_header_t(Bit#(40) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(1) routed;
  Bit#(1) outerRouted;
  Bit#(1) tunnelTerminate;
  Bit#(5) ingressTunnelType;
  Bit#(16) nexthopIndex;
} FabricHeaderUnicastT deriving (Bits, Eq);
instance DefaultValue#(FabricHeaderUnicastT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(FabricHeaderUnicastT);
  defaultMask = unpack(maxBound);
endinstance
function FabricHeaderUnicastT extract_fabric_header_unicast_t(Bit#(24) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(1) routed;
  Bit#(1) outerRouted;
  Bit#(1) tunnelTerminate;
  Bit#(5) ingressTunnelType;
  Bit#(16) ingressIfindex;
  Bit#(16) ingressBd;
  Bit#(16) mcastGrp;
} FabricHeaderMulticastT deriving (Bits, Eq);
instance DefaultValue#(FabricHeaderMulticastT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(FabricHeaderMulticastT);
  defaultMask = unpack(maxBound);
endinstance
function FabricHeaderMulticastT extract_fabric_header_multicast_t(Bit#(56) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(16) rewriteIndex;
  Bit#(10) egressPort;
  Bit#(5) egressQueue;
  Bit#(1) pad;
} FabricHeaderMirrorT deriving (Bits, Eq);
instance DefaultValue#(FabricHeaderMirrorT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(FabricHeaderMirrorT);
  defaultMask = unpack(maxBound);
endinstance
function FabricHeaderMirrorT extract_fabric_header_mirror_t(Bit#(32) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(5) egressQueue;
  Bit#(1) txBypass;
  Bit#(2) reserved;
  Bit#(16) ingressPort;
  Bit#(16) ingressIfindex;
  Bit#(16) ingressBd;
  Bit#(16) reasonCode;
} FabricHeaderCpuT deriving (Bits, Eq);
instance DefaultValue#(FabricHeaderCpuT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(FabricHeaderCpuT);
  defaultMask = unpack(maxBound);
endinstance
function FabricHeaderCpuT extract_fabric_header_cpu_t(Bit#(72) data);
  return unpack(byteSwap(data));
endfunction

typedef struct {
  Bit#(16) etherType;
} FabricPayloadHeaderT deriving (Bits, Eq);
instance DefaultValue#(FabricPayloadHeaderT);
  defaultValue = unpack(0);
endinstance
instance DefaultMask#(FabricPayloadHeaderT);
  defaultMask = unpack(maxBound);
endinstance
function FabricPayloadHeaderT extract_fabric_payload_header_t(Bit#(16) data);
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
  PacketInstance pkt;
  MetadataT meta;
} MetadataRequest deriving (Bits, Eq);
typedef union tagged {
  struct {
    PacketInstance pkt;
    MetadataT meta;
  } DropNopRspT;
} MetadataResponse deriving (Bits, Eq);
typedef struct {
} MetadataT deriving (Bits, Eq);
instance DefaultValue#(MetadataT);
  defaultValue = unpack(0);
endinstance
// ====== PARSER ======

typedef enum {
  StateStart,
  StateParseEthernet,
  StateParseFabricHeader,
  StateParseFabricHeaderUnicast,
  StateParseFabricHeaderMulticast,
  StateParseFabricHeaderMirror,
  StateParseFabricHeaderCpu,
  StateParseFabricPayloadHeader,
  StateParseIpv4
} ParserState deriving (Bits, Eq);
interface Parser;
  interface Put#(EtherData) frameIn;
  interface Get#(MetadataT) meta;
  interface Put#(int) verbosity;
  method ParserPerfRec read_perf_info ();
endinterface
module mkParser  (Parser);
  PulseWire w_parse_fabric_header_start <- mkPulseWireOR();
  PulseWire w_parse_ipv4_start <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_mirror_parse_fabric_payload_header <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_unicast_parse_fabric_payload_header <- mkPulseWireOR();
  PulseWire w_parse_ethernet_parse_ipv4 <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_parse_fabric_header_cpu <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_cpu_parse_fabric_payload_header <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_parse_fabric_header_mirror <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_parse_fabric_header_unicast <- mkPulseWireOR();
  PulseWire w_parse_fabric_payload_header_parse_ipv4 <- mkPulseWireOR();
  PulseWire w_parse_ethernet_parse_fabric_header <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_parse_fabric_header_multicast <- mkPulseWireOR();
  PulseWire w_parse_fabric_header_multicast_parse_fabric_payload_header <- mkPulseWireOR();
  Reg#(ParserState) rg_parse_state <- mkReg(StateStart);
  Reg#(int) cr_verbosity[2] <- mkCRegU(2);
  FIFOF#(int) cr_verbosity_ff <- mkFIFOF;
  rule set_verbosity;
    let x = cr_verbosity_ff.first;
    cr_verbosity_ff.deq;
    cr_verbosity[1] <= x;
  endrule

  FIFOF#(EtherData) data_in_ff <- mkFIFOF;
  FIFOF#(MetadataT) meta_in_ff <- mkFIFOF;
  PulseWire parse_done <- mkPulseWire();
  Reg#(Bit#(32)) rg_next_header_len[3] <- mkCReg(3, 0);
  Reg#(Bit#(32)) rg_buffered[3] <- mkCReg(3, 0);
  Reg#(Bit#(32)) rg_shift_amt[3] <- mkCReg(3, 0);
  Reg#(Bit#(512)) rg_tmp <- mkReg(0);
  Reg#(Bool) rg_dequeue_data[3] <- mkCReg(3, False);
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
  function Action fetch_next_header(Bit#(32) len);
    action
      rg_next_header_len[0] <= len;
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
  function Action compute_next_state_parse_ethernet(Bit#(16) etherType);
    action
      let v = {etherType};
      case (v) matches
        'h9000: begin
          dbg3($format("transit to parse_fabric_header"));
          w_parse_ethernet_parse_fabric_header.send();
        end
        'h0800: begin
          dbg3($format("transit to parse_ipv4"));
          w_parse_ethernet_parse_ipv4.send();
        end
      endcase
    endaction
  endfunction
  function Action compute_next_state_parse_fabric_header(Bit#(3) packetType);
    action
      let v = {packetType};
      case (v) matches
        'h01: begin
          dbg3($format("transit to parse_fabric_header_unicast"));
          w_parse_fabric_header_parse_fabric_header_unicast.send();
        end
        'h02: begin
          dbg3($format("transit to parse_fabric_header_multicast"));
          w_parse_fabric_header_parse_fabric_header_multicast.send();
        end
        'h03: begin
          dbg3($format("transit to parse_fabric_header_mirror"));
          w_parse_fabric_header_parse_fabric_header_mirror.send();
        end
        'h05: begin
          dbg3($format("transit to parse_fabric_header_cpu"));
          w_parse_fabric_header_parse_fabric_header_cpu.send();
        end
        default: begin
          dbg3($format("transit to start"));
          w_parse_fabric_header_start.send();
        end
      endcase
    endaction
  endfunction
  function Action compute_next_state_parse_fabric_header_unicast();
    action
      dbg3($format("transit to parse_fabric_payload_header"));
      w_parse_fabric_header_unicast_parse_fabric_payload_header.send();
    endaction
  endfunction
  function Action compute_next_state_parse_fabric_header_multicast();
    action
      dbg3($format("transit to parse_fabric_payload_header"));
      w_parse_fabric_header_multicast_parse_fabric_payload_header.send();
    endaction
  endfunction
  function Action compute_next_state_parse_fabric_header_mirror();
    action
      dbg3($format("transit to parse_fabric_payload_header"));
      w_parse_fabric_header_mirror_parse_fabric_payload_header.send();
    endaction
  endfunction
  function Action compute_next_state_parse_fabric_header_cpu();
    action
      dbg3($format("transit to parse_fabric_payload_header"));
      w_parse_fabric_header_cpu_parse_fabric_payload_header.send();
    endaction
  endfunction
  function Action compute_next_state_parse_fabric_payload_header(Bit#(16) etherType);
    action
      let v = {etherType};
      case (v) matches
        'h0800: begin
          dbg3($format("transit to parse_ipv4"));
          w_parse_fabric_payload_header_parse_ipv4.send();
        end
      endcase
    endaction
  endfunction
  function Action compute_next_state_parse_ipv4(Bit#(13) fragOffset, Bit#(4) ihl, Bit#(8) protocol);
    action
      let v = {fragOffset, ihl, protocol};
      case (v) matches
        default: begin
          dbg3($format("transit to start"));
          w_parse_ipv4_start.send();
        end
      endcase
    endaction
  endfunction

  let sop_this_cycle = data_in_ff.first.sop;
  let eop_this_cycle = data_in_ff.first.eop;
  let data_this_cycle = data_in_ff.first.data;

  rule rl_data_ff_load if (rg_buffered[1] < rg_next_header_len[1]);
    rg_buffered[1] <= rg_buffered[1] + 128;
    data_in_ff.deq;
    rg_dequeue_data[1] <= True;
    dbg3($format("dequeue data %d %d", rg_buffered[1], rg_next_header_len[1]));
  endrule

  rule rl_data_ff_idle if (rg_buffered[1] >= rg_next_header_len[1]);
    rg_dequeue_data[1] <= False;
  endrule

  rule rl_start_state if ((rg_parse_state == StateStart) && sop_this_cycle);
    rg_parse_state <= StateParseEthernet;
    rg_buffered[0] <= 128;
    rg_shift_amt[0] <= 0;
    rg_dequeue_data[2] <= True;
    dbg3($format("start state -> ethernet"));
  endrule

  rule rl_start_state_wait if ((rg_parse_state == StateStart) && !sop_this_cycle);
    data_in_ff.deq;
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ethernet_load if ((rg_parse_state == StateParseEthernet) && (rg_buffered[0] < 112));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ethernet_extract if ((rg_parse_state == StateParseEthernet) && (rg_buffered[0] >= 112));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    let ethernet_t = extract_ethernet_t(truncate(data));
    compute_next_state_parse_ethernet(ethernet_t.etherType);
    rg_tmp <= zeroExtend(data >> 112);
    succeed_and_next(112);
    dbg3($format("extract %s %h", "parse_ethernet", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_ethernet_parse_fabric_header, rl_parse_ethernet_parse_ipv4" *)
  rule rl_parse_ethernet_parse_fabric_header if ((rg_parse_state == StateParseEthernet) && (w_parse_ethernet_parse_fabric_header));
    rg_parse_state <= StateParseFabricHeader;
    dbg3($format("%s -> %s", "parse_ethernet", "parse_fabric_header"));
    fetch_next_header(40);
  endrule

  rule rl_parse_ethernet_parse_ipv4 if ((rg_parse_state == StateParseEthernet) && (w_parse_ethernet_parse_ipv4));
    rg_parse_state <= StateParseIpv4;
    dbg3($format("%s -> %s", "parse_ethernet", "parse_ipv4"));
    fetch_next_header(160);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_load if ((rg_parse_state == StateParseFabricHeader) && (rg_buffered[0] < 40));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_extract if ((rg_parse_state == StateParseFabricHeader) && (rg_buffered[0] >= 40));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    let fabric_header_t = extract_fabric_header_t(truncate(data));
    compute_next_state_parse_fabric_header(fabric_header_t.packetType);
    rg_tmp <= zeroExtend(data >> 40);
    succeed_and_next(40);
    dbg3($format("extract %s %h", "parse_fabric_header", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_fabric_header_parse_fabric_header_unicast, rl_parse_fabric_header_parse_fabric_header_multicast, rl_parse_fabric_header_parse_fabric_header_mirror, rl_parse_fabric_header_parse_fabric_header_cpu, rl_parse_fabric_header_start" *)
  rule rl_parse_fabric_header_parse_fabric_header_unicast if ((rg_parse_state == StateParseFabricHeader) && (w_parse_fabric_header_parse_fabric_header_unicast));
    rg_parse_state <= StateParseFabricHeaderUnicast;
    dbg3($format("%s -> %s", "parse_fabric_header", "parse_fabric_header_unicast"));
    fetch_next_header(24);
  endrule

  rule rl_parse_fabric_header_parse_fabric_header_multicast if ((rg_parse_state == StateParseFabricHeader) && (w_parse_fabric_header_parse_fabric_header_multicast));
    rg_parse_state <= StateParseFabricHeaderMulticast;
    dbg3($format("%s -> %s", "parse_fabric_header", "parse_fabric_header_multicast"));
    fetch_next_header(56);
  endrule

  rule rl_parse_fabric_header_parse_fabric_header_mirror if ((rg_parse_state == StateParseFabricHeader) && (w_parse_fabric_header_parse_fabric_header_mirror));
    rg_parse_state <= StateParseFabricHeaderMirror;
    dbg3($format("%s -> %s", "parse_fabric_header", "parse_fabric_header_mirror"));
    fetch_next_header(32);
  endrule

  rule rl_parse_fabric_header_parse_fabric_header_cpu if ((rg_parse_state == StateParseFabricHeader) && (w_parse_fabric_header_parse_fabric_header_cpu));
    rg_parse_state <= StateParseFabricHeaderCpu;
    dbg3($format("%s -> %s", "parse_fabric_header", "parse_fabric_header_cpu"));
    fetch_next_header(72);
  endrule

  rule rl_parse_fabric_header_start if ((rg_parse_state == StateParseFabricHeader) && (w_parse_fabric_header_start));
    rg_parse_state <= StateStart;
    dbg3($format("%s -> %s", "parse_fabric_header", "start"));
    fetch_next_header(0);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_unicast_load if ((rg_parse_state == StateParseFabricHeaderUnicast) && (rg_buffered[0] < 24));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_unicast_extract if ((rg_parse_state == StateParseFabricHeaderUnicast) && (rg_buffered[0] >= 24));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    compute_next_state_parse_fabric_header_unicast();
    rg_tmp <= zeroExtend(data >> 24);
    succeed_and_next(24);
    dbg3($format("extract %s %h", "parse_fabric_header_unicast", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_fabric_header_unicast_parse_fabric_payload_header" *)
  rule rl_parse_fabric_header_unicast_parse_fabric_payload_header if ((rg_parse_state == StateParseFabricHeaderUnicast) && (w_parse_fabric_header_unicast_parse_fabric_payload_header));
    rg_parse_state <= StateParseFabricPayloadHeader;
    dbg3($format("%s -> %s", "parse_fabric_header_unicast", "parse_fabric_payload_header"));
    fetch_next_header(16);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_multicast_load if ((rg_parse_state == StateParseFabricHeaderMulticast) && (rg_buffered[0] < 56));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_multicast_extract if ((rg_parse_state == StateParseFabricHeaderMulticast) && (rg_buffered[0] >= 56));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    compute_next_state_parse_fabric_header_multicast();
    rg_tmp <= zeroExtend(data >> 56);
    succeed_and_next(56);
    dbg3($format("extract %s %h", "parse_fabric_header_multicast", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_fabric_header_multicast_parse_fabric_payload_header" *)
  rule rl_parse_fabric_header_multicast_parse_fabric_payload_header if ((rg_parse_state == StateParseFabricHeaderMulticast) && (w_parse_fabric_header_multicast_parse_fabric_payload_header));
    rg_parse_state <= StateParseFabricPayloadHeader;
    dbg3($format("%s -> %s", "parse_fabric_header_multicast", "parse_fabric_payload_header"));
    fetch_next_header(16);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_mirror_load if ((rg_parse_state == StateParseFabricHeaderMirror) && (rg_buffered[0] < 32));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_mirror_extract if ((rg_parse_state == StateParseFabricHeaderMirror) && (rg_buffered[0] >= 32));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    compute_next_state_parse_fabric_header_mirror();
    rg_tmp <= zeroExtend(data >> 32);
    succeed_and_next(32);
    dbg3($format("extract %s %h", "parse_fabric_header_mirror", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_fabric_header_mirror_parse_fabric_payload_header" *)
  rule rl_parse_fabric_header_mirror_parse_fabric_payload_header if ((rg_parse_state == StateParseFabricHeaderMirror) && (w_parse_fabric_header_mirror_parse_fabric_payload_header));
    rg_parse_state <= StateParseFabricPayloadHeader;
    dbg3($format("%s -> %s", "parse_fabric_header_mirror", "parse_fabric_payload_header"));
    fetch_next_header(16);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_cpu_load if ((rg_parse_state == StateParseFabricHeaderCpu) && (rg_buffered[0] < 72));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_header_cpu_extract if ((rg_parse_state == StateParseFabricHeaderCpu) && (rg_buffered[0] >= 72));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    compute_next_state_parse_fabric_header_cpu();
    rg_tmp <= zeroExtend(data >> 72);
    succeed_and_next(72);
    dbg3($format("extract %s %h", "parse_fabric_header_cpu", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_fabric_header_cpu_parse_fabric_payload_header" *)
  rule rl_parse_fabric_header_cpu_parse_fabric_payload_header if ((rg_parse_state == StateParseFabricHeaderCpu) && (w_parse_fabric_header_cpu_parse_fabric_payload_header));
    rg_parse_state <= StateParseFabricPayloadHeader;
    dbg3($format("%s -> %s", "parse_fabric_header_cpu", "parse_fabric_payload_header"));
    fetch_next_header(16);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_payload_header_load if ((rg_parse_state == StateParseFabricPayloadHeader) && (rg_buffered[0] < 16));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_fabric_payload_header_extract if ((rg_parse_state == StateParseFabricPayloadHeader) && (rg_buffered[0] >= 16));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    let fabric_payload_header_t = extract_fabric_payload_header_t(truncate(data));
    compute_next_state_parse_fabric_payload_header(fabric_payload_header_t.etherType);
    rg_tmp <= zeroExtend(data >> 16);
    succeed_and_next(16);
    dbg3($format("extract %s %h", "parse_fabric_payload_header", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_fabric_payload_header_parse_ipv4" *)
  rule rl_parse_fabric_payload_header_parse_ipv4 if ((rg_parse_state == StateParseFabricPayloadHeader) && (w_parse_fabric_payload_header_parse_ipv4));
    rg_parse_state <= StateParseIpv4;
    dbg3($format("%s -> %s", "parse_fabric_payload_header", "parse_ipv4"));
    fetch_next_header(160);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ipv4_load if ((rg_parse_state == StateParseIpv4) && (rg_buffered[0] < 160));
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, rg_tmp);
  endrule

  (* fire_when_enabled *)
  rule rl_parse_ipv4_extract if ((rg_parse_state == StateParseIpv4) && (rg_buffered[0] >= 160));
    let data = rg_tmp;
    if (rg_dequeue_data[0] == True) begin
      data = zeroExtend(data_this_cycle) << rg_shift_amt[0] | rg_tmp;
    end
    report_parse_action(rg_parse_state, rg_buffered[0], data_this_cycle, data);
    let ipv4_t = extract_ipv4_t(truncate(data));
    compute_next_state_parse_ipv4(ipv4_t.fragOffset,ipv4_t.ihl,ipv4_t.protocol);
    rg_tmp <= zeroExtend(data >> 160);
    succeed_and_next(160);
    dbg3($format("extract %s %h", "parse_ipv4", rg_dequeue_data[0]));
  endrule

  (* mutually_exclusive="rl_parse_ipv4_start" *)
  rule rl_parse_ipv4_start if ((rg_parse_state == StateParseIpv4) && (w_parse_ipv4_start));
    rg_parse_state <= StateStart;
    dbg3($format("%s -> %s", "parse_ipv4", "start"));
    fetch_next_header(0);
  endrule

  interface frameIn = toPut(data_in_ff);
  interface meta = toGet(meta_in_ff);
  interface verbosity = toPut(cr_verbosity_ff);
endmodule

// ====== DEPARSER ======

typedef enum {
  StateDeparseStart,
  StateEthernet,
  StateFabricHeader,
  StateFabricHeaderMulticast,
  StateFabricHeaderUnicast,
  StateFabricHeaderCpu,
  StateFabricHeaderMirror,
  StateFabricPayloadHeader,
  StateIpv4
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
  } NopReqT;
} BBRequest deriving (Bits, Eq);
typedef union tagged {
  struct {
    PacketInstance pkt;
  } NopRspT;
} BBResponse deriving (Bits, Eq);

// ====== NOP ======

interface Nop;
  interface Server#(BBRequest, BBResponse) prev_control_state;
endinterface
module mkNop  (Nop);
  RX #(BBRequest) rx_prev_control_state <- mkRX;
  TX #(BBResponse) tx_prev_control_state <- mkTX;
  let rx_info_prev_control_state = rx_prev_control_state.u;
  let tx_info_prev_control_state = tx_prev_control_state.u;
  FIFOF#(PacketInstance) curr_packet_ff <- mkFIFOF;
  rule nop_request;
    let v = rx_info_prev_control_state.first;
    rx_info_prev_control_state.deq;
    case (v) matches
      tagged NopReqT {pkt: .pkt}: begin
        curr_packet_ff.enq(pkt);
      end
    endcase
  endrule

  rule nop_response;
    let pkt <- toGet(curr_packet_ff).get;
    BBResponse rsp = tagged NopRspT {pkt: pkt};
    tx_info_prev_control_state.enq(rsp);
  endrule

  interface prev_control_state = toServer(rx_prev_control_state.e, tx_prev_control_state.e);
endmodule

// ====== DROP ======

typedef struct {
} DropReqT deriving (Bits, Eq);
typedef enum {
  DEFAULT_DROP,
  NOP
} DropActionT deriving (Bits, Eq);
typedef struct {
  DropActionT _action;
} DropRspT deriving (Bits, Eq);
import "BDPI" function ActionValue#(Bit#(1)) matchtable_read_drop(Bit#(0) msgtype);
import "BDPI" function Action matchtable_write_drop(Bit#(0) msgtype, Bit#(1) data);
instance MatchTableSim#(0, 1);
  function ActionValue#(Bit#(1)) matchtable_read(Bit#(0) key);
    actionvalue
      let v <- matchtable_read_drop(key);
      return v;
    endactionvalue
  endfunction
  function Action matchtable_write(Bit#(0) key, Bit#(1) data);
    action
      matchtable_write_drop(key, data);
    endaction
  endfunction
endinstance
interface Drop;
  interface Server #(MetadataRequest, MetadataResponse) prev_control_state_0;
  interface Client #(BBRequest, BBResponse) next_control_state_0;
endinterface
module mkDrop  (Drop);
  RX #(MetadataRequest) rx_metadata <- mkRX;
  let rx_info_metadata = rx_metadata.u;
  TX #(MetadataResponse) tx_metadata <- mkTX;
  let tx_info_metadata = tx_metadata.u;
  Vector#(1, FIFOF#(BBRequest)) bbReqFifo <- replicateM(mkFIFOF);
  Vector#(1, FIFOF#(BBResponse)) bbRspFifo <- replicateM(mkFIFOF);
  FIFOF#(PacketInstance) packet_ff <- mkFIFOF;
  Vector#(1, Bool) readyBits = map(fifoNotEmpty, bbRspFifo);
  Bool interruptStatus = False;
  Bit#(1) readyChannel = -1;
  for (Integer i=0; i>=0; i=i-1) begin
      if (readyBits[i]) begin
          interruptStatus = True;
          readyChannel = fromInteger(i);
      end
  end

  FIFOF#(MetadataT) metadata_ff <- mkFIFOF;
  rule rl_handle_action_request;
    let data = rx_info_metadata.first;
    rx_info_metadata.deq;
    let meta = data.meta;
    let pkt = data.pkt;
    packet_ff.enq(pkt);
    metadata_ff.enq(meta);
    BBRequest req = tagged NopReqT {pkt: pkt};
    bbReqFifo[0].enq(req); //FIXME: replace with RXTX.
  endrule

  rule rl_handle_action_response if (interruptStatus);
    let v <- toGet(bbRspFifo[readyChannel]).get;
    let meta <- toGet(metadata_ff).get;
    case (v) matches
      tagged NopRspT {pkt: .pkt}: begin
        MetadataResponse rsp = tagged DropNopRspT {pkt: pkt, meta: meta};
        tx_info_metadata.enq(rsp);
      end
    endcase
  endrule

  interface prev_control_state_0 = toServer(rx_metadata.e, tx_metadata.e);
  interface next_control_state_0 = toClient(bbReqFifo[0], bbRspFifo[0]);
endmodule

// ====== INGRESS ======

interface Ingress;
  interface Client#(MetadataRequest, MetadataResponse) next;
endinterface
module mkIngress #(Vector#(numClients, Client#(MetadataRequest, MetadataResponse)) mdc) (Ingress);
  FIFOF#(MetadataRequest) default_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) default_rsp_ff <- mkFIFOF;
  FIFOF#(MetadataRequest) drop_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) drop_rsp_ff <- mkFIFOF;
  FIFOF#(MetadataRequest) next_req_ff <- mkFIFOF;
  FIFOF#(MetadataResponse) next_rsp_ff <- mkFIFOF;
  Vector#(numClients, Server#(MetadataRequest, MetadataResponse)) mds = replicate(toServer(default_req_ff, default_rsp_ff));
  mkConnection(mds, mdc);
  Drop drop <- mkDrop();
  mkConnection(toClient(drop_req_ff, drop_rsp_ff), drop.prev_control_state_0);
  // Basic Blocks
  Nop nop_0 <- mkNop();
  mkChan(mkFIFOF, mkFIFOF, drop.next_control_state_0, nop_0.prev_control_state);
  rule default_next_state if (default_req_ff.notEmpty);
    default_req_ff.deq;
    let _req = default_req_ff.first;
    let meta = _req.meta;
    let pkt = _req.pkt;
    MetadataRequest req = MetadataRequest {pkt: pkt, meta: meta};
    drop_req_ff.enq(req);
  endrule

  rule drop_next_state if (drop_rsp_ff.notEmpty);
    drop_rsp_ff.deq;
    let _rsp = drop_rsp_ff.first;
    case (_rsp) matches
      tagged DropNopRspT {meta: .meta, pkt: .pkt}: begin
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
