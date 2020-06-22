# ARM Debug High Level Analyzer extension

# ETMv3 - Cortex-M, etc.
# PFTv1 - Cortex-A9, Cortex-A12 and Cortex-A15
# ETMv4 - Cortex-R7, Cortex-A53 and Cortex-A57

# See ARMv7-M Architecture Reference Manual Appendix D4 for packet encoding

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import IntEnum

class TPIU_FSM(IntEnum):
    HDR = 255 # waiting for header byte
    # ITM (instrumentation)
    ITM1 = 1
    ITM2 = 2
    ITM3 = 3
    ITM4 = 4
    # DWT (hardware)
    DWT1 = 5
    DWT2 = 6
    DWT3 = 7
    DWT4 = 8
    # EXT (extension)
    EXT = 9
    # LTS (Local TimeStamp)
    LTS = 10
    # GTS (Global TimeStamp)
    GTS1 = 11
    GTS2 = 12

# ITM/DWT decoding
class DecodeStyle(IntEnum):
    All = 0 # decode all data : ignore port# setting
    Port = 1 # decode specific port# only
    Console = 2 # decode specific port# as ASCII console
    Instrumentation = 3 # decode specific port# as eCosPro style multi-frame O/S instrumentation

# TPIU decoding
class DecodeStyleTPIU(IntEnum):
    All = 0 # decode all data : ignore stream# setting
    Stream = 1 # decode specific stream# only
    Saleae = 2 # internal decode to Saleae frames

# ITM
# Synchronisation:
ITMDWTPP_SYNC = 0x00 # Terminated by single set bit after at least 47 bits.
# Basic encoding:
# 0bXXXXXX00    protocol packets	0..6-bytes
# 0bXXXXXXSS	source packets		1-, 2- or 4-bytes

# Overflow:
ITMDWTPP_OVERFLOW = 0x70 # PROTOCOL byte with 0-bytes of payload
# TimeStamp:
#  0bCDDD0000
#  C == continuation
#  D (!= 000) == Data    0..4-bytes
#
# SWIT Software Source:
#  0bBBBBB0SS            1-, 2- or 4-bytes
#  B = 5-bit address
#  S = 2-bit payload size (with 0b00 invalid)
#
# Reserved 0bCxxx0100    0..4-bytes
#
# Priority: Highest -> Lowest
# (pri0) Synchronisation : (pri1) Overflow : (pri2) SWIT : (pri3) Timestamp

# Least-significant 2-bits decode PROTOCOL or SOURCE packets:
ITMDWTPP_TYPE_MASK = 0x3
ITMDWTPP_TYPE_PROTOCOL = 0x0
ITMDWTPP_TYPE_SOURCE1 = 0x1
ITMDWTPP_TYPE_SOURCE2 = 0x2
ITMDWTPP_TYPE_SOURCE4 = 0x3

ITMDWTPP_PROTOCOL_EXTENSION = (1 << 3) # extension
ITMDWTPP_SOURCE_SELECTION = (1 << 2) # identifies SWIT when 0
ITMDWTPP_SOURCE_SHIFT = (3)
ITMDWTPP_SOURCE_MASK = (0x1F << ITMDWTPP_SOURCE_SHIFT)

ITMDWTPP_PROTOCOL_EXT_ITM_PAGE_SHIFT = (4)
ITMDWTPP_PROTOCOL_EXT_ITM_PAGE_MASK = (0x7 << ITMDWTPP_PROTOCOL_EXT_ITM_PAGE_SHIFT)

DWT_ID_EVENT_COUNTER_WRAP = 0
DWT_ID_EXCEPTION = 1
DWT_ID_PC_SAMPLE = 2
# 3..7 reserved
# 8..23 Data tracing

#------------------------------------------------------------------------------
# Normally we would extract the format of the instrumentation records
# as embedded in the (non-loaded) ELF sections using a suitable
# tool. For example, instdump:
#
#  $ instdump fpint_thread_switch

# ASCERTAIN: Does the Saleae python world allow arbitrary command
# execution (a security risk, but we would need the feature to be able
# to use external tools)

class Instrumentation:
    def __init__(self):
        self.start_time = None
        self.end_time = 0
        self.sequence = 256
        self.lastseq = 0
        self.rec_words = 0
        self.num_words = 0
        self.dvector = []

    def packet(self, start_time, end_time, size, pdata):
        if size == 1:
            # tail
            snum = (pdata & 0xFF)
            nf = None
            if self.sequence != snum:
                data_str = 'Seq# mismatch: saw {0:02X} expected {1:02X}'.format(snum, self.sequence)
                use_start = self.start_time
                if use_start == None:
                    use_start = start_time
                nf = AnalyzerFrame('err', use_start, end_time, {'val': data_str })
            else:
                data_str = ''
                if snum != ((self.lastseq + 1) & 0xFF):
                    # CONSIDER: Reporting count of "at least # missed"
                    data_str += '[Missed packets] '
                data_str += 'Seq#{0:02X}'.format(self.sequence)
                if self.rec_words != self.num_words:
                    data_str += '[Fields saw {0:d} expected {1:d}] '.format(self.num_words, self.rec_words)
                for idx in range(self.num_words):
                    data_str += ' {0:08X}'.format(self.dvector[idx])
                nf = AnalyzerFrame('console', self.start_time, end_time, {'val': data_str })
            self.lastseq = snum
            self.sequence = 256
            return nf
        elif size == 2:
            # head
            nf = None
            if self.sequence != 256:
                # If active (non-tail) record then return "error frame" for output
                data_str = 'Partial record for seq# {0:02X}'.format(self.sequence)
                use_start = self.start_time
                if use_start == None:
                    use_start = start_time
                nf = AnalyzerFrame('err', use_start, self.end_time, {'val': data_str })
            # new record:
            self.num_words = 0
            self.sequence = (pdata & 0xFF)
            self.rec_words = ((pdata >> 8) & 0xFF)
            self.start_time = start_time
            self.end_time = end_time
            self.dvector = []
            return nf
        elif size == 4:
            # data
            self.dvector.append(pdata)
            self.num_words += 1
            self.end_time = end_time
            return None
        else:
            # Unexpected size : return error frame
            data_str = 'Unexpected field size {0:d}'.format(size)
            self.sequence = 256
            use_start = self.start_time
            if use_start == None:
                use_start = start_time
            return AnalyzerFrame('err', use_start, end_time, {'val': data_str })

#------------------------------------------------------------------------------

class ConsoleCtx:
    def __init__(self, start_time):
        self.start_time = start_time
        self.ctext = ''

    def cdata(self, frame, cc):
        nf = None

        if cc == 0x0A or cc == 0x00:
            nf = AnalyzerFrame('console', self.start_time, frame.end_time, {'val': self.ctext })
            self.ctext = ''
        else:
            if self.ctext == '':
                self.start_time = frame.start_time
            newchr = chr(cc)
            if str(newchr).isprintable():
                self.ctext += newchr

        return nf

#------------------------------------------------------------------------------

class PktCtx:
    def __init__(self, start_time, dstyle, portaddr):
        self.start_time = start_time
        self.end_time = 0
        self.portaddr = portaddr
        self.fsm = TPIU_FSM.HDR
        self.ipage = 0
        self.size = 0
        self.pcode = 0
        self.pdata = 0
        self.dstyle = dstyle
        self.instrumentation = None
        self.conctx = None

    def itm_process_data(self, frame):
        #if self.pcode is not 24:
        #    return

        data_str = ''

        do_tag = 'itm'
        do_raw = True

        # Cope with stimulas port page extension:
        paddr = (self.ipage * 32) + self.pcode

        if self.dstyle is DecodeStyle.Port:
            if paddr != self.portaddr:
                return None

        if self.dstyle is DecodeStyle.Console:
            if paddr != self.portaddr:
                return None
            else:
                # We group all characters between newlines into single reported
                # frames to make it easier for the user to track whole
                # messages that have been split across multiple TPIU packets.
                if self.conctx is None:
                    self.conctx = ConsoleCtx(frame.start_time)
                nframes = []
                for idx in range(self.size):
                    nf = self.conctx.cdata(frame, ((self.pdata >> (idx * 8)) & 0xFF))
                    if nf != None:
                        nframes.append(nf)
                return nframes
                # ALTERNATIVE: code if we want individual characters reported:
                # for idx in range(self.size):
                #    data_str += '{0:c}'.format((self.pdata >> (idx * 8)) & 0xFF)
                # do_raw = False

        if self.dstyle is DecodeStyle.Instrumentation:
            if paddr != self.portaddr:
                return None
            else:
                if self.instrumentation == None:
                    self.instrumentation = Instrumentation()
                return self.instrumentation.packet(self.start_time, frame.end_time, self.size, self.pdata)

        self.end_time = frame.end_time

        # Extra DBG
        #data_str += '(DBG: dstyle {0:d} portaddr {1:d}) '.format(self.dstyle, int(self.portaddr))

        if do_raw:
            data_str += "Port#{0:d} Size#{1:d}".format(paddr,self.size)
            data_str += ' '
            if self.size == 1:
                data_str += "Data#{0:02X}".format(self.pdata & 0xFF)
            elif self.size == 2:
                data_str += "Data#{0:04X}".format(self.pdata & 0xFFFF)
            else:
                data_str += "Data#{0:08X}".format(self.pdata & 0xFFFFFFFF)
        return AnalyzerFrame(do_tag, self.start_time, self.end_time, {'val': data_str })

    def dwt_process_data(self, frame):
        self.end_time = frame.end_time
        if self.dstyle == DecodeStyle.Console:
            return None
        data_str = ''
        if self.pcode == DWT_ID_PC_SAMPLE:
            # The POSTCNT counter period determines the PC sampling interval
            #
            # 1-byte for WFI/WFE (CPU asleep) or 4-byte for PC sample:
            if self.size == 1:
                if self.pdata == 0:
                    # ARMv7-M D4.3.3 Full periodic PC sample packet
                    data_str += ' IDLE:SLEEP'
                else:
                    # Reserved
                    data_str += ' IDLE:{0:02X}'.format(self.pdata & 0xFF)
            elif self.size == 4:
                data_str += ' PC:{0:08X}'.format(self.pdata)
            else:
                data_str += ' PC:Unrecognised'
        elif self.pcode == DWT_ID_EXCEPTION:
            # 2-byte exception number and event descriptor:
            # byte0: ExceptionNumber[7..0]
            # byte1: ExceptionNumber[8] and FN[1..0]
            #
            # FN:
            #  0 reserved
            #  1 entered exception indicated by ExceptionNumber
            #  2 exited exception indicated by ExceptionNumber
            #  3 returned to exception indicated by ExceptionNumber
            exception_number = (self.pdata & 0x1FF)
            fn = ((self.pdata >> 12) & 0x3)
            fn_reason = 'RESERVED'
            if fn == 1:
                fn_reason = 'ENTERED'
            elif fn == 2:
                fn_reason = 'EXITED'
            elif fn == 3:
                fn_reason = 'RESUMED'
            data_str += ' EXC {0:d} {1:s}'.format(exception_number, fn_reason)
        elif self.pcode == DWT_ID_EVENT_COUNTER_WRAP:
            # 1-byte with bitmask of counter overflow marker bits
            #  b7      b6      b5      b4      b3      b2      b1     b0
            # |   0   |   0   |  Cyc  | Fold  |  LSU  | Sleep |  Exc |  CPI  |
            #
            # b5 Cyc    POSTCNT  timer
            # b4 Fold   FOLDCNT  profiling counter
            # b3 LSU    LSUCNT   profiling counter
            # b2 Sleep  SLEEPCNT profiling counter
            # b1 Exc    EXCCNT   profiling counter
            # b0 CPI    CPICNT   profiling counter
            data_str += ' WRAP {0:02X}'.format(self.pdata & 0xFF)
        else:
            if self.pcode < 8:
                data_str += ' RESERVED'
            else:
                # Data trace packets 8..23:
                # |b7 b6 |b5 b4 |b3       |b2 |b1 b0 |
                # | Type | CMPN | TypeDir | 1 | Size |
                #
                # Type:
                #   00 reserved
                #   01 PC value (b3==0) or address (b3==1)
                #   10 data value read (b3==0) or write (b3==1)
                #   11 reserved
                #
                # CMPN: comparator number
                #
                # PC value packet: 4-bytes
                # Address packet: 2-bytes
                # Data value packet read: 1-, 2- or 4-bytes
                # Data value packet write: 1-, 2- or 4-bytes
                data_str += ' DATA-TRACE:IGNORED'

        return AnalyzerFrame('dwt', self.start_time, self.end_time, {'val': data_str })

    def ext_process_data(self, frame):
        self.end_time = frame.end_time
        data_str = ' {0:08X}'.format(self.pdata)
        return AnalyzerFrame('ext', self.start_time, self.end_time, {'val': data_str })

    def local_timestamp(self, frame):
        self.end_time = frame.end_time
        data_str = 'Local TS {0:d}'.format(self.pdata)
        if self.pcode == 0:
            data_str += ' synchronous'
        elif self.pcode == 1:
            data_str += ' delayed'
        elif self.pcode == 2:
            data_str += ' delayed-generated'
        elif self.pcode == 3:
            data_str += ' delayed-relative'
        else:
            data_str += ' UNKNOWN'
        return AnalyzerFrame('console', self.start_time, self.end_time, {'val': data_str })

    def global_timestamp1(self, frame):
        self.end_time = frame.end_time
        data_str = 'Global TS {0:d}'.format(self.pdata)
        if (self.pcode & (1 << 5)):
            data_str += ' ClkChk'
        if (self.pcode & (1 << 6)):
            data_str += ' Wrap'
        return AnalyzerFrame('console', self.start_time, self.end_time, {'val': data_str })

    def global_timestamp2(self, frame):
        self.end_time = frame.end_time
        data_str = 'Global TS Hi-order {0:d}'.format(self.pdata)
        return AnalyzerFrame('console', self.start_time, self.end_time, {'val': data_str })

    def hdr(self, frame, db):
        decoded = None

        if (db == ITMDWTPP_SYNC):
            # ignore and stay at HDR
            self.start_time = None
            self.ipage = 0
        elif (db == ITMDWTPP_OVERFLOW):
            # ignore and stay at HDR
            # CONSIDER: output saleae frame showing 1-byte OVERFLOW
            self.start_time = None
        else:
            source = (db & ITMDWTPP_TYPE_MASK)
            size = 0

            if source == ITMDWTPP_TYPE_PROTOCOL:
                if db & ITMDWTPP_PROTOCOL_EXTENSION:
                    # EX[2:0] in bits 4..6 with C in bit 7
                    # remaining bits 3..31 in option successive bytes
                    # According to ARMv7-M D4.2.6 the extension information
                    # *only* to provide additional information for decoding
                    # instrumentation packets.
                    if (db & (1 << 7)):
                        # (C)ontinuation
                        self.fsm = TPIU_FSM.EXT
                        self.pdata = ((db >> 4) & 0x7)
                        # We track byte number in self.size
                    else:
                        # Single byte: check SH:
                        if (db & ITMDWTPP_SOURCE_SELECTION):
                            # Undefined, so ignore:
                            self.pdata = 0
                        else:
                            # Stimulus port page number for
                            # subsequent instrumentation packets:
                            self.ipage = ((db & ITMDWTPP_PROTOCOL_EXT_ITM_PAGE_MASK) >> ITMDWTPP_PROTOCOL_EXT_ITM_PAGE_SHIFT)
                            # The page is cleared back to 0 by a synchronisation packet
                        # Stay at HDR
                else:
                    if db & ITMDWTPP_SOURCE_SELECTION:
                        self.pdata = 0
                        self.pcode = 0
                        if (db == 0x94):
                            # GTS1 header is 0x94
                            self.fsm = TPIU_FSM.GTS1
                        elif (db == 0xB4):
                            # GTS2 header is 0xB4
                            self.fsm = TPIU_FSM.GTS2
                        else:
                            data_str = 'Global TimeStamp Decode {0:02X}'.format(db)
                            use_start = self.start_time
                            if use_start == None:
                                use_start = frame.start_time
                            decoded = AnalyzerFrame('err', use_start, frame.end_time, {'val': data_str })
                    else:
                        # TimeStamp 1..5-bytes
                        # 0bCDDD000
                        # DDD != 000 (encodes sync when C=0)
                        # DDD != 111 (encodes overflow when C=0)
                        # Those special cases are caught explicitly above:

                        if (db & (1 << 7)):
                            # (C)ontinuation : marks 2-..5-bytes timestamp
                            #
                            #       | b7   | b6   | b5   | b4   | b3   | b2   | b1   | b0   |
                            # byte0 |  C   | TC2  | TC1  | TC0  |  0   |  0   |  0   |  0   |
                            # byte1 |  C   | TS6  | TS5  | TS4  | TS3  | TS2  | TS1  | TS0  |
                            # byte2 |  C   | TS13 | TS12 | TS11 | TS10 | TS9  | TS8  | TS7  |
                            # byte3 |  C   | TS20 | TS19 | TS18 | TS17 | TS16 | TS15 | TS14 |
                            # byte4 |  0   | TS27 | TS26 | TS25 | TS24 | TS23 | TS22 | TS21 |
                            #
                            # TC encoding depends on number of bytes of timestamp output
                            # 1-byte (byte0 C==0) : TC==0 Reserved : TC==7 Overflow ITM : else TimeStamp emitted synchronous to ITM data
                            # 2- or more bytes : TC==0..3 Reserved : TC==4 Timestamp synchronous to ITM data : TC==5 Timestamp delayed to ITM : TC==6 Packet delayed : TC==7 Packet and timestamp delayed
                            self.fsm = TPIU_FSM.LTS
                            self.pcode = ((db >> 4) & 0x7) # Timestamp Control
                            self.pdata = 0
                        else:
                            # Single byte local timestamp
                            self.pcode = 0 # timestamp emitted synchronous to ITM data
                            self.pdata = ((db >> 4) & 0x7) # will be TimeStamp value of 1..6
                            decoded = self.local_timestamp(frame)
                            # Stay at HDR
            else: # SWIT : Software Source
                if source == ITMDWTPP_TYPE_SOURCE1:
                    size = 1
                elif source == ITMDWTPP_TYPE_SOURCE2:
                    size = 2
                elif source == ITMDWTPP_TYPE_SOURCE4:
                    size = 4

                if (db & ITMDWTPP_SOURCE_SELECTION):
                    id = ((db & ITMDWTPP_SOURCE_MASK) >> ITMDWTPP_SOURCE_SHIFT)
                    # ARMv7-M D4.2.7 bit2 indicate instrumentation
                    # (0==ITM) or hardware (1==DWT)

                    # Actually the top-bit of the id is the
                    # (C)ontinuation flag, and the bottom (least
                    # significant) bit should always be zero. Of
                    # the 5-bits of id only 3 encode the feature.
                    self.fsm = TPIU_FSM.DWT1
                    self.pcode = id
                    self.pdata = 0
                else:
                    port = ((db & ITMDWTPP_SOURCE_MASK) >> ITMDWTPP_SOURCE_SHIFT)
                    self.fsm = TPIU_FSM.ITM1
                    self.pcode = port;
                    self.pdata = 0;
                self.start_time = frame.start_time
            self.size = size
        return decoded

    def itm1(self, frame, db):
        decoded = None
        self.pdata = db
        if self.size == 1:
            decoded = self.itm_process_data(frame)
            self.fsm = TPIU_FSM.HDR
        else:
            self.fsm = TPIU_FSM.ITM2
        return decoded

    def itm2(self, frame, db):
        decoded = None
        self.pdata |= (db << 8)
        if self.size == 2:
            decoded = self.itm_process_data(frame)
            self.fsm = TPIU_FSM.HDR
        else:
            self.fsm = TPIU_FSM.ITM3
        return decoded

    def itm3(self, frame, db):
        decoded = None
        self.pdata |= (db << 16)
        if self.size == 3:
            decoded = self.itm_process_data(frame)
            self.fsm = TPIU_FSM.HDR
        else:
            self.fsm = TPIU_FSM.ITM4
        return decoded

    def itm4(self, frame, db):
        decoded = None
        self.pdata |= (db << 24)
        if self.size == 4:
            decoded = self.itm_process_data(frame)
        self.fsm = TPIU_FSM.HDR
        return decoded

    def dwt1(self, frame, db):
        decoded = None
        self.pdata = db
        if self.size == 1:
            decoded = self.dwt_process_data(frame)
            self.fsm = TPIU_FSM.HDR
        else:
            self.fsm = TPIU_FSM.DWT2
        return decoded

    def dwt2(self, frame, db):
        decoded = None
        self.pdata |= (db << 8)
        if self.size == 2:
            decoded = self.dwt_process_data(frame)
            self.fsm = TPIU_FSM.HDR
        else:
            self.fsm = TPIU_FSM.DWT3
        return decoded

    def dwt3(self, frame, db):
        decoded = None
        self.pdata |= (db << 16)
        if self.size == 3:
            decoded = self.dwt_process_data(frame)
            self.fsm = TPIU_FSM.HDR
        else:
            self.fsm = TPIU_FSM.DWT4
        return decoded

    def dwt4(self, frame, db):
        decoded = None
        self.pdata |= (db << 24)
        if self.size == 4:
            decoded = self.dwt_process_data(frame)
        self.fsm = TPIU_FSM.HDR
        return decoded

    def ext(self, frame, db):
        decoded = None
        continuation = False
        if self.size == 0:
            self.pdata |= ((db & 0x7F) << 3)
            continuation = (db & (1 << 7))
        elif self.size == 1:
            self.pdata |= ((db & 0x7F) << 10)
            continuation = (db & (1 << 7))
        elif self.size == 2:
            self.pdata |= ((db & 0x7F) << 17)
            continuation = (db & (1 << 7))
        else: # size == 3
            self.pdata |= (db << 24)
            continuation = False

        if continuation:
            self.size += 1
        else:
            decoded = self.ext_process_data(frame)
            self.fsm = TPIU_FSM.HDR

        return decoded

    def lts(self, frame, db):
        decoded = None
        self.pdata |= ((db & 0x7F) << (self.size * 7))
        if (db & (1 << 7)):
            self.size += 1
            if (self.size == 4):
                data_str = 'Local TimeStamp Continuation'
                decoded = AnalyzerFrame('err', self.start_time, frame.end_time, {'val': data_str })
                self.fsm = TPIU_FSM.HDR
        else:
            decoded = self.local_timestamp(frame)
            self.fsm = TPIU_FSM.HDR

        return decoded

    def gts1(self, frame, db):
        decoded = None

        if (self.size != 3):
            self.pdata |= ((db & 0x7F) << (self.size * 7))
        else: # bits 21..25
            self.pdata |= ((db & 0x1F) << (self.size * 7))
            self.pcode = (db & 0x60) # Wrap and ClkCh flags
        if (db & (1 << 7)):
            self.size += 1
            if (self.size == 4):
                data_str = 'Global TimeStamp1 Continuation'
                decoded = AnalyzerFrame('err', self.start_time, frame.end_time, {'val': data_str })
                self.fsm = TPIU_FSM.HDR
        else:
            decoded = self.global_timestamp1(frame)
            self.fsm = TPIU_FSM.HDR

        return decoded

    def gts2(self, frame, db):
        # Hi-order bits for most recently transmitted GTS1 packet
        decoded = None
        self.pdata |= ((db & 0x7F) << (self.size * 7))
        if (db & (1 << 7)):
            self.size += 1
            # may be 5-byte (bits 26..47) or 7-byte (bits 26..63) packet
            if (self.size == 6):
                data_str = 'Global TimeStamp2 Continuation'
                decoded = AnalyzerFrame('err', self.start_time, frame.end_time, {'val': data_str })
                self.fsm = TPIU_FSM.HDR
        else:
            decoded = self.global_timestamp2(frame)
            self.fsm = TPIU_FSM.HDR

        return decoded

    def run(self, frame):
        switcher = {
            TPIU_FSM.HDR: self.hdr,
            TPIU_FSM.ITM1: self.itm1,
            TPIU_FSM.ITM2: self.itm2,
            TPIU_FSM.ITM3: self.itm3,
            TPIU_FSM.ITM4: self.itm4,
            TPIU_FSM.DWT1: self.dwt1,
            TPIU_FSM.DWT2: self.dwt2,
            TPIU_FSM.DWT3: self.dwt3,
            TPIU_FSM.DWT4: self.dwt4,
            TPIU_FSM.EXT: self.ext,
            TPIU_FSM.LTS: self.lts,
            TPIU_FSM.GTS1: self.gts1,
            TPIU_FSM.GTS2: self.gts2
        }
        func = switcher.get(self.fsm)
        return func(frame, frame.data['data'][0])

#------------------------------------------------------------------------------
# ARM TPIU exports 16-byte frames:
# See ARM DDI 0314H section 8.12
# - even bytes contain stream id if bit0 set; otherwise data
# - odd bytes are always data
# - byte15 is the LSB of the even bytes
#
# See ARM DDI 0314H 8.12.1
#  When a trace source is changed the appropriate flag bit, F, is set
#  (1 = ID, 0 - Data on the following byte). The second byte is always
#  data and the corresponding bit at the end of the sequence (bits
#  A-J) indicates if this second byte correspondds to the new ID (F
#  bit clear) or the previous ID (F bit set).

# ISSUE:INVESTIGATE: The SWO captured TPIU stream from a
# STM32F429I-DISCO board sometimes seems to start half-way through a
# 16-byte packet. Have seen offsets of 4-, 8- and 12-bytes into the
# TPIU packet.

class TPIUCtx:
    def __init__(self, tpdstyle, stream_match, offset):
        self.start_time = None
        self.dstyle = tpdstyle
        self.stream_match = stream_match
        self.stream_active = 0
        self.bidx = int(offset)
        self.packet = []
        # Create dummy bytes for missing data:
        if self.bidx:
            for idx in range(self.bidx):
                self.packet.append( (0x00, None, None) )

    def dump_stream(self, start_time, end_time, streamid, databytes):
        if self.dstyle is DecodeStyleTPIU.Stream:
            if streamid != self.stream_match:
                return None

        if len(databytes) != 0:
            if self.dstyle is DecodeStyleTPIU.Saleae:
                if streamid != self.stream_match:
                    return None
                # We return Analyzer frames for each byte to be decoded by our higher layer:
                frames = []
                for idx in range(len(databytes)):
                    raw_byte = databytes[idx][0]
                    byte_start = databytes[idx][1]
                    byte_end = databytes[idx][2]
                    if (byte_start != None) and (byte_end != None):
                        nf = AnalyzerFrame('data', byte_start, byte_end, { 'data': bytes( [raw_byte] ) } )
                        frames.append(nf)
                return frames

            data_str = 'Stream{0:d}:'.format(streamid)
            for idx in range(len(databytes)):
                raw_byte = databytes[idx][0]
                byte_start = databytes[idx][1]
                byte_end = databytes[idx][2]
                if (byte_start != None) and (byte_end != None):
                    data_str += ' {0:02X}'.format(raw_byte)
            return AnalyzerFrame('tpiu', start_time, end_time, {'val': data_str })

        return None

    def process_byte(self, frame, db):
        frames = []

        if self.bidx == 0:
            self.start_time = frame.start_time
            self.packet.clear()

        # We need to record the start_time for each data byte supplied
        # so that we can resync into packets by the higher level
        # decoder:
        self.packet.append( (db, frame.start_time, frame.end_time) )

        self.bidx += 1
        if self.bidx == 16:
            # Process data bytes:
            databytes = []
            lsbits = self.packet[15][0]

            stream_start_time = self.start_time
            pending_nextstream = None
            do_sync = False

            # Prepare for next packet:
            self.bidx = 0

            for idx in range(15):
                pb = self.packet[idx][0]
                bstart = self.packet[idx][1]
                bend = self.packet[idx][2]
                if idx & 1:
                    if do_sync:
                        if pb == 0x7F:
                            do_sync = False
                            # Currently assumes we are always at the start of a TPIU packet:
                            synclen = (idx + 1)
                            sync_end_time = self.packet[idx][2]
                            if sync_end_time == None:
                                sync_end_time = frame.end_time
                            for si in range(synclen):
                                del self.packet[0]
                            self.bidx = (16 - synclen)
                            self.start_time = self.packet[0][1]
                            data_str = 'BAD '
                            if synclen == 2:
                                data_str = 'Short '
                            elif synclen == 4:
                                data_str = ''
                            data_str += 'Sync'
                            nf = AnalyzerFrame('tpiu', stream_start_time, sync_end_time, {'val': data_str })
                            frames.append(nf)
                            break
                        elif pb != 0xFF:
                            data_str = "Expected FF"
                            nf = AnalyzerFrame('err', stream_start_time, frame.end_time, {'val': data_str })
                            frames.append(nf)
                    else:
                        databytes.append( (pb, bstart, bend) )
                        if pending_nextstream != None:
                            nf = self.dump_stream(stream_start_time, frame.end_time, self.stream_active, databytes)
                            if nf != None:
                                if isinstance(nf, list):
                                    frames += nf
                                else:
                                    frames.append(nf)
                            self.stream_active = pending_nextstream
                            pending_nextstream = None
                            databytes.clear()
                else:
                    #even
                    if pb & 1:
                        # ARM DDI 0314H 8.12.1
                        # The byte15 flag byte indicates whether the next odd
                        # byte is for the previous stream or the new stream
                        #
                        # ARM IHI 0029E D4.2.6
                        # We should expect to see the active stream ID repeated
                        # (~10-frames) if we have continuous data from a single
                        # stream source.
                        #
                        # ARM IHI 0029E D4.2.2/D4.2.3
                        # Synchronisation packets are described as being output
                        # periodically *between* frames
                        #
                        if pb == 0xFF:
                            do_sync = True
                        else:
                            nextstream = (pb >> 1)
                            if nextstream != self.stream_active:
                                stream_start_time = self.packet[idx][1]
                                if ((lsbits >> (idx >> 1)) & 1):
                                    # Next byte for previous stream:
                                    pending_nextstream = nextstream
                                else:
                                    # Common with above:
                                    nf = self.dump_stream(stream_start_time, frame.end_time, self.stream_active, databytes)
                                    if nf != None:
                                        if isinstance(nf, list):
                                            frames += nf
                                        else:
                                            frames.append(nf)
                                    self.stream_active = nextstream
                    else:
                        if do_sync:
                            data_str = "Expected LongSync FF"
                            nf = AnalyzerFrame('err', stream_start_time, frame.end_time, {'val': data_str })
                            frames.append(nf)
                        else:
                            fb = (pb | ((lsbits >> (idx >> 1)) & 1))
                            databytes.append( (fb, bstart, bend) )

            if len(databytes):
                nf = self.dump_stream(stream_start_time, frame.end_time, self.stream_active, databytes)
                if nf != None:
                    if isinstance(nf, list):
                        frames += nf
                    else:
                        frames.append(nf)

        return frames

#------------------------------------------------------------------------------
# TPIU packet decoding

class TPIU(HighLevelAnalyzer):
    # Consider options for:
    # - all streams
    # - specific stream
    # - allow ETM decoding

    # Decode style:
    tpiu_decode_style = ChoicesSetting(choices=('All', 'Stream'))

    # Stream ID:
    stream = NumberSetting(min_value=1, max_value=126)
    # Stream  0x00       : idle : ignored
    # Streams 0x01..0x6F : normal debug streams
    # Streams 0x70..0x7A : reserved
    # stream  0x7B       : flush response
    # stream  0x7C       : reserved
    # Stream  0x7D       : trigger event
    # Stream  0x7E       : reserved
    # Stream  0x7F       : reserved : never used since affects sync detection

    # Initial synchronisation:
    offset = NumberSetting(min_value=0, max_value=15)
    # Sometimes the capture may miss bytes of the first 16-byte aligned TPIU
    # packet. This allows the decoder to be synchronised on the partial packet.

    result_types = {
        'tpiu': {
            'format': 'TPIU: {{data.val}}'
        }
    }

    def __init__(self):
        self.ctx = None
        pass

    def decode(self, frame: AnalyzerFrame):
        # frame.type should always be 'data'
        # frame.data['data'] will be a bytes object
        # frame.data['error'] will be set if there was an error

        # IMPLEMENT: Check for frame.data['error'] string and skip
        # decoding if invalid source data

        # For AsyncSerial we expect the 'data' field to contain one byte

        if self.ctx == None:
            tpdstyle = DecodeStyleTPIU.All # default
            if self.tpiu_decode_style == 'Stream':
                tpdstyle = DecodeStyleTPIU.Stream
            self.ctx = TPIUCtx(tpdstyle, self.stream, self.offset)

        # Process bytes:
        nf = self.ctx.process_byte(frame, frame.data['data'][0])
        if nf is None:
            return

        return nf

#------------------------------------------------------------------------------
# ITM and DWT packet protocol  decoding

class ITMDWT(HighLevelAnalyzer):
    # Decode style:
    decode_style = ChoicesSetting(choices=('All', 'Port', 'Console', 'Instrumentation'))

    # We can have 8 pages of 32-ports in each page
    port = NumberSetting(min_value=0, max_value=255)

    # We may need to de-reference a TPIO stream:
    TPIU_stream = NumberSetting(min_value=0, max_value=127)
    # NOTE: 0 indicates NO TPIU encoding (BYPASS mode)

    # Initial synchronisation:
    TPIU_offset = NumberSetting(min_value=0, max_value=15)

    result_types = {
        'console': {
            'format': '{{data.val}}'
        },
        'err': {
            'format': 'Error: {{data.val}}'
        },
        'itm': {
            'format': 'ITM: {{data.val}}'
        },
        'dwt': {
            'format': 'DWT: {{data.val}}'
        },
        'ext': {
            'format': 'EXT: {{data.val}}'
        }
    }

    def __init__(self):
        self.ctx = None
        self.tpiu = None
        pass

    def decode(self, frame: AnalyzerFrame):
        # frame.type should always be 'data'
        # frame.data['data'] will be a bytes object
        # frame.data['error'] will be set if there was an error

        # IMPLEMENT: Check for frame.data['error'] string and skip
        # decoding if invalid source data

        # For AsyncSerial we expect the 'data' field to contain one byte

        if self.ctx == None:
            dstyle = DecodeStyle.All # default
            if self.decode_style == 'Port':
                dstyle = DecodeStyle.Port
            elif self.decode_style == 'Console':
                dstyle = DecodeStyle.Console
            elif self.decode_style == 'Instrumentation':
                dstyle = DecodeStyle.Instrumentation
            self.ctx = PktCtx(frame.start_time, dstyle, self.port)

        # Progress FSM:
        nf = None

        # We may need to unwrap from a TPIU stream encoding:
        if self.TPIU_stream != 0:
            if self.tpiu == None:
                self.tpiu = TPIUCtx(DecodeStyleTPIU.Saleae, self.TPIU_stream, self.TPIU_offset)
            tframes = self.tpiu.process_byte(frame, frame.data['data'][0])
            if tframes is None:
                nf = None
            else:
                if isinstance(tframes, list):
                    nf = []
                    for idx in range(len(tframes)):
                        iframe = self.ctx.run(tframes[idx])
                        if iframe != None:
                            if isinstance(iframe, list):
                                nf += iframe
                            else:
                                nf.append(iframe)
                            #nf.append(iframe)
                else:
                    nf = None
        else:
            nf = self.ctx.run(frame)

        if nf is None:
            #if self.no_match_start_time is None:
            #    self.no_match_start_time = frame.start_time
            #self.no_match_end_time = frame.end_time
            return

        return nf

#------------------------------------------------------------------------------
#> EOF debug.py
