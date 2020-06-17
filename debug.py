# ARM Debug High Level Analyzer extension

# Since the Saleae extension API does not allow nested extensions; we
# abstract the lower-layers inside this source file so that we can
# provide the higher level decodings:

#                      +--- port0
#                      |
#          +--- ITM ---+--- portN
#          |           |
#          |           +--- portX --  Instrumentation -- O/S specific decoding
#          |
#  TPIU ---+
#          |
#          +--- ETM

# The ITM port is just be a setting: [All|0|1|...|x]

# So we provide a single extension with a setting that decides how the
# debug data is decoded. We then allow the user to have multiple ins
# instances of the extension if they want to show the different
# embedded data fields.

# ETMv3 - Cortex-M, etc.
# PFTv1 - Cortex-A9, Cortex-A12 and Cortex-A15
# ETMv4 - Cortex-R7, Cortex-A53 and Cortex-A57

# See ARMv7-M Architecture Reference Manual Appendix D4 for packet encoding

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import IntEnum

class TPIU_FSM(IntEnum):
    HDR = 9 # waiting for header byte
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

class DecodeStyle(IntEnum):
    All = 0 # decode all data : ignore port# setting
    Port = 1 # decode specific port# only
    Console = 2 # decode specific port# as ASCII console
    Instrumentation = 3 # decode specific port# as eCosPro style multi-frame O/S instrumentation

# NOTE: eCosPro instrumentation (default traceport 24, but can be arbitrary port#)
# Consists of:
#  2-byte header : 0xNNSS : NN=number of fields : SS=sequence#
#    NN * 4-byte : instrumentation record (structure) fields
#    1-byte tail : 0xSS : SS=sequence#
#
# An encoded 5 word instrumentation record takes ~150us to be transferred over
# an 8N1 2MHz UART (SWO) connection.

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

DWT_ID_EVENT_COUNTER_WRAP = (0)
DWT_ID_EXCEPTION = (1)
DWT_ID_PC_SAMPLE = (2)
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
        self.start_time = 0
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
                nf = AnalyzerFrame('err', self.start_time, end_time, {'val': data_str })
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
                nf = AnalyzerFrame('err', self.start_time, self.end_time, {'val': data_str })
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
            return AnalyzerFrame('err', self.start_time, end_time, {'val': data_str })

#------------------------------------------------------------------------------

class PktCtx:
    def __init__(self, start_time, dstyle, portaddr):
        self.start_time = start_time
        self.end_time = None
        self.portaddr = portaddr
        self.fsm = TPIU_FSM.HDR
        self.ipage = 0
        self.size = 0
        self.pcode = 0
        self.pdata = 0
        self.dstyle = dstyle
        self.instrumentation = None

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
                do_tag = 'console'
                # CONSIDER: Like the "Text Messages" HLA-extension we should
                # group all characters between newlines into single reported
                # frames to make it easier for the user to track whole
                # messages that have been split across multiple TPIU packets.
                for idx in range(self.size):
                    data_str += '{0:c}'.format((self.pdata >> (idx * 8)) & 0xFF)
                do_raw = False

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
                data.str += ' PC={0:08X}'.format(self.pdata)
            else:
                data_str += ' PC=Unrecognised'
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
            data.str += ' EXC={0:d) {1:s}'.format(exception_number, fn_reason)
        elif self.pcde == DWT_ID_EVENT_COUNTER_WRAP:
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
            data.str += ' WRAP={0:02X}'.format(self.pdata & 0xFF)
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

    def hdr(self, frame, db):
        if (db == ITMDWTPP_SYNC):
            # ignore and stay at HDR
            self.start_time = None
            self.ipage = 0
        elif (db == ITMDWTPP_OVERFLOW):
            # ignore and stay at HDR
            self.start_time = None
        else:
            source = (db & ITMDWTPP_TYPE_MASK)
            size = 0

            if source == ITMDWTPP_TYPE_PROTOCOL:
                # TODO: We need to skip continuation bytes until C==0 when parsing
                if db & ITMDWTPP_PROTOCOL_EXTENSION:
                    # EX[2:0] in bits 4..6 with C in bit 7
                    # remaining bits 3..31 in option successive bytes
                    # According to ARMv7-M D4.2.6 the extension information
                    # *only* to provide additional information for decoding
                    # instrumentation packets.
                    if (db & ITMDWTPP_SOURCE_SELECTION):
                        dwt_extension = db
                    else:
                        # Single byte SH==0 used to provide page for
                        # subsequent instrumentation packets:
                        self.ipage = ((db & ITMDWTPP_PROTOCOL_EXT_ITM_PAGE_MASK) >> ITMDWTPP_PROTOCOL_EXT_ITM_PAGE_SHIFT)
                        # The page is cleared back to 0 by a synchronisation packet
                else:
                    if db & ITMDWTPP_SOURCE_SELECTION:
                        if (db & 0x94) == 0x94:
                            # 0b10T10100
                            # T = Global timestamp packet type


                            global_timestamp = db
                        else:
                            reserved = db
                    else:
                        # 0bCDDD000
                        # DDD != 000 (encodes sync when C=0)
                        # DDD != 111 (encodes overflow when C=0)
                        local_timestamp = db
                        # TimeStamp 1..5-bytes
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

                self.pcode = 0 # just a holder to keep Python happy
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
        return None

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
            self.fsm = TPIU_FSM.DWT
        return decoded

    def dwt4(self, frame, db):
        decoded = None
        self.pdata |= (db << 24)
        if self.size == 4:
            decoded = self.dwt_process_data(frame)
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
            TPIU_FSM.DWT4: self.dwt4
        }
        func = switcher.get(self.fsm)
        return func(frame, frame.data['data'][0])

#------------------------------------------------------------------------------
# TPIU packet decoding

class TPIU(HighLevelAnalyzer):
    #some_string = StringSetting()
    decode_style = ChoicesSetting(choices=('All', 'Port', 'Console', 'Instrumentation'))
    # We can have 8 pages of 32-ports in each page
    port = NumberSetting(min_value=0, max_value=255)

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
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        self.no_match_start_time = None
        self.no_match_end_time = None
        self.ctx = None
        pass

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

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
        nf = self.ctx.run(frame)
        if nf is None:
            #if self.no_match_start_time is None:
            #    self.no_match_start_time = frame.start_time
            #self.no_match_end_time = frame.end_time
            return

        return nf

#------------------------------------------------------------------------------
#> EOF debug.py
