# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting
from saleae.data import GraphTimeDelta


DSM2_22MS_1024 = "DSM2 22MS 1024"
DSM2_11MS_2048 = "DSM2 11MS 2048"
DSMX_22MS_2048 = "DSMX 22MS 2048"
DSMX_11MS_2048 = "DSMX 11MS 2048"

SYSTEM_TO_PROTOCOL = {
    b'\x01' : DSM2_22MS_1024,
    b'\x12' : DSM2_11MS_2048,
    b'\xa2' : DSMX_22MS_2048,
    b'\xb2' : DSMX_11MS_2048,
}

CHANNEL_NAMES = [
    "Throttle",
    "Aileron",
    "Elevator",
    "Rudder",
    "Gear",
    "Aux 1",
    "Aux 2",
    "Aux 3",
    "Aux 4",
    "Aux 5",
    "Aux 6",
    "Aux 7",
]

MAX_FRAME_TIME_DELTA = GraphTimeDelta(second=0, millisecond=2)

class SpektrumPacketAnalyzer(HighLevelAnalyzer):

    receiver_type_setting = ChoicesSetting(choices=("INTERNAL", "EXTERNAL"))
    protocol_setting = ChoicesSetting(choices=(DSM2_22MS_1024, DSM2_11MS_2048, DSMX_22MS_2048, DSMX_11MS_2048))

    last_end_time = None

    frame_buf = []

    result_types = {
        'fades': {
            'format': 'fades={{data.fades}}'
        },
        'system': {
            'format': 'proto={{data.proto}}, match={{data.match}}'
        },
        'channel_1024': {
            'format': '{{data.chan_name}} ({{data.chan_id}}), pos={{data.pos}}'
        },
        'channel_2048': {
            'format': '{{data.chan_name}} ({{data.chan_id}}), pos={{data.pos}}, pha={{data.pha}}'
        },
        'err': {
            'format': "ERROR"
        }
    }

    def __init__(self):
        print("Settings:", self.receiver_type_setting, self.protocol_setting)

    def decode(self, frame: AnalyzerFrame):
      
        # for every frame we analyze, we check if the time difference between
        # the current and the last is greater than MAX_FRAME_TIME_DELTA, if so
        # it means we started analyzing in the middle of a spektrum 
        # packet transmission and are already analyzing the contents of the
        # next packet -> clear buffer, emit error frames, add current frame to buffer 
        #
        # if we analyze 16 frames without the delta time exceeding the MAX_FRAME_TIME_DELTA
        # we can parse a spektrum packet
        
        if self.time_delta(frame) > MAX_FRAME_TIME_DELTA:
            errors = self.make_error_frames()
            self.frame_buf = [frame] # first frame of new spektrum packet, don't throw away
            return errors
        
        self.frame_buf.append(frame)


        if len(self.frame_buf) == 16:
            parsed = self.make_parsed_frames()
            self.frame_buf = []
            return parsed
                  
        return 
    
    def time_delta(self, frame):
        if self.last_end_time is None:
            self.last_end_time = frame.start_time # use frame.start_time here so the difference ends up being 0 for the very first analyzed frame
        td = frame.start_time - self.last_end_time
        self.last_end_time = frame.end_time # don't forget to store frame.end_time for next calculcation
        return td
    
    def make_error_frames(self):
        return [AnalyzerFrame('err', f.start_time, f.end_time) for f in self.frame_buf]
    
    def make_parsed_frames(self):
        prased_proto, parsed_frames = self.parse_system_and_fades()
        # EXTERNAL receiver: parsed_proto will be None so we fall back to the setting in the analyzer
        # INTERNAL receiver: parsed_proto will be whatever was parsed from the packet (or None if invalid -> fallback to setting)
        actual_proto = prased_proto if prased_proto is not None else self.protocol_setting
        parsed_frames = parsed_frames + self.parse_channels(actual_proto)
        return parsed_frames 


    def parse_system_and_fades(self):
        frames = self.frame_buf[:2]
        if self.receiver_type_setting == "INTERNAL":
            fades = int.from_bytes(frames[0].data['data'], byteorder='big')
            proto = SYSTEM_TO_PROTOCOL.get(frames[1].data['data'])
            match = 'YES' if proto == self.protocol_setting else 'No' # does the parsed protocol match the on provided by the setting?
            return (proto, [
                AnalyzerFrame('fades', frames[0].start_time, frames[0].end_time, {'fades': fades}),
                AnalyzerFrame('system', frames[1].start_time, frames[1].end_time, {'proto': proto, 'match': match })
                ])
        else:
            fades = int.from_bytes(frames[0].data['data'] + frames[1].data['data'], byteorder='big')
            return (None, [AnalyzerFrame('fades', frames[0].start_time, frames[1].end_time, {'fades': fades})])
        

    def parse_channels(self, proto):
        frames = self.frame_buf[2:]
        frames2 = [frames[i:i + 2] for i in range(0, len(frames), 2)] # split 'frames' array into size-two chunks 
        return [self.parse_channel(frame2, proto) for frame2 in frames2]


    def get_channel_name(self, id:int):
        if 0<=id< len(CHANNEL_NAMES):
            return CHANNEL_NAMES[id]
        else:
            return "NOT_IDENTIFIED"


    def parse_channel(self, frames, proto):
        parsed = int.from_bytes(frames[0].data['data'] + frames[1].data['data'], byteorder='big')
        # masks and bit shifts from datasheet
        if proto == DSM2_22MS_1024:
            pos = parsed & 0x03ff
            id = (parsed & 0xfc00) >> 10
            return AnalyzerFrame('channel_1024', frames[0].start_time, frames[1].end_time, {'chan_name': self.get_channel_name(id), 'chan_id': id, 'pos': pos})
        else:
            pos = parsed & 0x07ff
            id = (parsed & 0x7800) >> 11
            pha = (parsed & 0x8000) >> 15
            return AnalyzerFrame('channel_2048', frames[0].start_time, frames[1].end_time, {'chan_name': self.get_channel_name(id), 'chan_id': id, 'pos': pos, 'pha': pha })

