import sys
from pyshark import FileCapture

"""
After getting raw files we can convert them into wav using following SOX utility
sox -t raw -r 8000 -e mu-law -c 1 et97l2hjprm7r9a8lctj.raw et97l2hjprm7r9a8lctj.wav
"""

def create_file(_curr: FileCapture, _name: str):
    written_bytes: int = 0    
    """
    We could use binary value which would be better
    files[1][0].rtp.payload.binary_value
    """
    rtp_list = []
    raw_audio = open(_name,'wb')
    for i in _curr:
        try:
            rtp = i[3]
            if rtp.payload:
                rtp_list.append(rtp.payload.split(":"))
        except:
            pass
        
    for rtp_packet in rtp_list:
        packet = " ".join(rtp_packet)
        written_bytes = written_bytes + raw_audio.write(bytearray.fromhex(packet))
    
    return written_bytes

if(len(sys.argv) < 4):
    print("Usage : parse_calls <input_file.pcap> <port_start_range> <port_end_range>")
    print("Usage : parse_calls voice_call.pcap \"38000\" \"40000\"")
    quit()
else:
    print(f"parsing[{sys.argv[1]}] Range[{sys.argv[2]} - {sys.argv[3]}]")

def get_call_id(_raw_file: FileCapture):
    setup_frame_number = int(_raw_file[0].rtp.get('setup-frame'))
    setup_packet = FileCapture(_raw_file.input_filepath.name, display_filter=f"frame.number == {setup_frame_number}")
    ret_call_id = setup_packet[0].sip.call_id
    setup_packet.close()
    return ret_call_id

input_file = sys.argv[1]
port_start_range = sys.argv[2]
port_end_range = sys.argv[3]

ssrc = []
files = []
cap:FileCapture = FileCapture(input_file, display_filter=f"rtp && (udp.dstport > {port_start_range} && udp.dstport < {port_end_range})")
for packet in cap:
    if packet.rtp.ssrc not in ssrc:
        files.append(FileCapture(input_file, display_filter=f"rtp && (udp.dstport > {port_start_range} && udp.dstport < {port_end_range}) && rtp.ssrc == {packet.rtp.ssrc}"))
        ssrc.append(packet.rtp.ssrc)

cap.close()

for raw_file in files:
    raw_call_id = get_call_id(raw_file)
    create_file(raw_file, raw_call_id + '.raw')
    print(f"File {raw_call_id}.raw Added")
    raw_file.close()

print("Ended !")
