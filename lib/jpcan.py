import serial # pyserial

class JPCan:
    def __init__(self, device, debug=False):
        self.debug = debug
        self.ser = serial.Serial(device, 9600)
    
    def shutdown(self):
        self.ser.close()
        
    def recv(self, timeout):
        line = self.ser.readline().decode().strip()
        msg = self.parse(line)
        return msg

    def Message(self, is_extended_id, arbitration_id, data):
        command = "s"

        can_id = hex(arbitration_id)[2:]
        while len(can_id) < 4:
            can_id = "0"+can_id
        command += can_id

        for thing in data:
            hex_string = hex(thing)[2:]
            while len(hex_string) < 2:
                hex_string = "0"+hex_string
            command += hex_string

        command += "\r"
        # print("sending >", command)
        return command
    
    def send(self, msg):
        self.ser.write(msg.encode())

    def parse(self, line):
        # print(line)
        # cheap way to make an object that we can set attributes/properties on
        msg = lambda: None
        msg.can_id = 0
        msg.data = []

        bits = line.split(" ")
        # print(bits)
        if bits[0] != "<":
            print("Ignoring ", line)
            return None

        msg.can_id = int(bits[1], 16)

        hex_string_data = bits[3:]
        # print(hex_string_data)
        
        for thing in hex_string_data:
            # print(thing)
            raw = int(thing, 16)
            # print(raw)
            msg.data.append(raw)
        
        if self.debug:
            print("< ", end="")
            print(hex(msg.can_id), end=" ")
            print(": ", end="")
            for thing in msg.data:
                print(hex(thing), end=" ")
            print()
        return msg