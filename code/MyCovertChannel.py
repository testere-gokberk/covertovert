from CovertChannelBase import CovertChannelBase
from scapy.all import sniff, Ether
from scapy.all import ARP, Ether, IP, srp
from scapy.all import get_if_hwaddr, conf
from scapy.layers.l2 import LLC
from scapy.layers.l2 import SNAP
import time
import random

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        super().__init__()
           
    def send(self, log_file_name):
        """
        - In this covert channel implementation, I am using DSAP field in the LLC header to send the secret message.
        - We process the message two bits by two bits and every possible two bit pattern corresponds to a range of dsap values:
        - 00 -> [0, 63]
        - 01 -> [64, 127]
        - 10 -> [128, 191]
        - 11 -> [192, 255]
        """
    
        binary_message = self.generate_random_binary_message_with_logging(log_file_name,min_length=16,max_length=16)

        own_mac = self.get_current_mac()
        
        start = None
        end = None
        
        for i in range(0, len(binary_message), 2):

            dsap = None
            #print(binary_message[i : i+2])
            
            if binary_message[i : i+2] == "00":
                dsap = random.randint(0, 63)

            elif binary_message[i : i+2] == "01":
                dsap = random.randint(64, 127)

            elif binary_message[i : i+2] == "10":
                dsap = random.randint(128, 191)
                
            elif binary_message[i : i+2] == "11":
                dsap = random.randint(192, 255)                

            packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=own_mac) / LLC(dsap=(dsap))

            if(i==0):
                start = time.time()

            super().send(packet)
                
        end = time.time()
        
        #print("ELAPSED TIME ", end-start)
        #print("CHANNEL CAPACITY ", 128/(end-start))

    def get_current_mac(self):

        """
        - An utility function to get the MAC adress of the device that we run this script.
        - Since it is necessary, we use this function to provide the MAC adress of the sending device in the Ether header.
        """

        mac_address = get_if_hwaddr(conf.iface)
        return mac_address
        
    def receive(self, log_file_name):
        """
        - To receive the covert channel message, we sniff the packets if the packet has an LLC header.
        - We extract two bits from each packet depending on the which range of dsap values it falls into:
        - [0, 63] -> 00 
        - [64, 127] -> 01 
        - [128, 191] -> 10
        - [192, 255] -> 11
        
        """

        self.binary_message = ""

        def packet_callback(packet):
            
            if packet.haslayer(LLC):

                dsap_value = packet[LLC].dsap
                secret_bit = None
                
                if 0 <= dsap_value and dsap_value <= 63:
                    secret_bit = "00"
                elif 64 <= dsap_value and dsap_value <= 127:
                    secret_bit = "01"
                elif 128 <= dsap_value and dsap_value <= 191:
                    secret_bit = "10"
                elif 192 <= dsap_value and dsap_value <= 255:
                    secret_bit = "11"
                    
                self.binary_message += secret_bit

        def check_stop(packet):
            
            if packet.haslayer(LLC):             
                if self.convert_eight_bits_to_character(self.binary_message[-8:]) == ".":
                    return True
            
            return False

        sniff(iface="eth0", prn=packet_callback, stop_filter=check_stop)

        char_msg = []
        
        for i in range(0, len(self.binary_message), 8):
            char_msg.append(self.convert_eight_bits_to_character(self.binary_message[i:i+8]))

        decoded_message = "".join(char_msg)

        self.log_message(decoded_message, log_file_name)

        return decoded_message








