from CovertChannelBase import CovertChannelBase
from scapy.all import sniff, Ether
from scapy.all import ARP, Ether, IP
from scapy.all import get_if_hwaddr, conf
from scapy.layers.l2 import LLC
from scapy.layers.l2 import SNAP

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
        print("COVERT CHANNEL INITIATED")
        
    def get_mac(self, ip):
        
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        
        answered, unanswered = srp(arp_req, timeout=5, verbose=True)

        for sent, received in answered:
            return received.hwsrc  

        
    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        
        #mac_addr = self.get_mac("172.18.0.3")
        
        #print("MAC OF TARGET FOUND ", mac_addr)
        
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        #print("BINARY MESSAGE", binary_message)
        
        own_mac = self.get_current_mac()
        print("MAC OF THIS DEVICE ", own_mac)
        
        for bit in binary_message:
            
            print( type(bit))
            
            if bit == "1":
                
                base_dsap = 0xc0  
                encoded_dsap = base_dsap | 0x01

                print("ENCODED DSAP with 1", hex(encoded_dsap))

                #packet = LLC(dsap=encoded_dsap) / IP(dst="172.18.0.3") 
                
                #02:42:ac:12:00:03 ff:ff:ff:ff:ff:ff
                # src=own_mac
                packet = Ether(dst="ff:ff:ff:ff:ff:ff" ) / LLC(dsap=encoded_dsap) / IP(dst="172.18.0.3") #/ LLC(dsap=encoded_dsap) 

                print("PACKET SENT ", packet.show(dump=True) , "\n PACKET BIT ", bit)

                super().send(packet)

                self.sleep_random_time_ms(start=1, end=5)        
            
            else:
                
                base_dsap = 0xc0  
                encoded_dsap = base_dsap & 0xFE

                print("ENCODED DSAP with 0", hex(encoded_dsap))

                packet = LLC(dsap=(encoded_dsap)) / IP(dst="172.18.0.3") 

                print("PACKET SENT ", packet.show() , "\n PACKET BIT ", bit)
                
                super().send(packet)
                
                self.sleep_random_time_ms(start=1, end=5)        
                        
            
    def get_current_mac(self):

        iface = conf.iface        
        mac_address = get_if_hwaddr(iface)
        return mac_address
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        #self.log_message("", log_file_name)

        mac_addr = self.get_current_mac()
        #print("MAC ADDRESS OF THIS CONTAIENER ", mac_addr)

        self.binary_message = ""

        def packet_callback(packet):
            
            print("CATCHED THE PACKET ", packet.show(dump=True))
            
            counter = 0
            
            while True:
                layer = packet.getlayer(counter)
                if layer is None:
                    break

                print(layer)
                counter += 1

            if packet.haslayer(LLC):
                print("HAS LLC")
                
                dsap_value = packet[LLC].dsap

                secret_bit = (dsap_value & 1) 

                print("SECRET BIT ", secret_bit)
                
                self.binary_message += str(secret_bit)

                if len(self.binary_message) % 8 == 0:  
                    char = self.convert_eight_bits_to_character(self.binary_message[-8:])
                    if char == ".":
                        print("TERMINATION CHAR FOUND")
                        return True
                    
            return False

        def check_stop(packet):
            
            print("CATCHED THE PACKET ", packet.show(dump=True))
            
            counter = 0
            
            while True:
                layer = packet.getlayer(counter)
                if layer is None:
                    break

                print(layer)
                counter += 1

            if packet.haslayer(LLC):
                print("HAS LLC")
                
                dsap_value = packet[LLC].dsap

                secret_bit = (dsap_value & 1) 

                print("SECRET BIT ", secret_bit)

                if len(self.binary_message) % 8 == 0:  
                    char = self.convert_eight_bits_to_character(self.binary_message[-8:])
                    if char == ".":
                        print("TERMINATION CHAR FOUND")
                        return True
                    
            return False

        sniff(iface="eth0", prn=packet_callback, stop_filter=check_stop)

        decoded_message = "".join(
            self.convert_eight_bits_to_character(self.binary_message[i:i + 8])
            for i in range(0, len(self.binary_message), 8)
        )

        self.log_message(decoded_message, log_file_name)

        return decoded_message

        

