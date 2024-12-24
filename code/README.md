# Replace with Your Covert Channel Name

**Covert Channel**

We are sending our covert channel message using the DSAP field of LLC header. 
The secret message is carried in the least significant bit of DSAP field which controls whether the message is sent to a single device or a group of devices. Depending on that value we either use a broadcasting MAC adress or the individual MAC adress of the target device. 

**Encoding Method**

We apply a simple encoding mechanism where we map every possible bit pattern with length of 4 to each other. 
For decoding, we apply the reverse of mappings used in encoding to recover the original message.

    For example:

        Encode: 0000 -> 1000
        Decode: 1000 -> 0000

We store the mappings in a dictionary. We encode the whole message before transmitting and decode it after receiving it completely.

**Covert Channel Performance**

Our covert channel capacity is ~12.11 bps
