# Gökberk-Salim Covert Channel

**Covert Channel**

We are sending our covert channel message using the DSAP field of LLC header. 
To convey our message we ate using all possible values of the 8 bits of the DSAP field.
We are sending two bits from the secret message per packet.

**Encoding Method**

To encode our message we are mapping every possible 2 bit combinations into different range of DSAP values.
    
    - Bit Values -> DSAP Ranges
    - 00 -> [0, 63]
    - 01 -> [64, 127]
    - 10 -> [128, 191]
    - 11 -> [192, 255]

For decoding, we apply the reverse of this and extract the bit values which DSAP value of the packet corresponds to.

**Covert Channel Performance**

Our covert channel capacity is ~23 bps
