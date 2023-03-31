from pymodbus.client.sync import ModbusTcpClient as ModbusClient

# address of modbus device
IX100_0 = 800
IX100_1 = 801
IX100_2 = 802
IX100_3 = 803
IX100_4 = 804
IX100_5 = 805
IX100_6 = 806
IX100_7 = 807

def main():
    """
    description:
        the driver function 
    """
    # connect to PLC
    OPENPLC_ADDR = "127.0.0.1"
    OPENPLC_PORT = 5020
    client = ModbusClient( OPENPLC_ADDR, port=OPENPLC_PORT )
    client.connect()
    print( client )

    client.write_coil( IX100_0, True, unit=1 )
    client.read_coils( IX100_0 )

    client.close()  
    return

if( __name__ == "__main__" ):
    main()
