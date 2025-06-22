# ATL-protocol
Custom protocol made in python



ATL Protocol Setup for Linux (Kali/Ubuntu/Parrot OS)
1. Install Dependencies

```
sudo apt update && sudo apt upgrade -y  
sudo apt install python3 python3-pip -y  
pip3 install cryptography
```

2. Clone the Repository
```
git clone https://github.com/ediop3SquadALT/ATL-protocol.git  
cd atl-protocol
```
4. Run the Protocol
Server Mode (Listener)
```
python3 atl_protocol.py  
Listens on UDP port 5699 
```


Test Client Mode
Modify the __main__ section in atl_protocol.py to include:
```
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    atl = ATL(mode=ATL.Mode.STREAM)
    atl.set_callback('stream_data', lambda addr, data: print(f"Stream from {addr}: {data.decode()}"))
    atl.start()
    
    def send_test_data():
        time.sleep(2)
        target_addr = ('TARGET_IP', 5699)  # Replace with target IP
        atl.send(target_addr, b"Hello from Linux!")
    
    threading.Thread(target=send_test_data, daemon=True).start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        atl.stop()
```

4. Firewall Rules (Allow UDP Traffic)
```
sudo ufw allow 5699/udp
sudo ufw enable
```
6. Run in Background (Optional)

```
nohup python3 atl_protocol.py 
```
Notes:
Replace TARGET_IP with the local IP of the receiving device.
