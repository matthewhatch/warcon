import gpsd

from os import system
from scapy.all import sniff, Dot11Beacon, Dot11, Dot11Elt, RadioTap
from threading import Thread
from time import sleep

endpoints = []

def change_channel():
  channel = 1
  while True:
    system(f"iwconfig wlan1 channel {channel}")
    channel = channel % 14 + 1
    sleep(1)

def find_ssid(packet):
  try:
    if packet.haslayer(Dot11Beacon):
      system('clear')
      dot11_layer =  packet.getlayer(Dot11)
      bssid = dot11_layer.addr2
      ssid = packet.getlayer(Dot11Elt).info
      ssid = ssid.decode('utf-8')
      time, lat, lon = get_location()
      strength = packet.getlayer(RadioTap).dBm_AntSignal
      stats = packet[Dot11Beacon].network_stats()
      channel = stats.get('channel')
      crypto = stats.get('crypto')

      print(f'BSSID: {bssid}\nSSID: {ssid}\nSIGNAL: {strength}\nChannel: {channel}\nEncryption: {crypto}\nLAT: {lat}\nLON: {lon}\nTimestamp: {time}\n')
  except KeyboardInterrupt:
    print("Stopping find_ssid")

def get_location():
  current_location = gpsd.get_current()
  time = current_location.time
  lat = current_location.lat
  lon = current_location.lon

  return time, lat, lon

if __name__ == "__main__":
  try:
    system('clear')
    print('Connecting GPS...')
    gpsd.connect()

    print('Starting Channel Changer...')
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    print('Channel Changer Started!')
    print('Start Sniffing')
    sniff(iface="wlan1",prn=find_ssid)
  except KeyboardInterrupt:
    print('Stopping __main__')