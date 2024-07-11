import gpsd
import sqlite3

from datetime import datetime
from os import system, environ, path, rename
from scapy.all import sniff, Dot11Beacon, Dot11, Dot11Elt, RadioTap
from threading import Thread
from time import sleep
from network import Network

ADD_NETWORK = 0
UPDATE_NETWORK = 1
SKIP_NETWORK = 2

def change_channel():
  channel = 1
  while True:
    system(f"iwconfig wlan1 channel {channel}")
    channel = channel % 14 + 1
    sleep(1)

def add_or_update(bssid, strength):
  return_val = SKIP_NETWORK
  try:
    existing = Network.find('bssid',bssid)
    if len(existing) == 0:
      return_val = ADD_NETWORK
    elif existing[0][3] < strength:
      return_val = UPDATE_NETWORK
    
    return return_val
  except KeyError:
    return True

def find_ssid(packet):
  try:
    if packet.haslayer(Dot11Beacon):
      dot11_layer =  packet.getlayer(Dot11)
      bssid = dot11_layer.addr2
      ssid = packet.getlayer(Dot11Elt).info
      ssid = ssid.decode('utf-8')
      strength = packet.getlayer(RadioTap).dBm_AntSignal
      stats = packet[Dot11Beacon].network_stats()
      channel = stats.get('channel')
      crypto = stats.get('crypto')
      time, lat, lon, has_fix = get_location()


      add_or_update_val = add_or_update(bssid, strength)
      if add_or_update_val == ADD_NETWORK:
        network = Network(bssid, ssid, int(strength), int(channel), str(crypto), float(lat), float(lon), time)
        print(f'Adding Network: {network}')
        network.save()
        return

      if add_or_update_val == UPDATE_NETWORK:
        network = Network(bssid, ssid, int(strength), int(channel), str(crypto), float(lat), float(lon), time)
        print(f'Updating Network {network}')
        network.update()
        return
  except KeyboardInterrupt:
    print("Stopping find_ssid")

def get_location():
  current_location = gpsd.get_current()
  time = current_location.time
  lat = current_location.lat
  lon = current_location.lon
  has_fix = current_location.mode >= 2
  return time, lat, lon, has_fix

def setup_table():
  connection = sqlite3.connect('warcon.db')
  cursor = connection.cursor()
  cursor.execute('''CREATE TABLE if NOT EXISTS networks (
                 id INTEGER PRIMARY KEY,
                 bssid TEXT,
                 ssid TEXT,
                 signal INTEGER,
                 channel INTEGER,
                 encryption TEXT,
                 latitude TEXT,
                 longitude TEXT,
                 updated_at TEXT)
  ''')

if __name__ == "__main__":
  try:
    setup_table()
    environ['TERM'] = 'linux'
    system('clear')
    print('[*] setting up wlan1')
    system('ifconfig wlan1 down')
    system('iwconfig wlan1 mode monitor')
    system('ifconfig wlan1 up')
    print('[*] wlan1 in monitor mode')

    print('[*] Connecting GPS')
    gpsd.connect()

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    sniff(iface="wlan1",prn=find_ssid)
  except KeyboardInterrupt:
    print('Stopping __main__')
