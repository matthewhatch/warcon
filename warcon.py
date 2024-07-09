import gpsd
import pandas as pd

from datetime import datetime
from os import system, environ, path, rename
from scapy.all import sniff, Dot11Beacon, Dot11, Dot11Elt, RadioTap
from threading import Thread
from time import sleep

networks = pd.DataFrame(columns=['BSSID','SSID','Signal','Channel','Encryption','Lat','Lon','updated_at'])
networks.set_index("BSSID", inplace=True)

def change_channel():
  channel = 1
  while True:
    system(f"iwconfig wlan1 channel {channel}")
    channel = channel % 14 + 1
    sleep(1)

def print_networks():
  while True:
    system('clear')
    print(networks)
    sleep(5)

def save_csv():
  while True:
    networks.to_csv('networks.csv')
    sleep(5)

def should_update(bssid, strength):
  try:
    old = networks.loc[bssid]
    if old.empty:
      True
  
    return old['Signal'] < strength
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

      if should_update(bssid, strength):
        networks.loc[bssid] = (ssid, strength, channel, crypto, lat, lon, time)
  except KeyboardInterrupt:
    print("Stopping find_ssid")

def get_location():
  current_location = gpsd.get_current()
  time = current_location.time
  lat = current_location.lat
  lon = current_location.lon
  has_fix = current_location.mode >= 2
  return time, lat, lon, has_fix

def rename_csv():
  FILE_ROOT = 'networks'
  FILE_EXT = '.csv'
  FILE_NAME = f'{FILE_ROOT}{FILE_EXT}'

  if path.isfile(FILE_NAME):
    date_string = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    new_name = f'{FILE_ROOT}-{date_string}{FILE_EXT}'
    rename(FILE_NAME, new_name)

if __name__ == "__main__":
  try:
    environ['TERM'] = 'linux'
    system('clear')
    print('[*] setting up wlan1')
    system('ifconfig wlan1 down')
    system('iwconfig wlan1 mode monitor')
    system('ifconfig wlan1 up')
    print('[*] wlan1 in monitor mode')

    print('[*] Connecting GPS')
    gpsd.connect()
    rename_csv()
    printer = Thread(target=print_networks)
    printer.daemon = True
    printer.start()

    saver = Thread(target=save_csv)
    saver.daemon = True
    saver.start()

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    sniff(iface="wlan1",prn=find_ssid)
  except KeyboardInterrupt:
    print('Stopping __main__')
