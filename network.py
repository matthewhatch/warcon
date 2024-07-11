# Class that represents a wireless network
import sqlite3
from dataclasses import dataclass

@dataclass
class Network:
    bssid: str
    ssid: str
    signal: int
    channel: int
    encription: str
    latitude: float
    longitude: float
    updated_at: str

    connection = sqlite3.connect('warcon.db')
    cursor = connection.cursor()

    def save(self):
        self.cursor.execute('''INSERT into networks
                            (
                            bssid,
                            ssid,
                            signal,
                            channel,
                            encryption,
                            latitude,
                            longitude,
                            updated_at) VALUES (?,?,?,?,?,?,?,?)''',
                            (self.bssid, self.ssid, self.signal, self.channel, self.encription, self.latitude, self.longitude, self.updated_at))
        self.connection.commit()

    def update(self):
        self.cursor.execute('''UPDATE networks
                            SET ssid = ?,
                                signal = ?,
                                channel = ?,
                                encryption = ?,
                                latitude = ?,
                                longitude = ?,
                                updated_at = ?
                            WHERE bssid = ?''',
                            (self.ssid, self.signal, self.channel, self.encription, self.latitude, self.longitude, self.updated_at, self.bssid))
        self.connection.commit()
  
    @classmethod
    def find(cls, column, value):
        connection = sqlite3.connect('warcon.db')
        cursor = connection.cursor()
        query = f'SELECT * FROM networks where {column} = ?'
        cursor.execute(query, (value,))
        results = cursor.fetchall()
        connection.close()
        return results
        