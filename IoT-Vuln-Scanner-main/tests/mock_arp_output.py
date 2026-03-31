# tests\mock_arp_output.py
mock_arp_output = [
    {
        "id": 1,
        "mac_address": "00:14:22:01:23:45",
        "ip_address": "192.168.0.10",
        "manufacturer": "Samsung",
        "device_type": "Smart TV",
        "services": [
            {"service": "HTTP", "version": "1.1"},
            {"service": "DLNA", "version": "1.5"}
        ]
    },
    {
        "id": 2,
        "mac_address": "00:25:9c:cf:1c:ac",
        "ip_address": "192.168.0.11",
        "manufacturer": "Philips",
        "device_type": "Hue Bulb",
        "services": [
            {"service": "Zigbee", "version": "3.0"}
        ]
    },
    {
        "id": 3,
        "mac_address": "44:65:0d:56:cc:d3",
        "ip_address": "192.168.0.12",
        "manufacturer": "Amazon",
        "device_type": "Echo",
        "services": [
            {"service": "HTTP", "version": "1.1"},
            {"service": "Alexa Voice Service", "version": "3.0"}
        ]
    },
    {
        "id": 4,
        "mac_address": "18:b4:30:25:7f:3d",
        "ip_address": "192.168.0.13",
        "manufacturer": "Nest",
        "device_type": "Thermostat",
        "services": [
            {"service": "HTTPS", "version": "1.2"},
            {"service": "MQTT", "version": "3.1.1"}
        ]
    },
    {
        "id": 5,
        "mac_address": "1c:0b:d5:2a:bc:de",
        "ip_address": "192.168.0.14",
        "manufacturer": "Ring",
        "device_type": "Doorbell",
        "services": [
            {"service": "HTTPS", "version": "1.2"},
            {"service": "SIP", "version": "2.0"}
        ]
    },
    {
        "id": 6,
        "mac_address": "40:b8:37:5b:cf:fe",
        "ip_address": "192.168.0.15",
        "manufacturer": "Netgear",
        "device_type": "Arlo Camera",
        "services": [
            {"service": "RTSP", "version": "2.0"},
            {"service": "HTTPS", "version": "1.2"}
        ]
    },
    {
        "id": 7,
        "mac_address": "94:10:3e:ac:df:ef",
        "ip_address": "192.168.0.16",
        "manufacturer": "Belkin",
        "device_type": "Wemo Plug",
        "services": [
            {"service": "HTTP", "version": "1.1"},
            {"service": "UPnP", "version": "1.0"}
        ]
    }
]
