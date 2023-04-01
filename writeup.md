<h3> PicoCTF-2023-writeup </h3>

I want to share my experience with the PicoCTF I participated which lasted for 2weeks and it was really fun and fascinating to play with and I learnt a lot from it. I participated with team 8h037.

![image](https://user-images.githubusercontent.com/113513376/229093471-77af8724-1b45-4d6f-a82e-fa835aafbd7e.png)

The whole team struggled to secure 1st position in Africa thanks to the team contribution. I want  to share my writeup on various challenges I solved.

And you can also get the rest of the challenges writeup on my team mates [github](https://h4ckyou.github.io/posts/ctf/picoctf/writeup.html)

Let get to the fun part of the challenges I solved and I hope y'all like it.

### Forensics

#### Who Is It
![image](https://user-images.githubusercontent.com/113513376/229096027-fcf2722d-c45c-4619-a6ac-cda341cefd8b.png)

Looking at the description, we are task to identify whose mail server the email is actually originated from.

Let download the file given and see what we can get from there and proceed to the next challenges.
![image](https://user-images.githubusercontent.com/113513376/229096280-276204e2-dbdd-4fc3-a3fd-4fe44cf57bcb.png)

This is the content of the file we downloaded and we got a IP which is 173.249.33.206 that is some lead there which can get us to the sender of the mail.

I decided to use the challenge name and search for whois online on google which lead me to a website.
![image](https://user-images.githubusercontent.com/113513376/229096353-4f65fee8-27be-46fa-848a-64a3f34ed536.png)

Website Used: [whois](https://www.whois.com/)

As we can see above we we're able to retrieve the scammer name by using the above link. That is a wrap I know right .

```
Flag: PicoCTF{Wilhelm Zwalina}
```

#### FIND AND OPEN
![image](https://user-images.githubusercontent.com/113513376/229096617-e5019d81-aa0e-4478-956c-0b98f9478779.png)

FindAndOpen a very cool challenge which two files was given, one for the zip file that need a password before we can extract it and the second file is what we need to analyse and get the first file password.
![image](https://user-images.githubusercontent.com/113513376/229096732-32f68746-d409-4a01-846e-f239d5b0f6a9.png)

This are the two downloaded file which is flag.zip which consist the flag and a pcap file which we can use wireshark to analyse it and get what we needed from it.

By analysing the pcap file we found an encoded string that look like base64. 
![image](https://user-images.githubusercontent.com/113513376/229096813-88d182ff-f37c-4934-b1e9-74ca43223e3d.png)

Let head to Cyberchef and try to decode it.
![image](https://user-images.githubusercontent.com/113513376/229096862-d735ab9d-83f0-4146-bee4-702cd38d130b.png)

We got the secret key to the flag.zip file so let try to extract it with the key we just found and see what happen next.
![image](https://user-images.githubusercontent.com/113513376/229096933-1cd72fb9-6b35-45b1-9151-6c40351c776f.png)

Extracting the flag.zip with the key we got gave out a file name flag which contain the flag we need.
![image](https://user-images.githubusercontent.com/113513376/229097011-076aa903-92fc-47fc-950e-bf1450dacbee.png)

```
Flag: picoCTF{R34DING_L0Kd_fil56_succ3ss_cbf2ebf6}
```

#### MSB
![image](https://user-images.githubusercontent.com/113513376/229097466-8ed39ea5-6aad-4908-aa48-5f33e319c2af.png)

This time we are dealing with image. Let download it and see what we have to do here.
![image](https://user-images.githubusercontent.com/113513376/229097496-ec754139-9298-4d55-adf4-03955d8b7a76.png)

This is the image which look corrupted and if we can recall the challenge is called MSB. Let search about that online we might get something interesting.
![image](https://user-images.githubusercontent.com/113513376/229097560-cce394b9-07de-48da-a0b0-db6dcd19d7eb.png)
![image](https://user-images.githubusercontent.com/113513376/229097651-b7c1c5da-d3da-467a-86c2-1fddf750b63f.png)

Site used: [stegonline](https://stegonline.georgeom.net/upload)

As we can see in the image below the website as Bit Order of MSB so all we have to do is click on go to extract what is hidden inside.
![image](https://user-images.githubusercontent.com/113513376/229097723-d5b8a01c-b3ce-47b3-8934-bcdfd30c5dd1.png)

We are able to retrive some readable ascii text so let download it and obtain the full data.
![image](https://user-images.githubusercontent.com/113513376/229097822-c859490a-661e-4ee3-8212-46c64e5fdcd4.png)

That is the extracted file we got from the online tools let try to get our flag from it.
![image](https://user-images.githubusercontent.com/113513376/229097998-5f1fee99-4b31-445a-bbe2-8eb8092878b4.png)

```
Command Use: cat Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisadaflag.dat | grep picoCTF
```

Boom and we have our flag. Seems easy and fun right?

```
Flag: picoCTF{15_y0ur_que57_qu1x071c_0r_h3r01c_06326238}
```

#### Unforgotten Bits
![image](https://user-images.githubusercontent.com/113513376/229098477-34e04742-bc40-4b08-ba84-e53ed496f0fc.png)

I spent some couples of hours on this challenge I don't even think it's an hours 🤔 I used a complete whole day to get it done. 

Let download the given files which is a disk img so I decided to use Autopsy on it.

```
Autopsy offers  GUI access to a variety of investigative command-line tools from The  Sleuth Kit, including file analysis, image and file hashing, deleted  file recovery, and case management. To know more about Autopsy you might check this link out https://cipcyber.com/2020/03/digital-forensics-investigation-using-autopsy-in-kali-linux.html.
```

Using Autopsy
![image](https://user-images.githubusercontent.com/113513376/229098863-6b26dc75-88bf-4a53-abbe-86521c152b98.png)

All we have to do here is click on new case.
![image](https://user-images.githubusercontent.com/113513376/229098910-468ab577-03e2-454b-abdd-83877e33bdf5.png)

We can name the case anything we feel like to name it so let click on new case again to proceed.
![image](https://user-images.githubusercontent.com/113513376/229098980-24d7fdfc-9fea-4106-a419-21e56cf97886.png)

Next thing to do is click on add host.
![image](https://user-images.githubusercontent.com/113513376/229099016-05b97841-9cb3-4158-8dfa-ba7342a02e2d.png)

Let click on add host again after to proceed forward.
![image](https://user-images.githubusercontent.com/113513376/229099114-44267670-f150-4d0e-9620-ea697eef2ca3.png)

This time we will click on add image.
![image](https://user-images.githubusercontent.com/113513376/229099132-198ac93f-3e93-4ef1-bd42-245319b1a8e3.png)

Time to add our image by clicking on the add image file.
![image](https://user-images.githubusercontent.com/113513376/229099208-48bf2dab-eb3d-4eb4-8257-ad0ee3429c63.png)

Next thing I did was to put the full path of where the disk img is located and click next.
![image](https://user-images.githubusercontent.com/113513376/229099301-d4d5ab24-d426-4479-afee-8a6aa74cf13f.png)

Let click on add to move forward.
![image](https://user-images.githubusercontent.com/113513376/229099360-a6c6fb89-a4ea-4439-b13f-0fc0b8162d3e.png)

All we have to do is click on analyze to analyze the file.
![image](https://user-images.githubusercontent.com/113513376/229099590-903eddff-8ed0-4bf9-8303-2129b8760756.png)

Let look at the home directory to find something interesting.

All this is under /home/yone directory and as we can see we have some interesting stuff there.
![image](https://user-images.githubusercontent.com/113513376/229099864-78010da3-1766-464f-a96a-aceb2e626513.png)

I decided to look into Contents Of File: /3/home/yone/irclogs/01/04/#avidreader13.log and i got all this which is steghide credential but we don't know for which image so let look around again.
![image](https://user-images.githubusercontent.com/113513376/229099952-78fa786b-8568-4b9d-9d0e-a61655f2c368.png)

We got some .bmp image under /home/yone/gallery directory now we can test the credential we found earlier on them before we can do that we have to use our Terminal that is the only place we can run steghide on the images.
![image](https://user-images.githubusercontent.com/113513376/229100014-2bd5dec8-2a1e-4971-aeeb-22a9780f761a.png)
![image](https://user-images.githubusercontent.com/113513376/229100047-f9c23c62-88bc-4e6c-8d9e-97d1891071f2.png)

Using the password we found earlier we we're able to extract encoded strings let use same passwords on the others image.
![image](https://user-images.githubusercontent.com/113513376/229100162-638a061f-169a-4583-88d4-91a23496d702.png)

```
Password Used: akalibardzyratrundle
```

I was able to get encoded txt files using same password but unfortunately the password didn't work for the last image which is 7.bmp, We will look into that later but first let try to decoding the encrypted txt files.
![image](https://user-images.githubusercontent.com/113513376/229100346-8240b1f2-9d6a-40e8-8921-e122d59bf833.png)

```
Command Used: sudo openssl aes-256-cbc -d -in les-mis.txt.enc -out out.txt -K 58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508 -iv 7a12fd4dc1898efcd997a1b9496e7591 -S 0f3fa17eeacd53a9
```

If we can recall earlier we got some iv, key and salt in autopsy so I use that on the encoded files so we will use same methology on the rest of the encoded files we should already know how to do that so let try to figure out the 7.bmp file by going back to autopsy.

checking the Contents Of File: /3/home/yone/irclogs/02/04/#leagueoflegends.log we got a lot of reading text which is kinda boring to read although I read them all by viewing the irlogs. There was some talking about league of legends champion and so on.
![image](https://user-images.githubusercontent.com/113513376/229100588-92433b40-24ed-4408-8134-ad7519452273.png)

I decided to check the contents of /home/yone/notes directory which has three files in it.
![image](https://user-images.githubusercontent.com/113513376/229100634-e68809c9-a1cf-4972-a295-fb4be7ec5c51.png)

This look like half of the password we are looking for and they look like league of legends champions name. After roaming around for quite long I got a hit by generating a wordlists from Leagues of legend champions name to complete the half password of yasuoaatrox....
![image](https://user-images.githubusercontent.com/113513376/229100714-ac110bc1-3c18-4324-b474-56fa06cc7ab4.png)

```
# Open the file containing the champion names
with open('champions.txt') as f:
    champion_names = f.readlines()

# Remove any whitespace characters from the names
champion_names = [name.strip() for name in champion_names]

# Create a list to hold the combinations
combinations = []

# Loop through each champion name
for i in range(len(champion_names)):
    # Loop through the remaining champion names
    for j in range(i+1, len(champion_names)):
        # Concatenate the two names and append to the combinations list
        combination = champion_names[i] + champion_names[j]
        combinations.append(combination)

# Write out the combinations to a new file
with open('wordlistsLOL.txt', 'w') as f:
    for combination in combinations:
        f.write(combination + '\n')

```

The champions.txt have all the names of the champions of league of legend which i compile.
![image](https://user-images.githubusercontent.com/113513376/229100909-f598341e-e462-4c48-8731-7a0d02509aff.png)

Let run our script.
![image](https://user-images.githubusercontent.com/113513376/229100974-bc97013c-b473-4aca-82d6-985ff6eb0244.png)

We just have to complete the half password now using a bash script.

```
#!/bin/bash

# Set the input and output file names
input_file="wordlistsLOL.txt"
output_file="new_wordlistsLOL.txt"

# Loop through each line in the input file
while read line; do
  # Prepend "yasuoaatrox" to the beginning of the line and write it to the output file
  echo "yasuoaatrox""$line" >> "$output_file"
done < "$input_file"
```

Now we run the script

And I found the password of the 7.bmp img so let use try it out.
![image](https://user-images.githubusercontent.com/113513376/229101258-26d89dee-c00c-4b6c-ae17-1ea7fab6d9bf.png)
![image](https://user-images.githubusercontent.com/113513376/229101304-f9265fe7-d951-4ee6-b6b9-67ea7747ce49.png)

I was able to extract a file name called ledger.1.txt.enc but when I try to decode it with the given key we found on Autopsy It didn't work so let go back to Autopsy to dig deeper.
![image](https://user-images.githubusercontent.com/113513376/229101353-067b96bc-8213-4dc6-82a1-4a24b27f755c.png)

After spending couples of hours I Found something that look like a binary string so I took it to Cyberchef and try my luck to decrypt it but nothing seems to happen then i went back to autopsy to check for more details

Looking around lead me to browsing history that seems like a hint to the Binary strings so I went straight to google and search about how to decrypt a bits strings to ascii with golden ratio base.
![image](https://user-images.githubusercontent.com/113513376/229101464-7493058d-e123-45c0-ab29-2d0ef1f040fa.png)

I wrote this code to solve the problem and name it solve.py. Let test it out .
![image](https://user-images.githubusercontent.com/113513376/229101527-78eec5b0-84d8-4dec-8ec5-3ecac7cf8988.png)
![image](https://user-images.githubusercontent.com/113513376/229101566-f792c653-1c7c-442d-9afa-a977ebe12006.png)

Finally we have gotten the salt, key and iv for the encoded ledger.enc.txt file so time to use openssl on it.
![image](https://user-images.githubusercontent.com/113513376/229101624-b5071a47-489a-42fa-b818-9eaa78045a4c.png)

```
Command Used: sudo openssl aes-256-cbc -d -in ledger.1.txt.enc -out out1.txt -K a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da -iv 908458e48fc8db1c5a46f18f0feb119f -S 2350e88cbeaf16c9.
```

Boom and we have our flag after suffering for a day but I learnt a lot.

```
Flag: picoCTF{f473_53413d_40405b89}
```

### Cryptography

#### POWER ANALYSIS: PART 2
![image](https://user-images.githubusercontent.com/113513376/229101977-75479f27-441c-4768-b2e4-5c2c5d86e4f3.png)

This time we are dealing with cryptography challenges which we are task to look for the encryption key. Let go ahead and download the given zip file.
![image](https://user-images.githubusercontent.com/113513376/229102072-98a4bfb4-1904-43b8-8796-2b892a2e7084.png)

After I extracted the given zip file as we can see above It gave out 100 txt files so I decided to read one of the files.
![image](https://user-images.githubusercontent.com/113513376/229102093-51a9de76-8d9f-4fd0-a676-5cb154099beb.png)

The plaintext and power traces seems interesting so i rushed to my google and did a little research on power analysis attack and luckily i found a writeup about a Google CTF 2022 that seems to be on power analysis attack [link](https://zenn.dev/kurenaif/articles/ae83691511b966)  but we seems to have no traces.json file but we did have a zip file that contains a txt files with a plaintext and the power trace i quickly write a python code to extract the power trace from each of the files and save to trace.json.

```
import json

# ANSI escape codes for colors
GREEN = "\033[32m"
RESET = "\033[0m"

plaintexts = []
traces = []

for i in range(100):
    filename = f'trace{str(i).zfill(2)}.txt'
    pt, trace = open(filename, 'r').read().split('\n')
    pt = bytes.fromhex(pt.split(' ')[-1])
    assert len(pt) == 16
    trace = trace.split("Power trace: ")[-1]
    trace = eval(trace)
    plaintexts.append(pt)
    traces.append(trace)


out = []
for pt, trace in zip(plaintexts, traces):
    out.append({"pt":list(pt), "pm":trace})

# Write output to file
with open("traces.json", "w") as f:
    f.write(json.dumps(out))

# Print success message
print(f"{GREEN}[SUCCESS]{RESET} Output written to traces.json.")
```

Now let put this as trace.py to get the traces.json.
![image](https://user-images.githubusercontent.com/113513376/229102323-80940404-36f8-425f-8cef-ae21acbc8df5.png)

We have successly retrieve the traces.json so now it time to run our script we got from the googleCTF.
![image](https://user-images.githubusercontent.com/113513376/229102379-423ce0cf-c130-4669-ac43-39c6122b4cb3.png)

This is the first script I tried.
![image](https://user-images.githubusercontent.com/113513376/229102426-7df226c6-9bf4-44c7-acf2-ae2ee49202fb.png)

That is the hex but unfortunately when I try to submit it, It gave incorrect flag so I went back to google and do more research about googleCTF and I got another different script.
![image](https://user-images.githubusercontent.com/113513376/229102502-b2eb42b7-121b-4de7-8035-af80aa4cc22b.png)

Link: [github](https://github.com/pkiluke/google-ctf-2022/blob/main/electric-mayhem-cls.py)

This is the link that gave me the right flag so let check the script out.

Running the script gave out an error so I decided to edit it by removing some line.
![image](https://user-images.githubusercontent.com/113513376/229102641-f691d323-d8da-4b5b-9089-f79ed384c07b.png)
![image](https://user-images.githubusercontent.com/113513376/229102665-f24dc494-addf-4c7b-873e-596ef3e3ffcb.png)

I decided to remove the line I circle above then i retry the script.
![image](https://user-images.githubusercontent.com/113513376/229102731-a6cef9c9-3fd9-4cd3-a0d4-83dddcd6a3c5.png)

I don't know why the webshell keep on killing the script let try it on our terminal.
![image](https://user-images.githubusercontent.com/113513376/229102798-c79ec681-38c0-4b8c-8556-a7698acc65f9.png)

Boom that's the flag we are looking right there kinda fun to play with right.

```
Flag: picoCTF{2f4981b159a0a78a5e222bc537f894ae}
```

#### POWER ANALYSIS: PART 1
![image](https://user-images.githubusercontent.com/113513376/229103490-dbe211eb-3d58-42c6-8ab3-9d565bfa7057.png)

Now let look into power analysis 1 by lauching the instance we can see a running server given all we have to do first is by getting the traces.json like we did in power analysis 2 so let check what the server does.
![image](https://user-images.githubusercontent.com/113513376/229103468-6812c8b5-89b7-4fae-a974-0d103bd71392.png)

It ask us to provide 16 bytes of plaintext encoded as hex let get the traces.json file and move forward 

This is my script i used to get the json file
![image](https://user-images.githubusercontent.com/113513376/229103554-c586afb5-4326-47e7-9fee-72a863e245c4.png)

So lets run it. It runs perfectly without any error that cool right.
![image](https://user-images.githubusercontent.com/113513376/229103620-a58d63c2-c273-4869-bf70-a031970a9326.png)
![image](https://user-images.githubusercontent.com/113513376/229103693-1738b565-5437-4bb0-9668-8db638967ec0.png)

It time to use same solve script of power analysis 2 which is the screenshot below.
![image](https://user-images.githubusercontent.com/113513376/229103739-940c1a81-c406-44b4-8e94-3fe04eba6a82.png)

I provided the solve script in power analysis 2 and you can get it if you go back to the top expalation of power analysis 2 that i did.
![image](https://user-images.githubusercontent.com/113513376/229103827-dcc4117c-a204-450a-bc9d-39ba718d4fd6.png)

That's the encryption key use for Power analysis 1 which will be our flag.

```
Flag: picoCTF{65cce0eab280e39d12625c7315b03fa1}
```

#### POWER ANALYSIS: WARMUP
![image](https://user-images.githubusercontent.com/113513376/229288645-5effac50-4e2e-4a4e-82be-07a8b9ebeba1.png)

The warmup PowerAnalysis challenge was actually hard I spend almost 4hours getting it done running my script 16 times let connect to the address with ncat. 
![image](https://user-images.githubusercontent.com/113513376/229288671-22e0397f-fcab-43c2-bd86-ae16cb29f324.png)

Asking us to provide a 16 bytes plaintext encoded as hex and should leak a bit to us trying 000000000000000000000000000000ef  and we got a leakage result which is 7 if we can code a script for it.

Take an example:

```
000000000000000000000000000000ef
000000000000000000000000000000f0
000000000000000000000000000000f1
000000000000000000000000000000f2
000000000000000000000000000000f3
000000000000000000000000000000f4
000000000000000000000000000000f5
000000000000000000000000000000f6
000000000000000000000000000000f7
000000000000000000000000000000f8
000000000000000000000000000000f9
000000000000000000000000000000fa
000000000000000000000000000000fb
000000000000000000000000000000fc
000000000000000000000000000000fd
000000000000000000000000000000fe
000000000000000000000000000000ff
```

We have to send 256 of that to the server so i scripted it to make it easy.

```
from pwn import remote

data1=b""
data3=b"000000000000000000000000000000"
i = 0

fo=open("output.txt",'wb')
while 1:
    if i == 256 : break
    r=remote('saturn.picoctf.net',64600)
    r.recvuntil("Please provide 16 bytes of plaintext encoded as hex: ")
    data2 = str(hex(i))[2:].encode()
    if len(data2) == 1: data2=b'0'+data2
    print(data1 + data2 + data3)
    r.sendline(data1 + data2 + data3)
    r.recvuntil("leakage result: ")
    fo.write(r.recvline().rstrip()+b"\n")
    i += 1
fo.close()
```

Running when it done we should get the output save in output.txt.
![image](https://user-images.githubusercontent.com/113513376/229288759-0f6b94ff-0dfa-4ccd-82ac-6003776c0f92.png)
![image](https://user-images.githubusercontent.com/113513376/229288771-348c786e-4f42-4fcf-9cec-4de3616e4ec8.png)

Now a little thing to break down  when the output is 7 => the leak at the position is changing = > 0 and 8 => the leak at that position is changing = 1 so we just have to script it out to convert all 7 = 0 and 8 =1.

```
def convert_file(input_filename, output_filename):
    with open(input_filename, "r") as input_file:
        input_str = input_file.read()

    output_str = ""
    for char in input_str:
        if char == "7":
            output_str += "0"
        elif char == "8":
            output_str += "1"
        else:
            output_str += char

    with open(output_filename, "w") as output_file:
        output_file.write(output_str)

input_filename = "output.txt"
output_filename = "new_output.txt"
convert_file(input_filename, output_filename)
```

Running it creates the new output file
![image](https://user-images.githubusercontent.com/113513376/229288815-e519f3c0-70ce-4160-a6b9-ead332c1eed9.png)

Now that we have it we can try brute forcing the key now since we have been given Sbox in encrypt.py file.

```
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
ls=[]
with open("new_output.txt",'rb') as f:
    for lines in f:
        ls.append(lines.rstrip())
print(ls)
res=[]
for i in range(256):
    for j in range(len(ls)):
        print(i,j,Sbox[i^j],Sbox[i^j]&0x01)
        if (str((Sbox[i^j]&0x01)).encode() != ls[j]) : break
        if (j == len(ls) - 1): res.append(i)
print(res)
```

Now with the script above we can run our brute forcing to get the first key.
![image](https://user-images.githubusercontent.com/113513376/229288857-2321aa8e-af53-4b51-89ea-5f14e59b2f01.png)

We got 157 which is the first key now we have the same process like 15 more times but NOTE we need to remove 00 from data3 and add to data1 just like that below.

```
from pwn import remote

data1=b"00"
data3=b"0000000000000000000000000000"
i = 0

fo=open("output.txt",'wb')
while 1:
    if i == 256 : break
    r=remote('saturn.picoctf.net',64600)
    r.recvuntil("Please provide 16 bytes of plaintext encoded as hex: ")
    data2 = str(hex(i))[2:].encode()
    if len(data2) == 1: data2=b'0'+data2
    print(data1 + data2 + data3)
    r.sendline(data1 + data2 + data3)
    r.recvuntil("leakage result: ")
    fo.write(r.recvline().rstrip()+b"\n")
    i += 1
fo.close()
```

Each time we got a key we need to keep editting out script till data3 is empty and data1 have everything.

```
data1=b"0000"
data3=b"00000000000000000000000000"

data1=b"000000"
data3=b"000000000000000000000000"
```

Till data3 is empty and remember any number you get the lowest should be 0 and the highest should be 1 with the same processs now that we have all the keys we can now convert it to hex to have our flag.

```
157 172 157 145 65 84 219 5 45 124 225 161 16 251 179 170
```

We can use cyberchef to convert it from decimal to hex.
![image](https://user-images.githubusercontent.com/113513376/229288944-c77d1310-3021-4468-b724-96f8ef01a66f.png)

That's our flag.

```
Flag: picoCTF{9dac9d914154db052d7ce1a110fbb3aa}
```

### Reverse Engineering

#### Virtual Machine 0
![image](https://user-images.githubusercontent.com/113513376/229289003-8ec5f39e-2bb0-41d9-af2b-d0932a47e409.png)

We we're given two files to download The first one is the dae file which we can use blender on it to view in 3D while the second one is an input.txt files that contain numbers which lead to the flag but we have to multiply it by another number and it only the dae files that can give us the number to multply with the input files number.
![image](https://user-images.githubusercontent.com/113513376/229289018-6b22e85f-f10b-4de4-b417-0118fd51dc14.png)

This is what it look like after opening it with blender so all we have to do is try to open it and see what is inside the red axles and blue axles.
![image](https://user-images.githubusercontent.com/113513376/229289036-2c8ce06e-9280-4d2e-a520-49074c1e96dd.png)

So I decided to delete the black blocks to show the red axles and the blue axles from there I counted all the whole tooth in red axles which is 40 in total and also counted the blue axles tooth which 8 then I divide it as 40 divided by 8 and it gave me 5.
![image](https://user-images.githubusercontent.com/113513376/229289052-e0ce75eb-752a-45d7-84bd-3c8747596e10.png)

I multiply the input.txt file which is the bigger number by 5 we got  and I indicate it the input as c it was the input given on the challenge. All we have to do is convert our final number to binary and then decode from binary which will gave us the flag.
![image](https://user-images.githubusercontent.com/113513376/229289069-2fc9e9ef-3005-4834-8044-6675561d309c.png)

We have convert it to binary all left is to decode from binary to get the flag.
![image](https://user-images.githubusercontent.com/113513376/229289084-5b8b008a-2b2e-4980-ab41-888cb6b10da3.png)

Boom and that's our flag right there.

```
Flag: picoCTF{g34r5_0f_m0r3_3537e50a}
```

#### Virtual Machine 1
![image](https://user-images.githubusercontent.com/113513376/229289112-51206ca0-ae8c-47f8-8197-c9f60db3c749.png)

Virtual Machine 1 is more complicate than the first one. I spent a lot of time to get this and as you can see we we're give an instance so let connect to the server and see what it does and download the file given which is also a dae file.
![image](https://user-images.githubusercontent.com/113513376/229289120-0119bca5-cbbb-4dcc-bfe9-5179f8a8acc1.png)

As we can see we we're given an input number which is 11277  and the number do change because when you restart the instance and connect to the server it will bring another number so you might see some change sin number while making the writeup now  let  look through the dae file to get the number we can multiply it with.
![image](https://user-images.githubusercontent.com/113513376/229289132-392a4e8e-45a8-49ba-9bbe-e1980f440822.png)

This is how virtual machine 1 look like kinda stressful but it part of learning so I went to google and search about how to calculate the ratio between three adjacent gear and I found a website that help out [link](https://clr.es/blog/en/steps-to-calculate-a-gear-ratio/)  in 1 rotation of the axel will result in how many total rotations of the gears that is how  I found out the number to be 9359 I actually use a pen and piece of paper to do the calculation which is really stressful for me. so let multiply the number of the input with the number we got. 
![image](https://user-images.githubusercontent.com/113513376/229289155-c2a7d19e-85b8-4fc7-9631-fbf0475a7193.png)

The instance die and I restart it that is why the number change from 11277 to 8010 so by multiplying 8010 by 9359 gave us 74965590 which will be the answer we will provide to the server. 
![image](https://user-images.githubusercontent.com/113513376/229289167-b965e32f-2757-4942-ab3e-14928ef245ec.png)

There goes our flag.

```
Flag: picoCTF{m0r3_g34r5_3g4d_1fe58bda}
```