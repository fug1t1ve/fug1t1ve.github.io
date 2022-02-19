---
layout: post
titile: "FridaLab"
date: 2022-02-19 14:30:00 +5:30
categories: Frida,Android,Reversing
---
# FridaLab

created by [Ross Marks](http://rossmarks.uk/blog/)

The app is similar to bomblabs it contains challenges suitable for a frida beginner to learn how the basics of frida works

[Download](https://rossmarks.uk/blog/fridalab/)


## Emulator
I prefer using [Genymotion(Windows 10 with virtualbox)](https://www.genymotion.com/download/) 

## Frida installation
- `pip install frida-tools`
- After installing frida-tools run the virtual anroid device 
- Then use `adb start-server` to start adb server then connect to the device `adb connect ip:port` (it automatically detects the device )
- You can see your device using `adb devices`
- Now Download Frida-server from [here](https://github.com/frida/frida/releases) for android (`frida-server-VER_NUM-android-x86.xz`)
- Unzip the server `unxz frida-server.xz`
- Then push ,set perms and run frida-server : 
    - `adb push frida-server /data/local/tmp/`
    - `adb shell "chmod 755 /data/local/tmp/frida-server"`
    - `adb shell "/data/local/tmp/frida-server &"`

## Getting Started
- Now your frida env is setup we can go ahead and install the apk and start tracing
- To install use `adb install fridalab.apk`
- To start tracing `frida -U -f uk.rossmarks.fridalab`
- Once you run the above commands you will get the frida shell: [img]
- do `%resume` as it is debugging and will stop at "start" and the classes are not declared
- You can follow the above commands for any application you are debugging

## Decompiler
[jadx](https://github.com/skylot/jadx) - Dex to Java decompiler


## Challenges
- Challenge01: Change class challenge_01’s variable ‘chall01’ to 1
- Challenge02: Run chall02()
- Challenge03: Make chall03() return true
- Challenge04: Send “frida” to chall04()
- Challenge05: Always send “frida” to chall05()
- Challenge06: Run chall06() after 10 seconds with correct value
- Challenge07: Bruteforce check07Pin() then confirm with chall07()
- Challenge08: Change ‘check’ button’s text value to ‘Confirm’

## Writeup

### Challenge01:
### Challenge02:
### Challenge03:
### Challenge04:
### Challenge05:
### Challenge06:
### Challenge07:
### Challenge08:

