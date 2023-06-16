---
layout: post
titile: "BluStealer - Malware Analysis"
date: 2023-06-16 14:00:00 +5:30
categories: Malware Analysis
---

# BluStealer

## Overview

The malware used here is categorised as a trojan with the label 'trojan.msil/stealer' and family labels 'msil', 'stealer', 'ratx' on VirusTotal. In MalwareBazaar it is indentified as 'BluStealer'.

BluStealer is a information-stealing malware that contains the functionality to steal login credentials, documents, cryptocurrency, and more sensitive data stored in a PC. Usually the harvested data is then returned to attacker via SMTP or the Telegram Bot API.

Source: [MalwareBazaar](https://bazaar.abuse.ch/sample/dafbb2a0e6111947e20d5916eae5c2a56937dec2c6c4e1843ce29ceefd22f205/)

Source: [VirusTotal](https://www.virustotal.com/gui/file/dafbb2a0e6111947e20d5916eae5c2a56937dec2c6c4e1843ce29ceefd22f205/detection)

`SHA256 hash: dafbb2a0e6111947e20d5916eae5c2a56937dec2c6c4e1843ce29ceefd22f205`



## Preliminaries

![](https://imgur.com/gallery/akYu7hq)
PE Detective identifies the executable as a .NET, 32-bit executable. Further Analysis using PEstudio reveals that the name of the binary during development was 'iENI.exe'; however, this can be tampered with. It also has a compiler timestamp `Thu Apr 27 03:12:03 2023`.
![](https://imgur.com/gallery/M7la8Pz)

The resources section reveals that there is a resource named `Gastroenterology.Properties`, which has exceptionally large entropy and high file-ratio. Large entropy indicates that the file is likely to have compressed or encrypted data.
![](https://imgur.com/gallery/6jg5YsE)

The resource section also reveals that there are few repeating bytes like `PAD`, which indicates that there may be junk data has been added as padding to make the reverse-engineering the binary hard.
![](https://imgur.com/gallery/0co9EX6)

## Part-1: iENI
Loading the file into the [dnSpyEx](https://github.com/dnSpyEx/dnSpy) loads up the different namespace sections of the files. At entry point we see multiple obfuscated function names, one of those obfuscated functions is using `Application.Run()`. This function is used two times in the `main()`, which results it to run two new instances of `frm_Splash` and `frm_Menu`.
![](https://imgur.com/gallery/XPn2LYh)

On analysis of the class `frm_Menu`, it seems to be a decoy class. It acts as a menu to initialize forms like `frm_Sudoku`, `frmJogoMemo`, `frm_Velha`, and more.
![](https://imgur.com/gallery/Y6yOj1a)

On the other hand, `frm_Splash` has 29 encrypted strings. On further analysis it shows that these 29 strings are then concatenated behind '4D5' and all the '^' characters are replaced by '00'. The final string is then parsed using `byte.Parse()` and then stored in an array. The byte array is then passed to a function in `Assembly` class. By looking at strings it seems the first function is [`Assembly.load()`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load?view=net-7.0) and the second is the [`Assembly.CreateInstance()`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.createinstance?view=net-7.0).

In short, it takes that encrypted hard-coded string and decrypts it using the steps mentioned above and then parses the string into a byte array and then loads it into the memory and creates an instance. The instance created passes an array object called `PES`, that is defined as a string array consisting of three entries:
![](https://imgur.com/gallery/5JXM6Jw)

The first two bytes of the byte array indicates that it is a DOS MZ executable.

## Part-2: Pend.dll

When analysing the file that consists of the byte array using PEstudio, it shows that it is a DLL file named "Pend.dll". PEstudio also reveals that it uses SmartAssembly .NET obfuscator to obfuscate the file, and that it was compiled on April 26th 2023.
![](https://imgur.com/gallery/1JbFjL3)

The [de4dot](https://github.com/de4dot/de4dot) is a commonly used tool to deobfuscate the SmartAssembly .NET obfuscated binaries.

The main method of this binary consists of a lot of decoy code but there is one thing noteworthy, a call to a method named `s6`. The method takes three strings as arguments string_0, string_1, string_2. These three strings are the strings that the original binary passes to the DLL when an instance is created.
![](https://imgur.com/gallery/YPPFKpz)

<a id="Munoz_Himentater"></a>
The `s6` method creates an instance of the returned value from the `Xe` method, specifically of type 'Munoz.Himentater'.
![](https://imgur.com/gallery/d8ofXa2)

Examining the `Xe` method reveals a large byte array which is Gzip decompressed using the `Xs` method.
![](https://imgur.com/gallery/AmrlY8r)
![](https://imgur.com/gallery/f8Dweoc)

## Part-3: Cruiser.dll

On decompressing the Gzip data, another DLL file is revealed. On analysing it using PEstudio, it is revealed that it also utilises the SmartAssembly .NET obfuscator. It also reveals that it had a name 'Cruiser.dll' and that it was compiled on April 10th 2023.
![](https://imgur.com/gallery/cjBZvcy)

Repeating the same steps with de4dot gives us the deobfuscated binary. On deompiling, it reveals a namespace 'Munoz', which has a class 'Himentater'. If you recall from last section that int the `s6` method it takes the returned value of the `Xe` method of type 'Munoz.Himentater'.
[click-here](#Munoz_Himentater)

![](https://imgur.com/gallery/d8ofXa2)

The `s6` uses a method 'CasualitySource' with the string_0 and string_1. On analysing the `CasualitySouce` method, it reveals that it converts hex given to its raw ASCII format using `smethod_1`. Based on this string_0 is "PrVE" and string_1 is "lth".
![](https://imgur.com/gallery/E5kilbT)
![](https://imgur.com/gallery/4MpsLkT)

## Part-4: Extracting another DLL

![](https://imgur.com/gallery/d8ofXa2)
On following the `s6` method, it returns a bitmap from the method `Fu`. The `Fu` method uses string_0 and string_2 as the arguments. On analysis, the targeted resource is "Gastroenterology.Properties.Resources.PrVE", which is in the initial binary(iENI).

Now for extracting the bitmap follow these steps:
- Save the resource as a raw file through the dnSpy as shown below:
![](https://imgur.com/gallery/2RqhTbt)
- Now we have to subtract the height and width of the bitmap by 150 pixels.
```py
# Imports
from PIL import Image
import codecs
# main
im = Image.open('PrVE.bmp', 'r')
cropped = im.crop((0, 0, 561, 561))
cropped.save("out.bmp")
```

The cropped bitmap is then passed into a method `VP`:
![](https://imgur.com/gallery/8vfazR4)
- It extracts the ARGB pixel values from the bitmap and store them in a byte array in little endian format
- It takes the first 4 bytes and convert them to int32
- Then it initialises a byte array with a size of the int32 generated
- It copies the byte array (consisting of the RGBA pixel values) from the 5th byte into the new byte array
- Python implementation of the function `VP`:
```py
def VP(bitmap):
    width = bitmap.width
    num2 = width * width * 4
    arr1 = bytearray([0] * num2)
    num = 0
    for i in range(width):
        for j in range(width):
            pixel_color = bitmap.getpixel((i, j))
            byte_array = bytearray([pixel_color[2], pixel_color[1], pixel_color[0], pixel_color[3]])
            arr1[num:num+4] = byte_array
            num += 4
    num3 = int.from_bytes(arr1[:4], byteorder='little', signed=True)
    array2 = arr1[4:num3+4]
    return array2
array2 = VP(cropped)
```

The byte array extracted from `VP` method is then fed to `SearchResult`.
The `SearchResult` function is in the `cruiser.dll` under namespace `Munoz` and class `Himentater`.
![](https://imgur.com/gallery/tqzefRV)

The `SearchResult` method performs the following actions:
- It takes two parameters a byte array and a string, the string passed to this function is the string_1 ("lth").
- It calculates `num` by performing a bitwise XOR between last element of byte array and `112`.
- Intializes a byte array of size len(byte array) + 1
- It then iterates over each element of the byte array and perform bitwise XOR between the current element, `num`, and the corresponding element from the string at index `num2`.
- `num2` ranges from 0-2, it repeats after 2
- The value obtained after bitwise XOR is storred in a new byte array `array`.
- The last element of the `array` is then removed and byte array is returned.
- Python implementation of the function:
```py
def search_result(binary_compatibility, opcode):
    bytes = codecs.encode(opcode, 'utf-16be')
    num = binary_compatibility[-1] ^ 112
    arr1 = bytearray([0] * (len(binary_compatibility) + 1))
    num2 = 0
    for i in range(len(binary_compatibility)):
        num3 = binary_compatibility[i] ^ num ^ bytes[num2]
        arr1[i] = num3
        if num2 == len(opcode) - 1:
            num2 = 0
        else:
            num2 = num2 + 1
    arr1 = arr1[:len(binary_compatibility) - 1]
    return arr1

array3 = search_result(array2, "lth")
f = open('final-b','wb')
for element in array3:
    f.write(element.to_bytes())
f.close()
```

The byte array returned from `SearchResult` is another binary which is executed.

## Part-5: Discompard.dll

The binary was initially named Discompard.dll. It has a description of "Plant Scientist," and the compiler timestamp is April 27th, 2023. The PEstudio shows that it doesn't use any tooling, i.e., it is not obfuscated. 
![](https://imgur.com/gallery/zgRiGaj)

de4dot suggests opposite, it shows that it uses an unkown obfuscation method.
![](https://imgur.com/gallery/xQADOpH)

On decompiling we see a namespace `TOfEQkKANJxMeS2a9c`, which has a lot of classes, enums, and structs. As the names are all random strings, it is hard to figure out the workflow of the binary. There are few exceptions like `LoadLibraryA` and `GetProcAddress`.

In the `s6` method the binary is loaded dynamically into the memory and within the function `YJ` of class `VP`, the 20th element is accessed followed by the invocation of 29th method.
```ps
$pathtodll = "C:\Users\IEUser\Desktop\Win32\blustealer\final.dll"
Add-Type -Path $pathtodll
$classtype = [Reflection.Assembly]::LoadFrom($pathtodll).GetTypes()[20]
$classtype.GetMethods()[29]
```
By Reflectively loading the module, the 29th method of the 20th element can be tracked:
![](https://imgur.com/gallery/cQbTPIy)

The method `TOfEQkKANJxMeS2a9c.kHaSXGF4djgFPmfQAx.nqk5uYnWxJ()` accesses the ApplicationData folder, which in itself is suspicious.

The function names are obfuscated and hard to analyse statically.

### Dynamic Analysis

Preliminaries to debug the Discompard.dll:
- Load the original malware into dnspy
- Set a breakpoint in `System.Reflection.MethodBase.Invoke()` in mscorlib.dll
![](https://imgur.com/gallery/mhRBq8m)

- Now, keep hitting the breakpoint and stepping out until you see that you have reached the method `TOfEQkKANJxMeS2a9c.l9KiV7K6JPwQWv7jdq0.bMBAzEBKcC()`. (Before reaching this method, when you step out, it doesn't actually step out and hits the breakpoint again).
![](https://imgur.com/gallery/pVWr8Wd)

- The above method makes the dnspy to load the Discompard.dll, which you can access using Assembly explorer on the left.
- Now set a breakpoint at `TOfEQkKANJxMeS2a9c.kHaSXGF4djgFPmfQAx.nqk5uYnWxJ()` and remove the breakpoint from System.Reflection.MethodBase.Invoke().
![](https://imgur.com/gallery/pm8HmQ0)

On line 358, `text2` is assigned the value of "C:\Users\IEUser\AppData\Roaming", and the next line stores "C:\Users\IEUser\AppData\Roaming\IvsnIzxmCcG.exe" in `text3`. 
![](https://imgur.com/gallery/R0R3ner)

On checking the hashes of both the original malware and this new binary created it seems to be the same. The malware is copied into the ApplicationData folder
![](https://imgur.com/gallery/z7big38)

The `text3` is then used by four methods:

- `kHaSXGF4djgFPmfQAx.hUX5m2eiwn(text3)` accesses the [DirectorySecurity](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.directorysecurity?view=net-7.0) class, which indicates it is modifying the permissions of the copied malware
![](https://imgur.com/gallery/eFuJU4M)
- `nWOObEDFiUid9AkLujp.lsLX4PlyF(text, text3, nWOObEDFiUid9AkLujp.sCDD0X6OXV)` confirms the suspicion as it uses System.IO.file.copy()
![](https://imgur.com/gallery/m1MSdz2)
- `kHaSXGF4djgFPmfQAx.irt5FtGhEP(text3)` also seems to access the [DirectorySecurity](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.directorysecurity?view=net-7.0) but in this method it can be seen that it is modifying various permissions like Read, ReadAndExecute, Delete, Write, and many more.
![](https://imgur.com/gallery/Hgf1dLB)
- `kHaSXGF4djgFPmfQAx.NA75tJjKiO()` generates a xml file:
```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2014-10-25T14:27:44.8929027</Date>
    <Author>MSEDGEWIN10\IEUser</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>MSEDGEWIN10\IEUser</UserId>
    </LogonTrigger>
    <RegistrationTrigger>
      <Enabled>false</Enabled>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>MSEDGEWIN10\IEUser</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\IEUser\AppData\Roaming\IvsnIzxmCcG.exe</Command>
    </Exec>
  </Actions>
</Task>
```
On line 145, the function uses "schtasks.exe" along with a command `/Create /TN ""Updates\IvsnIzxmCcG"" /XML ""C:\Users\IEUser\AppData\Local\Temp\tmp75E.tmp""`.
This registers a scheduled task
![](https://imgur.com/gallery/M9dpdNY)

In short, the above four functions copy the malware into the ApplicationData folder and set special permissions. The last function sets a scheduled task to run this copied malware.

The function `TOfEQkKANJxMeS2a9c.XJFGg9hoWsSBpIk5r2.U2PbPKIghF()` returns another binary, which is later injected into a process.
![](https://imgur.com/gallery/yFXlPEs)

## Part-6: DL_NATIVE_BOTNET1209

PEstudio shows that:
![](https://imgur.com/gallery/ikl26aL)

- It uses Visual Studio MASM and the file-type executable, which implies that it is not a .NET binary
- description is cuspated
- It was compiled on 25th Oct, 2022
- SHA256 - 52BA984A39D1A2221A044A79C6043F6C547ABAC96B074E457E90671B39F83F4B
-  It seems to have a URL `https://api.telegram.org/bot`
![](https://imgur.com/gallery/fPtgV0I)

On uploading to Virustotal, it labels it as a `virus.expiro/moiva`. [click-here](https://www.virustotal.com/gui/file/52ba984a39d1a2221a044a79c6043f6c547abac96b074e457e90671b39f83f4b/summary)

### Static Analysis

The malware seems to be storing some suspicious strings like:
- "CryptDuplicateKey" and "mpRetrieveMultipleCredentials" suggests that the malware is utilising the wincrypt.
- "kernel32.dll" handles the memory usage and "Shell32.dll" contains Windows Shell API functions, which are used when opening web pages and files.
- "HKEY_CURRENT_USER\\SOFTWARE\\VB and VBA Program Settings\\Settings\\GetCOOKIESreg" suggests it either writes or reads some settings.
- "https://api.telegram.org/bot" is used with "/sendMessage?text=&chat_id=" and "/sendDocument?chat_id=", which implies it is contacting to a telegram user and also sending some files.
- Then few other strings indicates that it is reading the username, compname and many more information about the pc.
- Other strings are random strings or hex-strings, which might be decrypted later in the malware.
![](https://imgur.com/gallery/LY24xRl)

### Dynamic Analysis

Process Monitor results:
- It utilises NTDLL, which contains NT kernel functions.
- It uses registry to perform operations like RegQueryValue, RegSetInfoKey, and RegQueryKey.
- One noticiable registry was `Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`
- It has few registry keys related to socket being used
- It also contacts to `72.5.161.12:http`, `mail410.us2.mcsv.net:http`, `206.191.152.58:http`, `63.251.106.25:http`, `167.99.35.88:http` through TCP.
- Most of these TCP connections are preceded by various queries to explorer.exe like QueryStandardInformationFile, QueryBasicInformationFile, QueryDirectory, ReadFile, CreateFile
- It also seems to be using multithreading to perform all these actions
![](https://imgur.com/gallery/5fdlzlo)

Debugging:
The `sub_4fb000` seems to be modifying a huge array:
![](https://imgur.com/gallery/4d2HLT5)

The function `sub_4b79b8` is responsible for loading DLLs such as NTDLL and Kernel32 into the memory. 

`sub_4640c4` begins by invoking five functions from the MSVBVM60 library, which are specific to the VB6 runtime and are likely responsible for handling various aspects of the Visual Basic 6.0 environment. `sub_4640c4` proceeds to call another function called `sub_468341`.

The `sub_468341` function has few suspicious DLL calls:
![](https://imgur.com/gallery/3FW0CwC)
- `sub_462068` - It calls the `shell32.SHGetSpecialFolderLocation`, which returns PIDL of a special folder
![](https://imgur.com/gallery/hJEzxQK)
![](https://imgur.com/gallery/KMdafVg)

- `sub_4620b8` - It calls the `shell32.SHGetPathFromIDListA`, which retrieves the path of a shell namespace object identified by its PIDL.
![](https://imgur.com/gallery/jgHV8J7)
![](https://imgur.com/gallery/szu1cFu)

The path "C:\Users\IEUser\AppData\Roaming\Microsoft\Windows\Templates" after few string operations is returned by the `sub_468341`:
![](https://imgur.com/gallery/ufFZOhP)

Few more string operations are performed on the returned path string. The modified path string is "C:\Users\IEUser\AppData\Roaming\Microsoft\Windows\Template\" (concatenated '\').
![](https://imgur.com/gallery/8Cg2aLX)

After few more function calls from the MSVBVM60 library, the `sub_46869E` function is called. 

The `sub_46869E` function takes three arguments, one of which is a pointer to an address, while the other two arguments are "GetCOOKIESreg" and "HKEY_CURRENT_USER\SOFTWARE\VB and VBA Program Settings\Settings".
![](https://imgur.com/gallery/jErO0mf)

In `sub_46869E`:
- The `sub_46853c` is called with "21AB900E8F90FA8FEC46B6EECE" as the argument. It converts the hex string to BSTR. BSTR strings are represented as Unicode strings, using two bytes per character. This BSTR is returned.
![](https://imgur.com/gallery/4ij3Csc)
- The `sub_468D3a` uses the BSTR("21AB900E8F90FA8FEC46B6EECE") and "AfzZZiYOhxgugZpWKhFfrXlnUzmtlItt" as arguments.
![](https://imgur.com/gallery/Fq01vWw)
- It copies the "AfzZZiYOhxgugZpWKhFfrXlnUzmtlItt" 8 times and stores at the address `0x0A21150`. 
- The memory address `0x0A20648` contains 256 bytes arranged in ascending order from 0 to 255.
- In the next loop, it performs this operation:
```c
*(0x0A20648+index) = (*(0x0A20648+index) + *(0x0A20648+index-1) + *(0x0A21150+index))%256
```
- The third loop uses this modified array and performs the XOR operation and generate the string "WScript.Shell" and the function `sub_468D3a` returns this string.
![](https://imgur.com/gallery/15T4XBf)

- The returned string is passed to the CreateObject, which creates a WScript Object that provides access to root object for the Windows Script Host object model (**wshom**).
![](https://imgur.com/gallery/6uDBBOK)

- Using the **wshom** object, the [RegRead](https://www.vbsedit.com/html/1b567504-59f4-40a9-b586-0be49ab3a015.asp) method is called, which returns the value of a key or value-name from the registry. The arg passed is "HKEY_CURRENT_USER\\SOFTWARE\\VB and VBA Program Settings\\Settings\\GetCOOKIESreg".
![](https://imgur.com/gallery/6Qy3IrF)

Following the `sub_46869E` call, there are a few checks that are followed by the function `sub_46A085`.
In `sub_46A085`:
- `sub_468341` [function explained above](#L324) generates and returns the path "C:\windows".
![](https://imgur.com/gallery/ei4hLFQ)
- After few string concatenation and few other operations, string is modified into "C:\windows\Microsoft.NET\Framework\v4.0.30319".
- This string is passed to the `rtcDir` function, which returns the string of file or directory name in the directory.
- After a comparison, it performs the same set of instructions until the string concatenation, where it concatenates "\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe" this time, resulting in "C:\windows\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe".
- The `sub_46A275` calls the function `sub_469578`, which has multiple DLL function calls
- In `sub_469578`:
  - The `sub_462000` calls RtlMoveMemory, which copies the contents of a source memory block to a destination memory block.
  - At start `sub_462000` function is called 2 times
  ![](https://imgur.com/gallery/RB2SEvj)
  - After string concatenation we get the path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe "
  - The `sub_4625C8` calls `kernel32.CreateProcessA` with "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe " as argument
  - The `sub_462614` calls `kernel32.GetThreadContext` with the applaunch path mentioned above as argument
  ![](https://imgur.com/gallery/iaETusv)
  - The `sub_4626A4` calls `kernel32.VirtualAllocEx` with 0x41c as hProcess
  - The `sub_46265C` calls `kernel32.VirtualAlloc` and allocates a virtual memory of size 0x66000
  - MZ headers are copied to addr 0x42E0000 using `sub_462000`
  - There are 2 loops in the function
  - 1st loop copies:
    - .text section to the address 0x042E0000 + X
    - .sdata at 0x4340000
    - .rsrc to the address 0x04342000
    - .reloc at 0x04344000
  - 2nd loop modifies few bytes in the memory 0x42E0000
  - The function then copies the 0x042E0000 to the virtual memory and calls `kernel32.SetThreadContext` and then the thread is resumed
  - The address 0x042E0000 stores a PE file

## Part-7: Stealer

### Retrieved binary
Virustotal:
- The VirusTotal labels the file as a trojan, and this file is flagged malicious only by 21/71 security vendors.
- MD5 : `01db414e65602506c94c2b583243a60`
- It is a PE32 executable Mono/.Net assembly
- It shows Dot Net Assembly name : 3.exe and CLR version v4.0.30319, which is the version of framework previous binary uses to execute this binary.

On analysing the binary using de4dot, it shows that it is not a .NET binary. The binary is obfuscated/encrypted when loaded into AppLaunch.exe. To obtain the non-obfuscated binary, set a breakpoint at address 0x469946. At this address, the pointer to the original binary is stored in eax and pushed to the function VarPtr, which returns the pointer.
In this case, the binary starts at address 0x009CBD70 and ends at 0x00A2BA70.

This encryption is done in the `sub_469578` function.

### 3.exe
MD5: `52756994e44514f825f435819cb9f4d5`
The PEstudio reveals that it is a 32-bit executable .NET binary. It also reveals that it was earlier named 3.exe and the manifest name was MyApplication.app.
![](https://imgur.com/KmkuYET)

VirusTotal:
- The VirusTotal labels the file as a `trojan.msil/stealer`, and this file is flagged malicious by 55/69 security vendors. 34 more vendors were able to detect it, so it seems the encryption/obfuscation was able to bypass few vendors.
- It also has labels like spyware, dropper, and injectorx, which deliver and install other malicious components onto a targeted system.
- MD5: `52756994e44514f825f435819cb9f4d5`
- It is a PE32 executable Mono/.Net assembly

PE studio reveals a manifest which requests the level `asInvoker`. It gives the application the same privileges as the parent process or the user who launched it.

On anlalysing the original binary with de4dot reveals it uses .NET Reactor to obfuscate.
![](https://imgur.com/gallery/bHg03AD)

In the Main() function, resource named 'app' is used with GZipStream and the decompressed bytes are loaded into the Assembly and then invoked.
![](https://imgur.com/gallery/YqT07Vz)

Set a breakpoint at line 29 of main (In obfuscated binary it is yX3qVQPc7HrPvyJ6nV.cZ6To4JeF1gFLqv7a4.TOsyUfqmE()) and save the array2, which has the assembly.

### ThunderFox
The PEstudio reveals that the retrieved binary is the ThunderFox malware and that it has a modified compiler stamp. VirusTotal shows that this binary was last analyzed three months ago and labels it as a stealer. The de4dot reveals that it utilizes .NET Reactor.

MD5: d2ec533f8b40a8224d79c87c2291f943

On decompilation using dnnpy, we see that there are multiple suspicious namespaces defined:
![](https://imgur.com/gallery/5m5kTI3)

The main function is defined in Class33 of an unnamed namespace ({}-). The main function uses try and catch, which helps the malware in case any exception occurs. It executes an empty block of code, thus doing nothing, not even exiting the program.

Main function:
- Starts by defining 3 null strings `text`, `text2`, and `text3`
- It opens the subkey 'Software\VB and VBA Program Settings\Settings' under the current user's registry hive and stores the values 'GetCOOKIESreg', 'GetCONTACTSreg', and 'GetMessagesreg' in text, text2, and text3 variables, respectively.
![](https://imgur.com/gallery/ltoWG2M)
- It calls `Chromium.Grab()`, which is defined in namespace `ChromeRecovery`:
  - It calls Chromium.LocalApplicationData to retrieve the path "C:\Users\IEUser\AppData\Local\Chromium\User Data", and then appends the 'User Data Directory' for multiple browsers. The resulting path is stored in a dictionary.
  ![](https://imgur.com/gallery/l8JeVrU)
  - For every browser it gets:
    - The master key saved in the '\Local state' folder of browsers using the function chromium.GetMasterKey(), which is subsequently used for decryption by other functions.
    ![](https://imgur.com/gallery/403AMPx)
    - Saved passwords, usernames, and the URLs where they are used are obtained using the Chromium.smethod_0().
    ![](https://imgur.com/gallery/ecvz0bZ)
    - Saved creditcard data by accessing the database located in the '\Web Data' subdirectory of the browser, which includes:
      - Type of creditcard(MasterCard, VisaCard, and Maestro)
      - Name on card
      - Card number
      - Expiry month and year
    ![](https://imgur.com/gallery/VXQ205C)
  - All of this data is appended to `Class33.string_0`
- The method `Class28.smethod_0()`:
  - A few hardcoded paths are stored in an array, representing commonly used registry key paths when working with Outlook profiles.
  - It uses these registry key to get values of:
    ```"SMTP Email Address", "SMTP Server", "POP3 Server", "POP3 User Name", "SMTP User Name", "NNTP Email Address", "NNTP User Name", "NNTP Server", "IMAP Server", "IMAP User Name", "Email", "HTTP User", "HTTP Server URL", "POP3 User", "IMAP User", "HTTPMail User Name", "HTTPMail Server", "SMTP User", "POP3 Password2", "IMAP Password2",	"NNTP Password2", "HTTPMail Password2", "SMTP Password2", "POP3 Password", "IMAP Password", "NNTP Password", "HTTPMail Password", "SMTP Password"```
- It uses Class27 to invoke smethod_0, smethod_1, and smethod_2, which utilize Account.rec0, Account.stg, and Account.tdat respectively. These files are used to retrieve account information such as URL, Username, and Password.
- It then calls the `Class33.smethod_0()`:
  - It uses the registry key "Software\FTPware\CoreFTP\Sites" and iterates through all the subkeys retrieving the corresponging URL, username, and password values for a CoreFTP account. 
  - The password value is decrypted using the `Class33.smethod_1` which basically decrypts using Rijndael ECB.
  ![](https://imgur.com/gallery/beMLrSg)
- The method `Class33.smethod_3()`:
  - retrieves WinSCP sessions using the registry key "Software\Martin Prikryl\WinSCP 2\Sessions". 
  - It iterates through all the subkeys and retrieves the correspondingg hostname, username, and password.
  - The password is decrypted using `WinSCPDecrypt` class.
  ![](https://imgur.com/gallery/8oGj7To)
- It appends all the data returned from methods called above to the `Class33.string_0`
- It calls `Class33.smethod_4`, which is responsible for extracting credentials from all Firefox-related brosers:
  - It stores and interates through browser name and corresponding paths
  - If the "Profiles" directory exists, it iterates through each profile and retrieves the path of `logins.json`, `key4.db`, `signons.sqlite`, and `key3.db` for each.
  - If the browser uses `logins.json` and `key4.db`, it calls `Class32.smethod_0`:
    - Uses the query "SELECT item1,item2 FROM metadata WHERE id = 'password';" to get GlobalSalt and ciphertext+EntrySalt.
    - The second value is parsed through Asn1Der.Parse() and converted to string to detect the encryption algorithm used
    - The encryption algorithm can be detected by checking for two strings: "2A864886F70D010C050103" for the first one, which represents "HMACSHA1", and "2A864886F70D01050D" for the second one, which represents "3DES".
    - It then checks if the master password is ""
    - Then it uses the query "SELECT a11,a102 FROM nssPrivate;", to get ciphertext, EntrySalt, and partIV after parsing it.
    - Ciphertext, EntrySalt, and PartIV, along with the global salt used earlier for the master password check, are used to decrypt using MozillaPBE(), which returns the key.
    - The key is used in `Class32.smethod_1` in conjunction with the `logins.json` file to decrypt the DESCBC-encrypted username and password.
    ![](https://imgur.com/gallery/aQlWgvx)
    - The URL, Username, and Password, along with Application name is stored in `Class33.string_0`.
  - If the browser uses `logins.json` and `key3.db`, it calls `Class30.smethod_0`:
    - The function uses BerkeleyDB and get the global salt and entry salt, which is used to check if the master password is null string.
    - The global salt is used to obtain the key and initialization vector (IV) for DESCBC decryption of a value extracted using BerkeleyDB, excluding cases where `keyvaluepair.key` is "global-salt", "Version", or "password-check".
    - The decrypted value is then returned and utilized in `Class32.smethod_1` as the key for decrypting the DESCBC-encrypted username and password stored in `logins.json`.
    - The URL, Username, and Password, along with Application name is stored in `Class33.string_0`.
  - If the browser uses `signons.sqlite` and `key3.db`:
    - It calls the `Class30.smethod_0`, which performs the same set of operations as above to get the DESCBC key
    - The hostname, encrypted username, and encrypted password are retrieved from `signons.sqlite` using sqliteHandler.
    - For each row, it decrypts the username and password and then stores the hostname, username, password, along with the application name, in `Class33.string_0`.
- The `Class33.string_0` is saved into  the "C:\Users\IEUser\Templates\credentials.txt"
![](https://imgur.com/gallery/oPVfeIS)
- The function then saves the Cookies from all browsers into "C:\Users\IEUser\Templates\Cookies{browser_name}.txt"
  - For firefox-related browsers the cookies are stored in a sqlite db named `cookies.sqlite` for each profile inside `Browser path + "\Profiles"`.
  - For other browsers the cookies are stored in `Browser User Data path + "\Cookies"`, which is also a sqlite db.
  - The difference is that in other browsers, the raw data is encrypted, and the Chromium master key is used to decrypt it. In contrast, in Firefox-related browsers, the data is stored in plaintext.
- The function then saves the Contacts from all firefox-related browsers into "C:\Users\IEUser\Templates\Contacts{browser_name}.txt"
![](https://imgur.com/gallery/YZu8zoi)
  - In the same function, it saves all the MailMaster data and contacts in "C:\Users\IEUser\Templates\ContactsMailMaster.txt"
- The function then saves the Messages from all the firefox-related browsers into "C:\Users\IEUser\Templates\Messages{browser_name}.txt"
![](https://imgur.com/gallery/UPs2W3H)