import string
ct = []
for i in string.ascii_uppercase:
    for j in string.ascii_uppercase:
        ct.append(f'{i}{j}')

insec = 'SWPNPDPFLVAOLNSXPHSQPIEOPAIDENLXHXEHIFLKPGLRHUARSTLQEEEPSUIHPDLSPEAOICLOSQEMLPPALNIBIAERHZLKHXEJHYHUEIEHELEEEKEG'
insec = 'PFLXLSTBLKHYLPLRHUEHIEEGEEARLQPLIHIAEKAOSTLVEOSQPDHZLNPAICIFEREJLKEMENHUHXIBEPEEEHEIEL'
insec = 'EKTDROREHXHURHRKRMCXEEKPRNKKUZPNLXNYNOHYAONRNUNWRJSQGZNXGUNTIHKIJYEHPAKBHTKEKGKDLKJVKHKFERGSGIEIHUGLEDGOGQGNEEGFGRGP'
out = '4;139.155.68.77;119.45.114.92;162.62.63.154;3.132.215.40'

dec = ''
for i in range(0, len(insec), 2):
    cur = insec[i:i+2]
    idx = ct.index(cur)
    mod_cnt = idx // 0x5e
    _sum = (idx + (mod_cnt * -0x5e) + 0x20) & 0x7f
    dec += chr(_sum)

print(dec)
