first i open the ghidra and get the code of a.out and i get this
```
ulong main(void)

{
  int iVar1;
  uint uVar2;
  undefined auVar3 [16];
  undefined input [16];
  char *check_str;
  
  printf("Flag: ");
  __isoc99_scanf("%15s",input);
  auVar3 = pshufb(input,SHUFFLE);
  auVar3 = CONCAT412(SUB164(auVar3 >> 0x60,0) + UINT_0010406c,
                     CONCAT48(SUB164(auVar3 >> 0x40,0) + UINT_00104068,
                              CONCAT44(SUB164(auVar3 >> 0x20,0) + UINT_00104064,
                                       SUB164(auVar3,0) + ADD32))) ^ XOR;
  check_str._0_4_ = SUB164(auVar3,0);
  check_str._4_4_ = SUB164(auVar3 >> 0x20,0);
  iVar1 = strncmp(input,(char *)&check_str,16);
  if (iVar1 == 0) {
    uVar2 = strncmp((char *)&check_str,EXPECTED_PREFIX,4);
    if (uVar2 == 0) {
      puts("SUCCESS");
      goto LAB_00101112;
    }
  }
  uVar2 = 1;
  puts("FAILURE");
LAB_00101112:
  return (ulong)uVar2;
}
```

and the main assembly code
```        
        001010ae 66 0f 6f        MOVDQA     XMM0,xmmword ptr [RSP]=>input
                 04 24
        001010b3 48 89 ee        MOV        RSI,RBP
        001010b6 4c 89 e7        MOV        RDI,R12
        001010b9 ba 10 00        MOV        EDX,16
                 00 00
        001010be 66 0f 38        PSHUFB     XMM0,xmmword ptr [SHUFFLE]                       = 
                 00 05 a9 
                 2f 00 00
        001010c7 66 0f fe        PADDD      XMM0,xmmword ptr [ADD32]                         = DEADBEEFh
                 05 91 2f                                                                    = FEE1DEADh
                 00 00                                                                       = 67637466h
                                                                                             = 13371337h
        001010cf 66 0f ef        PXOR       XMM0,xmmword ptr [XOR]                           = 
                 05 79 2f 
                 00 00
        001010d7 0f 29 44        MOVAPS     xmmword ptr [RSP + check_str],XMM0
                 24 10
        001010dc e8 4f ff        CALL       strncmp                                          int strncmp(char * __s1, char * 
                 ff ff

```
so first it gonna mov the input into xmm0 register (a 128 bit register) and do shuffle, doing addition and then xor with the input.
And then use it to do strncmp with the input
I notice that the first 4 char of the input have to be "CTF{" and the last char have to be "}".
And the output have to be equal to the input.

It checked this table for shuffle
```locations = [2, 6, 7, 1, 5, 11, 9, 14, 3, 15, 4, 8, 10, 12, 13, 0]```. And do ```result[i] = (location[i] & 0x80) ? 0 : inp[location[i] & 15];```(&15 
mean we only care about 1 byte).

But the output have to be equal to the input. So my idea is that first input "CTF{0000000000}". And given that input, i check the XMM0 register after PXOR instruction.
From the shuffle location, i know that given that input, after shuffle and do xor the location of the output is the location for the right input. 

For example: The "}" at the end got shuffle to the location 7, "{" got shuffle to location 6. 
So after the first input, the output the xmm0 register after pxor is "C?i{P?MDf0?fw}"j".
The output of the location 6 and 7 is "M" and "D" so with that we got the next input, repeat the process until u find the flag.

To check the XMM0 register, i use gdb, so i write a python script to print out the output every process and then get that input into the next input.
You have manually input it after each run.
```
#!/usr/bin/gdb -x

import gdb
from Crypto.Util.number import long_to_bytes
import string

break_addr = 0x5555555550dc
locations = [2, 6, 7, 1, 5, 11, 9, 14, 3, 15, 4, 8, 10, 12, 13, 0]
char = gdb.lookup_type('char')
integer = gdb.lookup_type('long long')

input_str = ['0' for i in range(0, 16)]
input_str[0] = 'C'
input_str[1] = 'T'
input_str[2] = 'F'
input_str[3] = '{'
# input_str[4] = 'S'
# input_str[5] = '1'
# input_str[6] = 'M'
# input_str[7] = 'D'
# input_str[8] = 'f'
# input_str[9] = '0'
# input_str[10] = 'r'
# input_str[11] = 'M'
# input_str[12] = '3'
# input_str[13] = '!'
input_str[14] = '}'
final_str = ['0' for i in range(0, 16)]

def read_reg(reg: str):
    return gdb.parse_and_eval(f"${reg}")

def get_char_array(array_addr, index):
    return int(gdb.Value(array_addr + index).cast(char.pointer()).dereference())

def is_correct_char(result_str: str, check_bytes: bytes, index: int):
    if chr(result[index]) == result_str:
        return True
    return False

def gdb_run_with_stdin(input_pwd: str):
    with open('./input.txt', 'w') as f:
        f.write(input_pwd)

    gdb.execute('run < input.txt')

if __name__ == '__main__':
    gdb.execute('file ./a.out')
    gdb.execute(f'break *{break_addr}')
    gdb_run_with_stdin(str(''.join(input_str)))
    xmm0 = read_reg("xmm0")

    v = f"{xmm0['uint128']}"
    result = long_to_bytes(int(v))[::-1]
    print(result)
    gdb.execute('quit')
```

The final flag is: `CTF{S1MDf0rM3!}`
