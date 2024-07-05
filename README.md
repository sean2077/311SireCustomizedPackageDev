# Sire 自定义包开发

Sire1.29 引进了自定义包（Sire Customized Package）的功能，以下为 RK [原文](https://tieba.baidu.com/p/6297758882?pid=127922812804&cid=0#127922812804)：

> **随着311技术普及，越来越多的人可以改代码，因此sire提供了自定义包加载功能，未来各路大神的自定义包都可以以DLC的形式加载，比如火神的功勋解锁特技：**
> ![img](https://imgsa.baidu.com/forum/w%3D580/sign=5162f626b1096b6381195e583c338733/69bb8c13b07eca803e1c08ee9e2397dda04483cc.jpg)
> ![img](https://imgsa.baidu.com/forum/w%3D580/sign=f0590c1d4da7d933bfa8e47b9d4ad194/72dd2612b31bb05107f38521397adab44bede00b.jpg)
> **把自定义包放到相应目录里，就可以使用了，还可以改参数哦~~**![img](https://tb2.bdstatic.com/tb/editor/images/face/i_f01.png?t=20140803)

但这些自定义包的开发基本只在技术圈内大佬之间进行研究，网上关于这方面的介绍少之又少。作为 311+sire 的忠实拥趸，长期享受各位大佬的用爱发电的成果，有时也会冒出一些改进游戏的想法，因此决定自行研究下如何编写 sire 自定义包，并在此记录，以作参考。

（PS：本人有一定编程经验，但对汇编反汇编这块还是小白一枚，一切从1（这个项目）开始，有何不对之处望各位大佬指正）



**主要资源**

- 本项目[311MemoryResearch](https://github.com/sjn4048/311MemoryResearch)是我了解 sire 工作原理的重要来源
- [big-guy-examples](./big-guy-examples/)文件夹中为一些大佬的自定义包，是我制作自定义包的重要参考，感谢各位大佬的辛勤付出。
- [examples](./examples/)中为本教程（姑且称之为教程~）的自制包。



**开发环境**

参考[sjn4048](https://github.com/sjn4048)在项目[311MemoryResearch](https://github.com/sjn4048/311MemoryResearch)中提及的内容，结合自己最近学习开发的一些经验，这里也给一些参考：

- **IDA Pro**：汇编反汇编神器，必装，网上有破解的，在此我就不多介绍了，网上自取。下面为一些我认为比较有用的插件：
  - [HexCopy](https://github.com/OALabs/hexcopy-ida)：IDA 插件，用于快速将反汇编代码复制为编码的十六进制字节
  - 此外，我自己在学习过程中也自己开发了一些 IDA 插件，推荐使用：
    - [hexpaste](https://github.com/sean2077/hexpaste-ida)：用于将Hex码快速拷贝进内存（原IDA里的change bytes一次只能替换16字节，拷贝自己修改的机械码太痛苦了）
    - [big5-decode](https://github.com/sean2077/big5-decode-ida)：将字节以big5字符进行解码，结果添加为 repeatable comment ，支持批量（游戏内存里big5字符串都是存在一段连续的内存的，用这个插件可以迅速对各个字符串添加注释）
    - [make-word-dword](https://github.com/sean2077/make-word-dword-ida)：可以在IDA视图和Struct视图中通过快捷键创建 word 和 double word，这在标记数据或结构体时非常有用（原IDA中的快捷方式真是一言难尽，常用的功能不是缺少快捷键就是有快捷键但按键特别别扭）
    - [311mem_tool](./ida-scripts/311mem_tool.py): san11pk内存地址记录工具，支持：内存地址汇总.md 中的记录导入到 IDA 中; IDA 中的内存地址记录导出到 内存地址汇总.md
    - [311stru_tool](./ida-scripts/311stru_tool.py): san11pk结构体记录工具.
- Cheat Engine：喜羊羊与RK都在用的动态调试神器，可以动态查看运行时的内存。暂时还没用到，因为目前的修改都比较简单。
- Hex WorkShop：用于改.exe，暂时还没用到





## 第零弹：Sire 自定义包的原理

首先明确下 Sire 自定义包的概念：

- 文件名后缀为 scp，放入 sire 的 customize 目录下生效，同名的 scpv 文件为对应的参数配置文件
- scp文件内容一般为 xml 文本，也有一些二进制文件（可能加密过？ TODO: 需找大佬确认）
- sire 的工作原理本质是对 SAN11PK 进程的内存中的机械码和数据进行修改，所以自定义包也是基于这一点，可以看到大佬们的自定义包中的 xml 文件都是描述对内存中的数据进行修改的
- 包中最重要的部分是 `<Codes>` 标签，包含了一系列修改内存的操作`<Code>`, `<Code>`中包含了代码的地址`<Address>`、启用该功能时的机器码`EnableCode`和不启用该功能时的机器码`DisableCode`（大部分情况下为原机器码）。



下面是一个简单的显示武将真实忠诚度包 [显示真实忠诚.scp](./big-guy-examples/显示真实忠诚.scp)的例子：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CustomModifyPackage>
	<PackageName>显示真实忠诚</PackageName>
	<PackageAuthor>龙哥</PackageAuthor>
	<PackageDiscription>显示超过100的忠诚的真实数值</PackageDiscription>
	<CustomModifyItems>
		<CustomModifyItem>
			<Caption>开启</Caption>
			<Enabled>true</Enabled>
			<Codes>
				<Code>
					<Description>代码</Description>
					<Address>004C8A9B</Address><!--长度:5-->
					<EnableCode>B8 64 00 00 00</EnableCode>
					<DisableCode>BE 64 00 00 00</DisableCode>
				</Code>
			</Codes>
		</CustomModifyItem>
	</CustomModifyItems>
</CustomModifyPackage>
```
（疑问：观察到每个`<Address>`后面都有一个长度的注释，实测为非必需，猜测自定包文件是由某编辑工具生成？ TODO: 需找大佬确认）

做的操作是将地址为 004C8A9B 处的机械码 BE 64 00 00 00 用 B8 64 00 00 00 替换，

在[内存资料](../内存资料/)全局搜索 004C8A9B 可以搜到：

```
[命令编号为23：返回武将忠诚度]
004C8A8B - 0f b6 b7 ac 00 00 00       - movzx esi,byte ptr [edi+000000ac]  esi = 忠诚度
004C8A92 - 83 fe 64                   - cmp esi,64
004C8A95 - 0f 8c e4 03 00 00          - jl 004c8e7f
004C8A9B - be 64 00 00 00             - mov esi,00000064
004C8AA0 - 8b c6                      - mov eax,esi                        返回武将忠诚度
004C8AA2 - 5e                         - pop esi
004C8AA3 - 5b                         - pop ebx
004C8AA4 - 5f                         - pop edi
004C8AA5 - c3                         - ret
```

这段汇编代码主要处理的是返回某个武将的忠诚度。我们可以逐行分析它的功能：

1. **004C8A8B - 0f b6 b7 ac 00 00 00 - movzx esi, byte ptr [edi+000000ac]**
   - `movzx esi, byte ptr [edi+000000ac]`：这个指令从`edi`寄存器指向的地址偏移`0xAC`处读取一个字节，并将其零扩展后存储到`esi`寄存器中。这里的`edi`为武将指针，`esi`存放的是武将的忠诚度。

2. **004C8A92 - 83 fe 64 - cmp esi, 64**
   - `cmp esi, 64`：将`esi`中的值（忠诚度）与十六进制的`64`（即十进制的100）进行比较。

3. **004C8A95 - 0f 8c e4 03 00 00 - jl 004c8e7f**
   - `jl 004c8e7f`：如果`esi`中的值小于100（即忠诚度小于100），则跳转到地址`004c8e7f`。`jl`是“jump if less”（如果小于则跳转）的缩写。

4. **004C8A9B - be 64 00 00 00 - mov esi, 00000064**
   - `mov esi, 00000064`：将十六进制的`64`（即十进制的100）赋值给`esi`寄存器。如果前面的比较没有跳转，说明忠诚度不小于100，这里将忠诚度设为100。

5. **004C8AA0 - 8b c6 - mov eax, esi**
   - `mov eax, esi`：将`esi`寄存器中的值（此时的忠诚度值）复制到`eax`寄存器中。`eax`寄存器通常用于函数的返回值，所以这里是将忠诚度值准备好作为返回值。

6. **004C8AA2 - 5e - pop esi**
   - `pop esi`：从栈顶弹出一个值到`esi`寄存器，恢复之前保存的`esi`值。

7. **004C8AA3 - 5b - pop ebx**
   - `pop ebx`：从栈顶弹出一个值到`ebx`寄存器，恢复之前保存的`ebx`值。

8. **004C8AA4 - 5f - pop edi**
   - `pop edi`：从栈顶弹出一个值到`edi`寄存器，恢复之前保存的`edi`值。

9. **004C8AA5 - c3 - ret**
   - `ret`：返回调用函数。这条指令会从栈顶弹出返回地址，并跳转到这个地址，恢复到调用该函数的地方继续执行。

这段代码的功能是读取一个武将的忠诚度，并确保返回的忠诚度不会超过100。如果忠诚度超过100，则将其限制在100以内，然后将这个值返回给调用者。

而我们做的修改是将地址 `004C8A9B` 处的代码改为：

```assembly
B8 64 00 00 00  ; mov eax, 00000064
```
这条指令的含义是：将十六进制的 64 (十进制 100) 赋值给 `eax` 寄存器，而`esi`的值还是原来的，然后下一条将`esi`值加载给`eax`返回，就达到了返回真实忠诚度的作用了。

（PS: 这里实际使得武将忠诚度上限不再是100了，感觉对其他忠诚度的操作如登用武将会有影响，不是很推荐）




## 第一弹：制作一个显示五维和的自定义包

了解了自定义包的原理，接下来实现一个简单的功能：武将列表显示五维和。

要实现该功能，一个是要了解如何在武将列表添加1列，另一个是要了解如何取五维值。



### 首先学习下大佬们的自定义包

我们可以在大佬们的自定义包中找到有类似功能的例子，比如[显示相性、与君主相性差、喜好武将和厌恶武将.scp](./big-guy-examples/显示相性、与君主相性差、喜好武将和厌恶武将.scp)中的代码：

```xml
...
		<CustomModifyItem>
			<Caption>相性差为与玩家势力君主相性差</Caption>
			<Enabled>TRUE</Enabled>
			<Codes>
				<Code>
					<Description>代码</Description>
					<Address>008BD490</Address>
					<EnableCode>40 01 95 00 13</EnableCode>
					<DisableCode>A8 CF 8B 00 07</DisableCode>
				</Code>
				<Code>
					<Description>代码</Description>
					<Address>00950140</Address>
					<EnableCode>01 00 00 00 15 00 00 00 4A 00 00 00 56 00 00 00 2F 00 00 00 49 00 00 00 06 00 00 00 11 00 00 00 0E 00 00 00 6A 00 00 00 6B 00 00 00 6C 00 00 00 6D 00 00 00 6E 00 00 00 6F 00 00 00 70 00 00 00 71 00 00 00 72 00 00 00 73 00 00 00</EnableCode>
					<DisableCode>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00</DisableCode>
				</Code>
				<Code>
					<Description>代码</Description>
					<Address>004C8EBC</Address><!--长度:4-->
					<EnableCode>E0 01 95 00</EnableCode>
					<DisableCode>6A 8A 4C 00</DisableCode>
				</Code>
				<Code>
					<Description>代码</Description>
					<Address>009501E0</Address><!--长度:40-->
					<EnableCode>0F B6 05 D8 1A 20 07 8B 04 85 1C 1A 20 07 50 B9 58 19 20 07 E8 A7 08 B4 FF 8B 40 04 50 8B CF E8 7C 9D B3 FF 5E 5B 5F C3</EnableCode>
					<DisableCode>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00</DisableCode>
				</Code>
				<Code>
					<Description>代码</Description>
					<Address>007ECABC</Address><!--长度:6-->
					<EnableCode>AC DB A9 CA AE 74</EnableCode>
					<DisableCode>A5 40 A5 4E 00 00</DisableCode>
				</Code>
			</Codes>
		</CustomModifyItem>
...
```

通过 **IDA Pro** 分析：

**008BD490** 处为数据段，内容为 A8 CF 8B 00 07，表示一个地址 和 数字7：

![image-20240612145534542](./.assets/image-20240612145534542.png)

其中 unk 意为 unknown，表示该地址类型未知，8BD00C为地址，地址后面的 07 应该表示的是这个数组大小，跳到 8BD00C ：

![image-20240612150620763](./.assets/image-20240612150620763.png)

发现值为：1, 15h(=21), 4Ah(=74), 56h(=86), 2Fh(=47), 49h(73), 6 刚好7个

所以该 Code 的作用就很明显了，将地址为 8BD00C 的大小为 7 的数组地址为 950140 大小为 13 的数组。至于数组的作用，后面再看。



**00950140** 处也为数据段，不过原内容全为0，是原程序没用到的内存，在这里定义了 19 个数，分别为：

01, 15, 4A, 56, 2F, 49, 06, 11, 0E, 6A, 6B, 6C, 6D, 6E, 6F, 70, 71, 72, 73

上述数字为16进制，这里就不转换了，共13h(19)个数，因此这两个 Code 合起来就是替换了一下数组，对比可以发现在原数组的基础上加了12个数，暂时还不知道做什么的。



**004C8EBC**处也是替换东西，只不过替换的不是数组，而是 loc，即 location，可以理解为函数块，004C8EBC存的原函数块的地址为 4C8A6A，

![image-20240612233455467](./.assets/image-20240612233455467.png)

查内存资料可得知这个函数是返回武将世代 ID 的，由于不常用，被替换也问题不大

![image-20240612234207881](./.assets/image-20240612234207881.png)

而用于替换的函数的地址为 **9501E0**， 即为下个 Code 定义的新函数。



**009501E0** 定义了一个新函数，尝试分析下这这段函数的功能：

（PS1：009501E0 实际已经处于 data 段了，一般是不放函数的，一个是需要执行权限，另一个是安全性问题，不过既然是魔改san11，就管不了这么多了）

（PS2：san11pk内存中存在一大块未被使用的部分，可以用来添加自定义的函数或数据，但应注意与其他自定包开发者协调，避免冲突）

新函数的机器码为：

```
0F B6 05 D8 1A 20 07 8B 04 85 1C 1A 20 07 50 B9 58 19 20 07 E8 A7 08 B4 FF 8B 40 04 50 8B CF E8 7C 9D B3 FF 5E 5B 5F C3
```

我们用 **IDA Pro** 工具将这段机器码反汇编（具体工具获取以及如何操作我就不介绍了，网上自取~），得到的汇编代码如下：

根据给定的机器码，重新描述其反汇编结果：

```assembly
0F B6 05 D8 1A 20 07     movzx   eax, byte ptr [07201AD8]
8B 04 85 1C 1A 20 07     mov     eax, dword ptr [eax*4 + 07201A1C]
50                       push    eax
B9 58 19 20 07           mov     ecx, 07201958
E8 A7 08 B4 FF           call    00490AA0   ; Call to GetCountryPtr
8B 40 04                 mov     eax, [eax+4]
50                       push    eax
8B CF                    mov     ecx, edi
E8 7C 9D B3 FF           call    00489F80   ; Call to CalcXiangxingDiff
5E                       pop     esi
5B                       pop     ebx
5F                       pop     edi
C3                       retn
```

1. **`movzx eax, byte ptr [07201AD8]`**

   - `0F B6 05 D8 1A 20 07`：从地址 `07201AD8` 读取一个字节( 从后面的分析看，该字节应存储的是当前选定势力的序号)，并零扩展到 `eax`。

2. **`mov eax, dword ptr [eax*4 + 07201A1C]`**
   - `8B 04 85 1C 1A 20 07`：从地址 `07201A1C` 加上 `eax` * 4 的偏移处读取一个双字（4 字节）到 `eax`。
   - 这里地址`07201A1C`对应内容如下，表示一个长度为 `0CEh`（206 个字节）的字节数组，每个字节初始化为 `0`。`db` 表示定义字节（define byte），`0CEh` 是十六进制数 `206`，`dup(0)` 表示重复初始化为 `0`。

   ![image-20240612163537728](./.assets/image-20240612163537728.png)

   - 这里的`07201A1C`应该是势力 ID 数组，在实际游戏时会为每个势力生成唯一ID。
   - PS：根据这里的限制，最大势力数应为 206/4=51 个？

3. **`push eax`**

   - `50`：将 `eax` 的值压入栈中，即将势力 ID 作为下一个调用函数的第一个参数。

4. **`mov ecx, 07201958`**
   - `B9 58 19 20 07`：将立即数 `07201958` 加载到 `ecx`，这个数字是啥意思暂按下不表。

5. **`call 00490AA0`**

   - `E8 A7 08 B4 FF`：调用 `00490AA0` 处的函数，根据内存资料查得该函数功能为：根据势力ID获取势力指针。该函数详细讲解建后面，最后读到的势力指针存在 `eax` 寄存器 。
   - PS：这里补充下汇编的基础知识，在x86和x86-64架构中，`E8` 是一个短调用（short call）指令的操作码，用于调用相对于下一条指令的跳转偏移位置处的函数或子程序。这里下一条指令的地址是 009501F9，而 `E8 A7 08 B4 FF` 是小端序存储的偏移，实际偏移应为 FFB408A7, 则实际函数位置即 `009501F9 + FFB408A7 = 00490AA0`。

6. **`mov eax, [eax+4]`**
   - `8B 40 04`：将 `eax` 寄存器中地址加 4 的位置的值读取到 `eax`，从后面看，这个取得应该是该势力的君主的ID。

7. **`push eax`**
   - `50`：将 `eax` 的值压入栈中，即将势力的君主ID作为下一个调用函数的第一个参数。

8. **`mov ecx, edi`**

   - `8B CF`：将 `edi` 的值加载到 `ecx`（从后面分析看，这里 `edi` 为当前武将的人物指针）。

9. **`call 00489F80`**

   - `E8 7C 9D B3 FF`：调用 `00489F80` 处的函数, 根据内存资料查得该函数功能为：计算A与B的相性差(push B的ID, ecx=A的指针)，最后函数会往栈中推3个值，具体函数讲解见后面。

10. **`pop esi`**

    - `5E`：从栈中弹出一个值到 `esi`。

11. **`pop ebx`**
    - `5B`：从栈中弹出一个值到 `ebx`。

12. **`pop edi`**
    - `5F`：从栈中弹出一个值到 `edi`。

13. **`retn`**
    - `C3`：从子程序返回。



要完整理解这段代码，还得去读一下其中调用的两个函数。

首先是**00490AA0** 处的函数，其反汇编结果如下：

![image-20240612194139722](./.assets/image-20240612194139722.png)

这段代码是函数 `GetCountryPtr` 的汇编代码，该函数的作用是根据传入的势力ID参数获取一个势力指针。以下是对代码的解释：

1. `GetCountryPtr` 是一个函数，它是一个近函数（near），意味着它是一个本地函数，不会跨越段边界。
2. 首先，通过 `mov eax, [esp+arg_0]` 指令将参数 `this` 存储的地址加载到寄存器 `eax` 中。【PS: 这里解释下为什么`esp+arg_0`就是this参数，`esp`（Extended Stack Pointer）是x86架构中的一个特殊寄存器。它主要用于管理栈操作。在调用函数时，返回地址被压入栈，参数按照从右到左顺序依次压入栈，在进入函数 `GetCountryPtr` 后，`esp` 指向栈顶，即返回地址。通常，在标准调用约定下，第一个参数位于 `[esp + 4]`，因为栈顶保存了返回地址（即调用函数返回后程序继续执行的位置），返回地址占用4个字节。】根据前面分析，压入栈的是一个代表势力ID的 双字（4 字节），因此这里 eax 即为势力 ID。【PS：从后面看，势力ID是一个比较小的数组，应该就是0~46范围的数，感觉用不到双字，不知道是不是有别的用途】
3. 然后，通过 `test eax, eax` 指令检查 `eax` 是否为零。如果为零，则跳转到 `loc_490ABD` 处。
4. 如果 `eax` 不为零，接着执行 `cmp eax, 2Eh` 指令，将 `eax` 与 `2Eh`（46） 进行比较。如果 `eax` 大于 `2Eh`（46），则跳转到 `loc_490ABD` 处。
5. 如果 `eax` 不大于 `2Eh`，则执行 `imul eax, 12Ch`，将 `eax` 乘以 `12Ch`（或者说乘以 300），然后执行 `lea eax, [eax+ecx+7AF8h]`，`lea` 指令是 Load Effective Address 的缩写，它用于将一个有效地址加载到目标操作数中。尽管它的名字中包含了 "load" 这个词，但实际上它并不从内存中加载数据，而是计算并加载一个有效地址。这里实际是计算地址`eax+ecx+7AF8h`，然后将该地址加载到`eax`。其中`ecx`在前面提到了，加载了立即数 `07201958`，这里`07201958+7AF8=7209450`, 查询内存资料知， 7209450即为所有势力数据的起始地址，每个势力数据占12Ch(=300)字节，用势力指针加偏移便可获得对应的属性。因此这里的`eax+ecx+7AF8h`即为该势力的指针。（PS: 这个立即数`07201958`颇有magic number的意思，在内存中可以搜到在调用势力相关的函数之前都会有 `mov ecx,07201958` 这么一段）![image-20240612195925036](./.assets/image-20240612195925036.png)
6. 最后，通过 `retn 4` 指令返回，其中 `4` 表示从堆栈中移除4个字节的参数。
7. 如果 `eax` 为零，则跳转到 `loc_490ABD` 处。在该处，通过 `xor eax, eax` 指令将 `eax` 清零，然后通过 `retn 4` 指令返回，效果相当于返回了一个空指针。



然后再是 **00489F80** 这个函数，其反汇编结果如下：

![image-20240612224343376](./.assets/image-20240612224343376.png)

这段反汇编代码定义的是计算两武将相位差的函数，根据前面分析，压入栈的参数是本势力君主的ID，而 eax 和 edi 寄存器里存的是当前武将的人物指针。下面是对代码逐条的分析和解释。

1. **函数入口和参数读取**：
    ```assembly
    .text:00489F80                 mov     eax, [esp+arg_0]
    ```
    将栈上的参数（君主ID）加载到 `eax` 中。

2. **参数有效性检查**：
    ```assembly
    .text:00489F84                 test    eax, eax
    .text:00489F86                 push    edi
    .text:00489F87                 mov     edi, ecx
    .text:00489F89                 jl      short loc_489F92
    .text:00489F8B                 cmp     eax, 44Bh
    .text:00489F90                 jle     short loc_489F98
    ```
    检查 `eax` 是否为负值或大于 `44Bh` (1099)。如果无效，跳转到 `loc_489F92`。

3. **无效参数处理**：
    ```assembly
    .text:00489F92 loc_489F92:                             ; CODE XREF: CalcXiangxingDiff+9↑j
    .text:00489F92                 xor     al, al
    .text:00489F94                 pop     edi
    .text:00489F95                 retn    4
    ```
    将 `al` 清零（返回0），恢复 `edi` 并返回。【PS：在x86汇编中，`al` 是 `eax` 寄存器的最低 8 位部分。`eax` 是一个 32 位寄存器，而它的各个部分可以分别作为 8 位、16 位或 32 位寄存器来使用。具体的分配如下：

    - `al`：`eax` 的低 8 位
    - `ah`：`eax` 的高 8 位
    - `ax`：`eax` 的低 16 位
    - `eax`：整个 32 位寄存器

    】

4. **有效参数处理**：
    ```assembly
    .text:00489F98 loc_489F98:                             ; CODE XREF: CalcXiangxingDiff+10↑j
    .text:00489F98                 push    esi
    .text:00489F99                 push    eax
    .text:00489F9A                 mov     ecx, offset dword_7201958
    .text:00489F9F                 call    GetPersonPtr
    .text:00489FA4                 mov     esi, eax
    .text:00489FA6                 push    esi             ; lp
    .text:00489FA7                 call    IsLegalPtr
    .text:00489FAC                 add     esp, 4
    ```
    将君主ID作为参数调用 `GetPersonPtr` 函数，获取君主的人物指针到 `esi`。然后调用 `IsLegalPtr` 检查指针合法性。

5. **合法性检查**：

    ```assembly
    .text:00489FAF                 test    eax, eax
    .text:00489FB1                 jz      short loc_489FD3
    ```
    如果指针不合法，跳转到 `loc_489FD3`。

6. **相性差异计算**：

    ```assembly
    .text:00489FB3                 movzx   ecx, byte ptr [esi+69h]
    .text:00489FB7                 movzx   eax, byte ptr [edi+69h]
    .text:00489FBB                 sub     eax, ecx
    .text:00489FBD                 jns     short loc_489FC1
    .text:00489FBF                 neg     eax
    ```
    获取 `esi` 和 `edi` 对象的69h偏移处的字节值，并计算它们的差值（绝对值）。

7. **相性差异与固定值对比**：
    ```assembly
    .text:00489FC1 loc_489FC1:                             ; CODE XREF: CalcXiangxingDiff+3D↑j
    .text:00489FC1                 mov     ecx, 96h
    .text:00489FC6                 sub     ecx, eax
    .text:00489FC8                 cmp     eax, ecx
    .text:00489FCA                 jl      short loc_489FD5
    ```
    比较相性差异 `eax` 与固定值 `96h` 的差值。如果 `eax` 小于差值，跳转到 `loc_489FD5`。

8. **相性差异返回处理**：
    ```assembly
    .text:00489FCC                 pop     esi
    .text:00489FCD                 mov     eax, ecx
    .text:00489FCF                 pop     edi
    .text:00489FD0                 retn    4
    ```
    如果 `eax` 大于等于差值，返回较小的值。

9. **非法指针处理和最终返回**：

    ```assembly
    .text:00489FD3 loc_489FD3:                             ; CODE XREF: CalcXiangxingDiff+31↑j
    .text:00489FD3                 xor     al, al
    .text:00489FD5
    .text:00489FD5 loc_489FD5:                             ; CODE XREF: CalcXiangxingDiff+4A↑j
    .text:00489FD5                 pop     esi
    .text:00489FD6                 pop     edi
    .text:00489FD7                 retn    4
    .text:00489FD7 CalcXiangxingDiff endp
    .text:00489FD7
    .text:00489FD7 ; ---------------------------------------------------------------------------

- `loc_489FD3` 和 `loc_489FD5` 处理函数在指针非法的情况下，将 `al` 清零（返回值为 0）。
- 恢复 `esi` 和 `edi` 寄存器的值。
- `retn 4` 指令用于返回并清理函数调用时的堆栈参数。它会弹出 4 字节（1 个参数）的返回地址，并恢复执行上下文。

最终得到的相性差值存在 `eax` 寄存器中。



综上可见，最终将原来取武将世代的函数替换成了计算与君主相性差的函数，这些函数会在你打开武将列表时被调用，并计算相应值。



那这些值是如何显示到列表中的呢？

我们先看下不启动这个自定义包时的武将列表：

![image-20240612235150654](./.assets/image-20240612235150654.png)

然后是应用自定义包后的效果：

![image-20240612235339263](./.assets/image-20240612235339263.png)

（未完整显示，右侧还有几列）

我们可以发现，原来的武将个人列表只有7列，现在变成了19列，多了12列。7和19这两个数字是不是很熟悉，就是前面被替换的数组的大小。由此我们可以推测，这个数组实际管的是武将个人列表会显示哪些列，如上面改的数组是：

```
01, 15, 4A, 56, 2F, 49, 06, 11, 0E, 6A, 6B, 6C, 6D, 6E, 6F, 70, 71, 72, 73
```

而这些具体的数字，应该是获取人物信息的函数的标识，比如获取人物的名字的函数标识是1，第一列全通过调用1对应的函数取得名字。

经过查询内存资料和分析IDA反汇编结果，发现果然如此，所有函数都存在起始地址为`004C8E88`的地方：

![image-20240613000447602](./.assets/image-20240613000447602.png)

武将个人页数组第9个数为0E，而我们前面替换的获取武将世代的函数(loc_4C8A6A)就属于其中第14个函数，对应0E，也会是巧合吗？为了搞清楚其中的关系，我们继续深挖。

搜索函数表的引用，发现就1处：

![image-20240613102031673](./.assets/image-20240613102031673.png)

可见这里的序号 ecx 是从一个地址为 **4C8FD8** 处的字节数组中取出来的，跳到该地址，发现就位于函数映射表下面，可以推测是一个命令编号-函数序号的映射表，命令表里存的是各函数在上述函数映射表中的序号。

![image-20240613101650317](./.assets/image-20240613101650317.png)

顺腾摸瓜可以找到获取武将信息的主函数位于**004C8720**：

![image-20240613105436591](./.assets/image-20240613105436591.png)

压入栈的参数有两个，调用前应先push命令编码, 再push武将指针，进入该函数后，先将武将指针加载至 **edi**（PS：有同学可能会疑惑，之前不是说的 esp+4 是第一个参数吗，这里`mov     edi, [esp+4+lp]`不是 esp+8 取得第二个参数吗，注意因为前面 `push edi`了，`esp` 当前指向 `push edi` 之后的位置，所以 `esp + 4` 是原始 `esp` 的位置），再判断 **edi**是否有效，如果有效（返回结果**eax**不为0）则跳转到后面各种case， 最终返回结果都存到**eax**寄存器了。



这下我们清楚了，获取武将信息需要武将指针和命令编号，那上面数组中数字自然就是命令编号了。上面的 0Eh 即 14，查命令列表（注意序号从0开始）得到对应的函数序号为 0Dh 即 13，再去查函数列表，得到对应函数地址为 4C8A6A，即返回武将世代 ID的函数。



我们将原本获取武将世代的函数替换成获取相性差的函数并生效了，现在如果我们将函数替换的代码取消掉，则武将相性差一列则会显示武将世代，验证如下：

![image-20240613004655446](./.assets/image-20240613004655446.png)



至此我们知道了武将列表中的值是怎么来的了，但还有一点不明，就是这个“相性差”的列标题是如何来的。看自定义包还剩最后一个 Code，估计就是干这个事的吧。



最后一个 Code 是在 **007ECABC** 处加 `AC DB A9 CA AE 74`, 查 IDA 知这里是只读数据段，基本存的都是各种字符串，我们先看看这里原来的文字是什么

![image-20240613005935282](./.assets/image-20240613005935282.png)

根据前面查到的资料，三国志11中用的是【BIG5】编码储存繁体汉字的，我编写了一个汉字和16进制表示的BIG5编码之间互转的python脚本 [string_tool.py](./string_tool.py)，可以得到这里编码`A5 40 A5 4E`对应的汉字为：

![image-20240613013519249](./.assets/image-20240613013519249.png)

我们再看看替换的汉字是什么：

![image-20240613013608436](./.assets/image-20240613013608436.png)

所以这段就是将 世代 替换成 相性差 的。

至此我们算是学完了这个包的原理，接下来我们开始做自己的包。



### 制作显示五维和的自定义包

首先，我们要添加的五维和应该在武将列表的能力页中，尝试找到其对应的数组

![image-20240613022645676](./.assets/image-20240613022645676.png)

正常有10列，我们在之前个人页数组对应的地址**008BD490**附近找长度为10的数组的地址，

![image-20240613025350864](./.assets/image-20240613025350864.png)

发现其实这里排着的顺序和武将列表里各页顺序是一一对应的，因此找到了我们要修改的第一个地方是`008BD460`, 我们尝试在魅力和体力之间加一列五维和，原数组地址为`008BCF20` , 内容为：

```
01 00 00 00 14 00 00 00  44 00 00 00 45 00 00 00
46 00 00 00 47 00 00 00  48 00 00 00 28 00 00 00
39 00 00 00 54 00 00 00
```

我们在倒数第3列左边增加一列，具体什么数字呢？

其实根据前面的分析，我们知道武将的所有属性其实已经固定下来了，如果要增加新的属性，只能覆盖掉已有的属性，像前面的显示相性差自定义包就是覆盖武将世代的属性。**由于目前不知道其他大神的自定义包修改的内存范围和覆盖了哪些属性，为了避免未知的风险，我们暂时选则原显示相性差包的修改内存地址和覆盖技能，等后续了解了哪些地址可以被修改（对游戏没影响且和其他自定义包不冲突）再做修改**。

我们在数组倒数第3列左边增加一列 0E 00 00 00：

```
01 00 00 00 14 00 00 00  44 00 00 00 45 00 00 00
46 00 00 00 47 00 00 00  48 00 00 00 0E 00 00 00
28 00 00 00 39 00 00 00  54 00 00 00
```

得到如下代码：

```
                <Code>
                    <Description>修改武将能力页数组地址</Description>
                    <Address>008BD460</Address>
                    <EnableCode>40 01 95 00 0B</EnableCode>
                    <DisableCode>20 CF 8B 00 0A</DisableCode>
                </Code>
                <Code>
                    <Description>武将能力页新数组</Description>
                    <Address>00950140</Address>
                    <EnableCode>01 00 00 00 14 00 00 00 44 00 00 00 45 00 00 00 46 00 00 00 47 00 00 00 48 00 00 00 0E 00 00 00 28 00 00 00 39 00 00 00 54 00 00 00</EnableCode>
                    <DisableCode>01 00 00 00 14 00 00 00 44 00 00 00 45 00 00 00 46 00 00 00 47 00 00 00 48 00 00 00 28 00 00 00 39 00 00 00 54 00 00 00</DisableCode>
                </Code>
                <Code>
                    <Description>替换命令编号0E对应的函数地址</Description>
                    <Address>004C8EBC</Address>
                    <EnableCode>E0 01 95 00</EnableCode>
                    <DisableCode>6A 8A 4C 00</DisableCode>
                </Code>
```



接下来就是实现计算武将五维和的函数了，这里我用 **IDA Pro**编写了如下代码，左边为内存地址，中间为机械码，右边为编写的汇编码：

![image-20240613193151787](./.assets/image-20240613193151787.png)

逻辑很简单，只不过要注意这里 `GetAbility_WithInjure` 函数的用法：

![image-20240613172615153](./.assets/image-20240613172615153.png)

它位于**00489030**，功能是获取武将指定受伤病影响的显示属性，输入为(push属性序号, ecx=武将指针)。

另外最后的3个pop是必须的，与其他函数表中的函数保持一致即可。

得到代码为：

```xml
                <Code>
                    <Description>替换命令编号0E对应的函数地址</Description>
                    <Address>004C8EBC</Address>
                    <EnableCode>E0 01 95 00</EnableCode>
                    <DisableCode>6A 8A 4C 00</DisableCode>
                </Code>
                <Code>
                    <Description>取五维和的函数</Description>
                    <Address>009501E0</Address>
                    <EnableCode>51 53 31 DB 89 F9 6A 00 E8 43 8E B3 FF 01 C3 6A 01 E8 3A 8E B3 FF 01 C3 6A 02 E8 31 8E B3 FF 01 C3 6A 03 E8 28 8E B3 FF 01 C3 6A 04 E8 1F 8E B3 FF 01 C3 89 D8 5B 59 5E 5B 5F C3</EnableCode>
                    <DisableCode>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00</DisableCode>
                </Code>
```



最后是将字符串“世代”替换成“五维和”：

![image-20240613150744129](./.assets/image-20240613150744129.png)

得到代码：

```
                <Code>
                    <Description>修改文字“世代”至“五维和”</Description>
                    <Address>007ECABC</Address>
                    <EnableCode>A4 AD BA FB A9 4D</EnableCode>
                    <DisableCode>A5 40 A5 4E</DisableCode>
                </Code>
```

最终的代码见 [examples/显示五维和.scp](./examples/显示五维和.scp).

我们装载上看看效果：

![image-20240613193442146](./.assets/image-20240613193442146.png)

符合预期！



## 第二弹：制作一个显示更多城市港关信息的自定包



### 导言

本弹将继续做情报一览相关的优化包，这次准备显示城市港关科技点收入，由于科技点相关的属性和机制均是血色6.0引入或改进，内存资料中缺少相关资料，需要我们自己分析内存，找到需要的地址，以及了解相关的各种地址是什么含义，**难度陡然提升**！

通过这一弹，你将了解：

- 学会使用 **IDA Pro** 分析运行中的 san11pk 进程
- 学会使用 **CheatEngine** 查找游戏中相关属性的地址和的函数地址
- 解读血色6.0中人口和科技相关代码& 科技点的来源和具体计算公式
- 制作一个显示城市港关科技点收入的自定包



### 第一步：使用 IDA Pro 分析 Sire 修改后的 san11pk 内存

现在游戏中都市一览和港关一览中已有钱粮输入和支出信息了，但缺少科技点的收入信息，因此决定新增一列显示该城市或港关的科技点收入。



至于如何新增呢，我们先检查下游戏中都市一览状态页找找灵感：

![image-20240615000825945](./.assets/image-20240615000825945.png)

其中城市人口和农村人口是血色6.0新增的人口机制中的概念，城市和港关状态页均有这两列。



我们知道，311程序员在编程时肯定是将城市或港关定义成一个结构体的，其大小已经固定，每个城市或港关实例在内存中是以一段连续的内存表示的，这里就有个疑问，原版中城市是没有城市人口和农村人口之分的，那这里怎么能新增两个字段呢。

有两种可能，一种是城市人口和农村人口覆盖了原结构体中的无用或不常用属性，另一种就是原结构体本身就还留有未使用字段，可以用于拓展新属性。具体是哪种情况，我们进一步往下深挖。



有一点需要注意的是，这次我们不能再用 IDA Pro 分析游戏目录下的脱壳文件 san11pk.exe 了，因为我们玩的血色衣冠是 sire 在 san11pk.exe 做了一些内存修改（或者说补丁）的，我们并不清楚 sire 到底修改了啥，因此要分析也得是分析运行的 san11pk.exe 的进程的内存。

我们先打开sire，为了验证我们分析的内存是加了 sire 补丁后的，我们在 sire 里加载一下我们上面编写的显示五维和的包，然后用 sire 启动游戏。

再打开32位版的 IDA Pro，点 Debugger -> 选 Local Window Debugger，找到san11pk.exe对应的进程，选择，这样就用 IDA Pro 打开了这个进程的内存了，里面不仅有 san11pk.exe 的内容，还有其调用的链接库的内容。我们跳到 **009501E0**，可以找到我们计算五维和的函数代码：

![image-20240615003527652](./.assets/image-20240615003527652.png)

说明我们现在看到的内容就是加了sire补丁后的 san11pk.exe。



需要注意的是，这里的 IDA debugger 是 attach 在进程上的，可以看到里面除了有san11pk.exe 的 segment，还有其他各种引入的动态库（dll）的 segment，如果我们将内存快照存下来分析，会发现 idb 文件超大， IDA Pro 分析时连 dll 里的内容也会分析，复杂度提升到根本分析不完的程度。【PS：这是我踩的第一个坑】

没有 IDA Pro 的分析帮助，怎么看得懂 RK 大佬们的代码呢。所谓 “**工欲善其事，必先利其器**”，为此我在网上各种搜索查找资料，加上自己不断摸索，终于找到了正确的道路：

我们的需求其实很简单，就是**将 sire 修改后的 san11pk 内存存下来供我们后续分析**，我们观察 IDA Pro 里呈现的 san11 进程，发现 san11pk.exe 的内存范围是 **00400000** -> **09C8256C**，和原来分析 san11pk.exe 那个可执行文件是一样的，我们要做的就是将 内存范围是 **00400000** -> **09C8256C**的 segment存下来，为此我写了个 IDAPython 脚本实现这个功能：

```python
import os

import idaapi
import idautils
import idc


def save_memory_range(start_addr, end_addr, output_file):
    with open(output_file, "wb") as f:
        current_addr = start_addr
        while current_addr <= end_addr:
            # Read 0x1000 bytes at a time
            chunk_size = min(0x1000, end_addr - current_addr + 1)
            data = idaapi.get_bytes(current_addr, chunk_size)
            if data:
                f.write(data)
            current_addr += chunk_size


# Define the memory range you want to save
start_address = 0x00400000
end_address = 0x09C8256C

# Specify the output file path
output_filename = "san11pk_dump.exe"

# 存到桌面
output_filename = os.path.join(os.path.expanduser("~"), "Desktop", output_filename)
print(f"Saving memory range from {hex(start_address)} to {hex(end_address)} to {output_filename}")


# Save the memory range to the specified file
save_memory_range(start_address, end_address, output_filename)


print(f"Memory range from {hex(start_address)} to {hex(end_address)} saved to {output_filename}")

```

将脚本存为 [ida-scripts/save_san11pk.py](./ida-scripts/save_san11pk.py)，然后在 IDA Pro 中 File -> Script File 执行该脚本，即可将内存范围是 **00400000** -> **09C8256C**的 segment 存下来，存到桌面的 san11pk_dump.exe 文件中。

我们将`san11pk_dump.exe`移至原 `san11pk.exe`的目录下，然后再用 IDA Pro打开这个 exe，就会自动进行分析了，并且速度很快，结果也更准确。

至此第一步算是完成，这也为后面进一步分析代码奠定基础。



### 第二步：使用 CE 分析获取城市/农村人口相关数据和函数的地址

接下来我们要找到调用获取城市的城市人口和农村人口的函数。



下面我们又得引入另一个重量级工具——**CheatEngine**了，这个工具可以捕捉运行时程序的内存信息。

打开32位的CE，选择打开san11pk血色衣冠的进程，接下来我们选个城市人口数字（如成都城市人口数 224000），填入CE，如下图：

![image-20240615005219704](./.assets/image-20240615005219704.png)

再点 FirstScan，发现了恰好一处地址 **6E07474** 的值为 224000：

![image-20240615005315694](./.assets/image-20240615005315694.png)

这个地址附近肯定就是存成都这个城市结构体的内存区域了，我们右键该项，选 Find out what accesses this address，这时会提示你 attach debugger到该进程，选是，我们再进游戏随便操作几下（如打开都市一览），然后发现有两处使用了该地址：

![image-20240615010343463](./.assets/image-20240615010343463.png)

至此我们便找到了城市人口相关的数据和函数地址，农村人口的类似可得。



### 第三步：分析城市/农村人口相关代码



现在得到了使用城市信息的函数的地址，我们可以继续在CE中探索代码，也可以回到 IDA 中，这个看个人习惯，像RK那些大佬，对汇编比较熟悉，都是直接在 CE 中读代码和改代码，我水平有限，还是回到 IDA 中来分析代码吧，一是 IDA 跳转比较方便，二是 IDA 会做一些分析辅助，区分哪些地方是函数，哪些地方是数据，对我们新手还是比较友好的。



我们先分析**004C101B**处的函数：

![image-20240615151347555](./.assets/image-20240615151347555.png)

看注释可以得到，1. 该指令的函数起点是**004C0C30**；2. 这个指令地址存在被**004C1620**跳表引用；

我们先看跳表被引用的地方**004C0F0D**：

![image-20240615152040533](./.assets/image-20240615152040533.png)

再看该跳表存储的内容的地方**004C1620**：

![image-20240615151740671](./.assets/image-20240615151740671.png)

发现命令编号是直接就是跳表序号，没有再套一层，上述获取城市人口数的loc **4C101B**，在跳表中的序号为 17（11h），

查内存资料，发现这个函数原来是取城市方针这个属性的

![image-20240615031501935](./.assets/image-20240615031501935.png)

估计你也和我一样，不知道城市方针是个什么东西，应该是什么不太重要的属性，所以大胆猜测，rk 就是用城市人口数覆盖了城市方针这个属性的。



上面CE显示的结果还有一个信息是，城市人口一直在 **910063** 处被取用，该位置所属函数为**910030**，一般这个位置的函数肯定是自定义的函数了，我们可以看看这个函数是干什么的：

![image-20240615152751054](./.assets/image-20240615152751054.png)

![image-20240615152824408](./.assets/image-20240615152824408.png)

查内存资料，可知上述调用的几个函数分别为：

- 00491770 根据设施指针获取设施ID
- 00490a10 根据城市ID获取城市指针
- 00490a40 根据关隘ID获取关隘指针
- 00490a70 根据港口ID获取港口指针

根据910063那段，可以肯定这里是获取城市或港关的城市人口的函数，至于怎么获取，对于城市来说，取的是[城市指针+4Ch], 而对于港/关，取的是[港/关指针+30h]



类似地，我们也可以分析到农村人口函数地址是 **4C102E**， 覆盖的是城市目标，农村人口数在 **009100DB** 处被取用，该位置所在函数为**009100A8**，为获取城市或港关的农村人口的函数。



关于城市人口和农村人口的相关代码先分析到这，我们如果想在都市一览和港关一览的状态页增加一列，就必须找到其对应的数组在哪，首先想到的是，这个数组可能和之前显示武将一览的数组放在一起，比如武将能力页的记录数组的地址在 **008BD460**，附近基本全是类似的数组，

![image-20240615114950181](./.assets/image-20240615114950181.png)

但是数组太多，如果一个个验证非常低效。

我们观察到, 与之前分析 san11pk.exe 文件的结果不同，这次分析的是运行时的进程，每个数组的上面都有个 dd offset，指向一个字符串，比如这里能力页数组上面的的 unk_**7EC3B8**处的值就表示的是“能力”：

![image-20240615115332362](./.assets/image-20240615115332362.png)

![image-20240615115350436](./.assets/image-20240615115350436.png)

由此我们可以推断，这块内存记录了该页名称和对应列的数组。

我们以此为切入点，寻找都市一览特殊的页，比如“地理”，big5码为“A6 61 B2 7A”，我们在 IDA Pro 中按`Alt+B`查找该字节数组：

![image-20240615162109491](./.assets/image-20240615162109491.png)

逐个查看，发现就第一个为页面里的列标题文字，位于**007EC370**，查询引用该字符串的地方，找到都市地理页的数组位于**008BC20C**，

![image-20240615162428749](./.assets/image-20240615162428749.png)

于是顺腾摸瓜便可找到都市状态页的数组位于**008BC1BC**：

![image-20240615162904796](./.assets/image-20240615162904796.png)

其内容为：

![image-20240615174544756](./.assets/image-20240615174544756.png)

从这我们可以看出，取都市的城市人口和农村人口的命令编号分别诶 11h，12h，对应的函数分别为 loc_4C101B 和 loc_4C102E，与上面的测试结果一致。



### 第四步：分析科技点相关代码



### 第四步：编写显示科技点收入的自定义包

接下来我们开始编写自定义包。



首先，我们需要找一块内存，用于我们新增修改，利用工具篇中介绍的 [analyze_scp](#批量分析各自定义包新增的修改地址区间)脚本，我们找到一块还未被大佬们涉足的内存，经过分析我们选定 **00970020** 作为我们的起始地址





目前找到的不太明白其功能的城市命令编号：

10h：城市是否处于战斗不可状态 （值取的 [esi+90h] ）





## 工具篇

### big5-decode：批量在 IDA Pro 中识别所有字符串并添加中文注释



游戏中的字符串都是以 big5 格式编码，在 IDA 浏览代码时，遇到一个便用工具解码一下，然后再添加 repeatable 注释，效率非常低，了解到 IDA 支持用 python 编写插件后，做了一个 [big5-decode-ida](https://github.com/sean2077/big5-decode-ida) 插件，以实现该功能：

按说明安装插件后，重启 IDA Pro，在 IDA 视图下右键某个地址，会多两个选项：

![image-20240616145519523](./.assets/image-20240616145519523.png)

点 Big5 decode 后便可自动解码+注释：

![image-20240616145658866](./.assets/image-20240616145658866.png)

Big5 batch decode 则是批量解码+注释，输入终止地址后，便可在所在地址和终止地址之间重复执行解码+注释，这样便可将所有字符串都解析出来，效率简直起飞！

### 批量更新 IDA 中的结构体声明

IDA 脚本： SireCustomizedPackageDev\ida-scripts\ida_structs\update_ida_struct.py

更新该脚本同目录下描述结构体的 txt 文件后，便可通过该脚本批量更新或创建 IDA Structure。

### 批量分析各结构体内存分布

脚本： SireCustomizedPackageDev\ida-scripts\ida_structs\analyze_structs.py

![analyze_structs.png](./analyze_structs.png)

### 批量分析各自定义包新增的修改地址区间

为快速了解其他开发者在san11pk内存中哪些块已经被引用，开发了一个脚本 [analyze_scp.py](./analyze_scp.py)，用于批量分析所有 scp 文件，找到所有修改的地址区间，方便后续分析。

![image-20240616183005751](./.assets/image-20240616183005751.png)

![image-20240616183022870](./.assets/image-20240616183022870.png)

### 分析san11pk未使用的内存区间

Ghidra 脚本：SireCustomizedPackageDev\ghidra-scripts\find_unused_memory_blocks.py

