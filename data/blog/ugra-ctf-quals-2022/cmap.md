---
title: Ugra CTF Quals 2022 – cmap
date: '2022-03-01'
draft: false
authors: ['blueset']
tags: ['Ugra CTF Quals 2022', 'Misc', 'Forensics', 'PDF', 'CMAP', 'Font', 'Encoding']
summary: 'CMap is CMap, but not all “CMap”s are CMap.'
---

## cmap I (PPC, 150) / cmap II (Forensics, 300)

> На объекте X, даже одно название которого совершенно секретно, введены чрезвычайные меры информационной безопасности — все компьютеры отключили от сети. Теперь сотрудники Х передают данные только на бумажных носителях — с визой руководителя отдела.
> 
> Однако, быстро выяснилось, что передавать сверхточные чертежи таким образом без потерь не получится. Поэтому в стенах Х был разработан алгоритм потоковой отправки данных с использованием лазерной печати без потерь. Алгоритм настолько эффективен, что позволяет передавать даже цветные изображения с использованием лишь чёрно-белого принтера.
> 
> Нам всё же удалось достать один из секретных файлов. Только почему-то ничего не копируется. Помогите разобраться :(
> 
> Примечание. В этом задании два флага.
> 
> Примечание 2 (добавлено 28 февраля в 17:32). не все программы для просмотра PDF показывают содержимое файла корректно. Вы должны увидеть много букв на каждой странице. Если вы их не видите — например, в Chromium, попробуйте другую программу.
>
> ---
>
> At facility X, even one name of which is top secret, emergency information security measures have been introduced - all computers have been disconnected from the network. Now employees of X transmit data only on paper - with the visa of the head of the department.
> 
> However, it quickly became clear that it would not be possible to transfer ultra-precise drawings in this way without loss. Therefore, within the walls of X, a data streaming algorithm was developed using lossless laser printing. The algorithm is so efficient that it can even transfer color images using only a black and white printer.
> 
> We still managed to get one of the secret files. For some reason, nothing is copied. Help me to understand :(
> 
> Note. There are two flags in this task.
> 
> Note 2 (added Feb 28 at 5:32 pm). Not all PDF viewers show the contents of a file correctly. You should see many letters on every page. If you do not see them - for example, in Chromium, try another program.
>
> (Google Translate)


> Нам стало известно, что алгоритм защищён от утечек — все файлы промаркированы, и, если хоть что-то попадёт в сеть, информатора быстро найдут. Узнайте, как работает эта защита.
> 
> ---
> 
> It became known to us that the algorithm is protected from leaks - all files are marked, and if at least something gets into the network, the informant will be quickly found. Find out how this protection works.
> 
> (Google Translate)

> Attachment: `cmap.pdf`

See also: Official write-up (Russian) of [cmap I](https://github.com/teamteamdev/ugractf-2022-quals/blob/master/tasks/cmap/WRITEUP.cmap1.md) and [cmap II](https://github.com/teamteamdev/ugractf-2022-quals/blob/master/tasks/cmap/WRITEUP.cmap2.md).

First, when I see the problem with a PDF attachment, and the name suggesting CMap, it immediately reminds me of an article I wrote a while ago.

[Obfuscate PDF Text: Scramble Copied Text with Crafted CMap – 1A23 Blog](https://blog.1a23.com/2017/08/29/obfuscate-pdf-text-uncopiable-text-with-crafted-cmap/)

Basically, [CMap](https://docs.microsoft.com/en-us/typography/opentype/spec/cmap) is a table of character codes and their corresponding glyph indices. It is a crutial component of OpenType standard, and being included in PDF embedded fonts for text interpretation.

Opening this PDF in Firefox, we can see a long chunk of ugly [tracked](https://en.wikipedia.org/wiki/Letter_spacing) [round hand](https://en.wikipedia.org/wiki/Round_hand) upper case letters.

![An extract of the PDF document](/static/images/ugra-ctf-quals-2022/cmap/example.png)

Inspecting this document with Adobe Acrobat Reader, the typeface used is a variant of [Monplesir Script](https://fontsisland.com/font/monplesir-script), a free [script typeface](https://en.wikipedia.org/wiki/Script_typeface) designed for Russian Cyrillic script.

However, copying these texts would give something more absurd.

```sh
$ pbpaste | python3 -c "print(*(hex(ord(i))[2:].rjust(4, '0') for i in input()))"
1562 04e6 fb0a 1d27 145c 1562 1347 2f8a 0b0d fb0a 2f8a d0c6 0782 d0c6 d0c6 d0c6 d0c6 d0c6 190e 0782 0a74 0a74 fbcc 1d27 b9c2
```

Open the PDF in a text editor, we can find a section of text like this:

```pdf
64 0 obj
<</BaseEncoding /WinAnsiEncoding /Differences 66 0 R>>
endobj

66 0 obj
[0 /uni010E 1 /uni0259 2 /uni040A 3 /uni04E6 4 /uni0581 5 /uni0782 6 /uni0785 7 /uni078B 8 /uni07B2 9 /uni07B8 10 /uni0909 11 /uni0A01 12 /uni0A22 13 /uni0A74 14 /uni0B0D 15 /uni122F 16 /uni1347 17 /uni145C 18 /uni154D 19 /uni1562 20 /uni1718 21 /uni1719 22 /uni190E 23 /uni191D 24 /uni1969 25 /uni196F 26 /uni19EC 27 /uni19ED 28 /uni19F2 29 /uni1D27 30 /uni1D32 31 /uni1D38 32 /uni1D6A 33 /uni1D7D 34 /uni213C 35 /uni2177 36 /uni23E8 37 /uni2B44 38 /uni2ED6 39 /uni2EFD 40 /uni2F8A 41 /uni3016 42 /uni303A 43 /uni30F8 44 /uni3101 45 /uni315E 46 /uni3BA7 47 /uni541F 48 /uni966C 49 /uni9982 50 /uniB9C2 51 /uniCD3B 52 /uniD0C6 53 /uniD188 54 /uniD1C3 55 /uniF960 56 /uniFB0A 57 /uniFB59 58 /uniFB9A 59 /uniFBBA 60 /uniFBCC 61 /uniFD5E 62 /uniFF18 63 /uniFF49]
endobj
```

Even if you know nothing about the PDF standard, it is quite obvious that this is a mapping of glyph indices to character codes, and everything here matches what we copied from the PDF. We now just need to find the real characters drawn in each glyph.

> **Sidenote**:  
> This table above is actually a Font Encoding table instead of a CMap table[^1]. In the official writeup, the author claimed that “cmap” refers to [a $\LaTeX$ package](https://www.ctan.org/tex-archive/macros/latex/contrib/cmap), instead of the actual CMap table.

[^1]: Whitington, J. (2012). Text and Fonts. In *PDF explained: The ISO standarad for document exchange*. essay, O'Reilly. 

To find out more of the embedded font in the PDF, we can use [FontForge](https://fontforge.org/en-US/), an open source font editor that can import PDF files and extract fonts from them.

Open the PDF in FontForge, then choose “Encoding” → “Compact” to hide all the non defined glyphs. We can see all the actual 64 glyphs shown in the defined order.

![The font extracted from the PDF with FontForge](/static/images/ugra-ctf-quals-2022/cmap/fontforge.png)

What we need to do now is to type out all the actual letters, and match them up with the code points we found in the encoding table. Then we can decode all the content in the PDF. In case you find any of the designs confusing, the [original typeface](https://fontsisland.com/font/monplesir-script) is always there as a reference.

Interestingly, even a total of 64 glyphs are found in the embed font, the actual document is only using 37 of them, making it a Base36 instead of Base64. Decode the Base36 data, and save it as a PNG file, we can then find the first flag drawn on it.

![Flag found from the decoded PNG image](/static/images/ugra-ctf-quals-2022/cmap/cmap1.png)

Go back to FontForge and scroll down a bit more. Surprisingly there’s yet another flag.

![Second half of the font extracted from the PDF with FontForge](/static/images/ugra-ctf-quals-2022/cmap/cmap2.png)

Killing two birds with one stone. Not bad, huh?