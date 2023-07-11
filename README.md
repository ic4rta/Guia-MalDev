## Guia Desarrollo de Malware

Esta es una pequeña guia de como empezar a desarrollar malware donde te pondre en orden cronologico los conocimientos que son necesarios desde mi punto de vista, los puntos que tome en cuenta para hacer esta guia fueron:

- Hacer todo manual
- Programar todo desde cero en C/C++ y ensamblador
- No usar scripts de otros
- No se tiene nada de conocimiento de como funciona una computadora (internamente), en programacion, redes y sistema operativos
- Todos los recursos mostrados son gratis

**Nota:** Solo soy un aprendiz y aficionado que quiso compartir estos recursos para los intersados en el tema

**Nota 2:** No es necesario ver todos los recursos de cada parte, por que muchos hablan de lo mismo, solo te doy opciones, asi como tampoco es necesario verlos si ya sabes del tema

**Nota 3:** Investiga aun mas por tu cuenta

**Nota 4:** Pequeño "foro" por si tienes algunas duda, aportacion, opinion, etc: [Click aqui](https://github.com/ic4rta/Guia-MalDev/discussions/1) o en el apartado de "Discussions"

## MalDev

#### Fundamentos

- **Fundamentos de windows**
    - [THM Pt1](https://tryhackme.com/room/windowsfundamentals1xbx)
    - [THM Pt2](https://tryhackme.com/room/windowsfundamentals2x0x) 
    - [THM Pt3](https://tryhackme.com/room/windowsfundamentals3xzx) 
    - [HTB Windows Fundamentals](https://academy.hackthebox.com/module/details/49) (por si no quieres usar THM por sus funas acerca de su seguridad)

- **Fundamentos de Linux**
    - [HTB Linux Fundamentals](https://academy.hackthebox.com/module/details/18) 
    - [Curso por edureka](https://www.youtube.com/watch?v=bz0ZCUv5rYo) 
    - [Linux Basics For Hackers](https://www.kea.nu/files/textbooks/humblesec/linuxbasicsforhackers.pdf)
    
- **Fundamentos en Redes**
    - [THM: ¿Que es una red?](https://tryhackme.com/room/whatisnetworking)
    - [THM: Introduccion al networking](https://tryhackme.com/room/introtonetworking)
    - [HTB: Introduccion al networking](https://academy.hackthebox.com/module/details/34)
    - [Curso por un indio tryhard](https://www.youtube.com/watch?v=IPvYjXCsTg8)

- **Introduccion a PowerShell**
    - [Pequeña introduccion por Microsoft](https://learn.microsoft.com/en-us/training/modules/introduction-to-powershell/)
    - [PowerShell 101 por Microsoft](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/00-introduction?view=powershell-7.3)
    - [Lo mismo de arriba pero en video](https://www.youtube.com/watch?v=bPt6DH8NYPY)

- **Linux Shells (comandos y demas)** Esto podria ser complementario con la parte de ```Fudamentos en Linux```
    - [Practica por HTM](https://tryhackme.com/room/linuxstrengthtraining)
    - [Overthewrite Bandit](https://overthewire.org/wargames/bandit/)

- **Sistemas operativos** 

    - [Operating System Concepts](https://os.ecci.ucr.ac.cr/slides/Abraham-Silberschatz-Operating-System-Concepts-10th-2018.pdf)


Esto es debatible, por que este libro aparte de darte conceptos basicos, te enseñara cosas sobre arquitectura de computadoras donde tendras que programar en C y ensamblador, y tomando en cuenta que esta guia lleva un orden, en este punto aun no se entra en materia de programacion.

Si solo quieres una pequeña introduccion sobre como funciona una compu, el CPU, la administracion de memoria, los procesos, etc, puedes leer hasta la parte **2.10** o hasta la pagina **102**

#### Introduccion a la programacion en C/C++

- **Logica de programacion**:

    - [Serie de videos en youtube](https://www.youtube.com/playlist?list=PLDLnmbUDWFUtFTqLf_lS99z2gmYU5ouRv)

- **Programacion en C/C++**

    - [Programacion ATS: C++](https://www.youtube.com/playlist?list=PLWtYZ2ejMVJlUu1rEHLC0i_oibctkl0Vh)
    - [Learn C The Hard Way](https://github.com/XWHQSJ/ebooks/blob/master/Cpp/C/Learn%20C%20the%20Hard%20Way.pdf)
    - [Learn-C](https://www.learn-c.org/)
    - [C cheatsheet?](https://learnxinyminutes.com/docs/c/)

A este punto ya podrias continuar con la lectura de ```Operating System Concepts``` por que ya tendras las bases de la programacion en C/C++, y desde mi punto de vista no seria mala idea empezar con programacion concurrente y para interactuar con el sistema operativo

#### Introduccion a ensamblador

- **Ensamblador x64 y x86 bits**

    - [Curso Neomatrix](https://www.youtube.com/playlist?list=PLZw5VfkTcc8Mzz6HS6-XNxfnEyHdyTlmP), Este es full introductorio, no es mala idea verlo primero

    - [Curso Solid y Ricardo Narvaja](https://www.youtube.com/playlist?list=PLn__CHOEZR1Ymxi2n4Q9G9I9kBYr6B4Ft), Que te puedo decir. orientado al reversing, full practico desde un depurador, tremenda obra audiovisual, obra maestra 10 de 10

    - [Open Security Training](https://opensecuritytraining.info/IntroX86.html), Esto nomas son como diapositivas aca rapidas sin tanta explicacion y videos

    - [Open Security Training v2](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch1001_x86-64_Asm+2021_v1/about), Lo mismo de arriba pero version 2 (desconozco si este es gratis, no me registre)

    - [0xInfection](https://0xinfection.github.io/reversing/), Infravalorado pero muy bueno, orientado de la explotacion binaria y reversing, full practico desde GNU debugger

#### Shellcodes

En este punto ya estoy considerando que ya le sabes al bisnes de todo lo anterior

- **Desarollo de shellcodes**

    - [Fundacion Sadosky](https://fundacion-sadosky.github.io/guia-escritura-exploits/buffer-overflow/2-shellcode.html), Considero que es de los mejores recursos en español para empezar a crear shellcodes

    - [Pentester 77](https://www.youtube.com/watch?v=9UZ4o-0LTSY&t=3376s), E bueno, todo muy practico y bastante visual

    - [cocomeloc](https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html), Que te puedo decir, obra maestra

    - [Axcheron](https://axcheron.github.io/linux-shellcode-101-from-hell-to-shell/), Otra maldita obra maestra

    - [c4rta](https://ic4rta.github.io//maldev-shellcodes/), Soy yo, te enseño a crear dos shellcodes, una para imprimir algo y otra para /bin/sh


#### Introduccion a la WinAPI o Win32 API

Este es un gran salto, la WinAPI es muy extensa, hay miles de funciones, y desde ahora te digo que no hay ninguna funcion exclusiva para el desarrollo de malware, **NINGUNA**, asi que lo que pasa en este punto es que debes de ver como puedes usar esas funciones para desarrollar malware, es decir, aplicarlas para otro fin del que fueron creadas, regularmente las funciones que se usan son las que tiene que ver con el manejo de procesos, subprocesos, y todo lo relacionado al VAS (Virtual Adress Space)

- **Programando con la WinAPI**

    - [Introduccion a la WinAPI](https://tryhackme.com/room/windowsapi)
    - [WinAPI process management](https://learn.microsoft.com/pdf?url=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fwindows%2Fwin32%2Fprocthread%2Ftoc.json), es un PDF de Windows con todas las funciones de procesos y sub procesos, son mas de 1100 paginas


#### Desarollo de malware

- **Introduccion a las inyecciones de proceso/codigo**

    - [ATT&CK](https://www.youtube.com/watch?v=CwglaQRejio)
    - [MalwareAnalysisForHedgehogs](https://www.youtube.com/watch?v=tBR1-1J5Jec&t=330s)

- **Algunas tecnicas de inyecciones de procesos/codigo**, algunas tecnicas con las que puedes empezar a inyectar tus primeras shellcodes o DLLs, algunas de estas tambien puedes ser usadas para evadir los AV/EDRs, ten en cuenta que cada una funciona de diferente forma, asi que procura entenderlas y analizarlas en un depurador, tambien pueden ser aplicadas de diferentes formas

    - Shellcode via Inline Assembly
    - RemoteThreadInjection
    - DLL Injection basico
    - Thread Hijacking
    - Local Thread Hijacking
    - Shellcode via CreatePoolWait
    - Reflective DLL injection (Papea antivirus)
    - Process Hollowing (esta es GOD)
    - Shellcode via Inter-Process Mapped-View
    - Ghostwriting (esta es GOD tambien)
    - Atom Bombing (esto papea antivirus)
    - Process Doppelgänging (tambien papea antivirus)
    - Early Bird APC Queue (aveces papea antivirus, por que la shellcode se ejecuta antes que un EDR)
    - Fiber injection (papea antivirus si usas varias fibras)
    - PROPagate (Es GOD y poco documentada)
    - Module Stomping (No papea todos los antivirus pero si al windows defender, y es muy buena para inyectar una DLL)
    - NLS Code Injection (Papea antivirus, muy poco documentada, y muy dificil de aplicar)

- **AntiDBG (evadir depuradores)**

    - [Anti-Debug Checkpoint](https://anti-debug.checkpoint.com/techniques/debug-flags.html)
    - [Papi Noteworthy](https://github.com/LordNoteworthy/al-khaser/tree/master/al-khaser/AntiDebug)

- **AntiVM y Anti emulacion (evadir maquinas virtuales)**

    - [Cynet](https://www.cynet.com/attack-techniques-hands-on/malware-anti-vm-techniques/)
    - [InfoSec Institute](https://resources.infosecinstitute.com/topic/anti-debugging-and-anti-vm-techniques-and-anti-emulation/)
    - [Papi Noteworthy](https://github.com/LordNoteworthy/al-khaser/tree/master/al-khaser/AntiVM)
    - [DeepInstinct](https://www.deepinstinct.com/blog/malware-evasion-techniques-part-2-anti-vm-blog)

- **Anti Disassembly**

    - [Preet Kamal](https://1malware1.medium.com/anti-disassembly-techniques-e012338f2ae0)
    - [Unknown](http://staff.ustc.edu.cn/~bjhua/courses/security/2014/readings/anti-disas.pdf)

-  **Timming Attacks/Ataques basados en temporizadores**

    - [Papi Noteworthy](https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/TimingAttacks/timing.cpp)

- **Ofuscacion y Packers**

    - [IredTeam](https://www.ired.team/offensive-security/code-injection-process-injection/writing-custom-shellcode-encoders-and-decoders)
    - [Lsec](https://medium.com/@lsecqt/encrypting-shellcode-with-xor-offensive-coding-in-c-5a42cb978d6e)
    - [malbot - Malware News](https://malware.news/t/reverse-engineering-crypto-functions-aes/55413)
    - [UPX](https://upx.github.io/)
    - [The Enigma Protector](https://enigmaprotector.com/)
    - [c3rb3ru5d3d53c](https://www.youtube.com/watch?v=6aik01mTiDc)

#### Desarollo de malware mas dificil

En este punto deberias de saber moverte un poco mejor programando con la WinAPI, ya sabes hacer reversing y leer ensamblador un poco mejor de tus propios malware

Como practica, puedes implementar las mismas tecnias mostradas anteriormente pero ahora usando la NTAPI

- **API nativa o NTAPI**

    - [ACCU Conference](https://www.youtube.com/watch?v=a0KozcRhotM)
    - [Sysinternals Freeware](https://web.archive.org/web/20121224002314/http://netcode.cz/img/83/nativeapi.html)
    - [Inside Native Applications - MSDN](https://learn.microsoft.com/en-us/sysinternals/resources/inside-native-applications)
    - [crow](https://www.crow.rip/crows-nest/malware-development/process-injection/ntapi-injection)


#### :skull: :skull: :skull: Desarollo de malware :skull: :skull: :skull:

Aqui si ya esta potente la cosa, en este punto ya todo es aun mas dificil (demasiado)

- **Programacion y explotacion de drivers**
    
    - [MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/)
    - [OSR](https://www.osr.com/getting-started-writing-windows-drivers/)
    - [Piotr Bania - Explotacion de drivers](https://www.piotrbania.com/all/articles/ewdd.pdf)
    - [Off By One Security](https://www.youtube.com/watch?v=nauAlHXrkIk)
    - [HackSys](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)
    - Bring Your Own Vulnerable Driver (no encontre tutoriales, pero basicamente ya debes de saber programar drivers, y encima con una vulnerabilidad intencionada, ej)
        - [Stack Overflow](https://blog.xpnsec.com/hevd-stack-overflow/)
        - [Pool Overflow](https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/)
        - [User After Free](https://infosecwriteups.com/use-after-free-13544be5a921)
        - [Type Confusion](https://hackingportal.github.io/Type_Confusion/type_confusion.html)
        - [Integer Overflow/Underflow](https://ic4rta.github.io/integer-overflow/)
        - [Null Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
        - [Arbitrary Overwrites (Write-What-Where condition)](https://connormcgarr.github.io/Kernel-Exploitation-2/)
        - [RS2 Bitmap Necromancy](https://fuzzysecurity.com/tutorials/expDev/22.html)

- **Creacion de rootkits**

    - Inline hooking
        - [MalwareTech](https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html) 
        - [SecureHat](https://blog.securehat.co.uk/process-injection/manually-implementing-inline-function-hooking)
        - [Ruben Revuelta](https://rrevueltab.medium.com/user-mode-rootkits-i-inline-hooking-66339e9332cb)
        - [InmuniWeb](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwjCiebDoIWAAxWgKEQIHbTyDhAQFnoECBYQAQ&url=https%3A%2F%2Fwww.immuniweb.com%2Fpublication%2Finline_hooking_in_windows.pdf&usg=AOvVaw39quiH9EVG15C5XmAdxLlA&opi=89978449)
    
    - SSDT hooking
        - [Dejan Lukan](https://resources.infosecinstitute.com/topic/hooking-system-service-dispatch-table-ssdt/)
        - [Adlice](https://www.adlice.com/kernelmode-rootkits-part-1-ssdt-hooks/)
        - [m0uk4](https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/ssdt-hook)
        - [Samsclass](https://samsclass.info/126/proj/pDC16rk.htm)

    - IAT hooking
        - [Ruben Revuelta](https://rrevueltab.medium.com/user-mode-rootkits-ii-iat-hooking-dll-injection-134457eb14b0)
        - [Adlice](https://www.adlice.com/userland-rootkits-part-1-iat-hooks/)
        - [Pentest Blog](https://pentest.blog/offensive-iat-hooking/)
        - [Guide Hacking](https://guidedhacking.com/threads/how-to-hook-import-address-table-iat-hooking.13555/)
        - [BlackHat](https://www.blackhat.com/presentations/bh-europe-06/bh-eu-06-Silberman-Butler.pdf)
        - [ReLearEx](https://relearex.wordpress.com/2017/12/26/hooking-series-part-i-import-address-table-hooking/)

- [Sourcefire](https://www.youtube.com/playlist?list=PLgBE3-yjLAKXExnugTBonsPkLafL87k5m), "Minicurso" de desarrollo de rootkits
- [RootKits and Bootkits](https://dl.ebooksworld.ir/motoman/No.Starch.Press.Rootkits.and.Bootkits.www.EBooksWorld.ir.pdf), es muy buen libro, ya que te enseñan tenicas que han usados rootkit para evadir AV/EDRs, las formas que han usados bootkits para sobreescribir la UEFI, almacenarse en el chipset de la BIOS y escarlar de ring 3 a ring 0, etc

## Recursos adicionales

#### Foros

[https://0x00sec.org/](https://0x00sec.org/)

#### Blogs

- [https://cocomelonc.github.io/](https://cocomelonc.github.io/)
- [https://www.vkremez.com/](https://www.vkremez.com/)
- [https://0xpat.github.io/](https://0xpat.github.io/)
- [https://zerosum0x0.blogspot.com/](https://zerosum0x0.blogspot.com/)
- [https://www.guitmz.com/](https://www.guitmz.com/)

#### GitHubs

- [https://github.com/rootkit-io/awesome-malware-development](https://github.com/rootkit-io/awesome-malware-development)
- [https://github.com/kymb0/Malware_learns](https://github.com/kymb0/Malware_learns)

#### Cursos de pago (estan gratis en internet)

- [https://www.pentesteracademy.com/course?id=3](https://www.pentesteracademy.com/course?id=3)
- [https://www.pentesteracademy.com/course?id=50](https://www.pentesteracademy.com/course?id=50)
- [https://institute.sektor7.net/view/courses/red-team-operator-malware-development-essentials/](https://institute.sektor7.net/view/courses/red-team-operator-malware-development-essentials/)
- [https://institute.sektor7.net/rto-maldev-intermediate](https://institute.sektor7.net/rto-maldev-intermediate)
