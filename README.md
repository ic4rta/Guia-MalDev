## Guia Desarrollo de Malware

Esta es una pequeña guia de como empezar a desarrollar malware donde te pondre recursos en orden cronologico, los puntos que tome en cuenta para hacer esta guia fueron:

- Hacer todo manual
- Programar todo desde cero en C/C++ y ensamblador
- No se tiene nada de conocimiento de como funciona una computadora (internamente), en programacion, redes y sistemas operativos
- Todos los recursos mostrados son gratis

**Nota:** Solo soy un aprendiz y aficionado que quiso compartir estos recursos para los intersados en el tema

**Nota 2:** No es necesario ver todos los recursos de cada parte, por que muchos hablan de lo mismo, solo te doy opciones, asi como tampoco es necesario verlos si ya sabes del tema

**Nota 3:** Investiga aun mas por tu cuenta

**Nota 4:** Pequeño "foro" por si tienes algunas duda, aportacion, opinion, etc: [Click aqui](https://github.com/ic4rta/Guia-MalDev/discussions/1) o en el apartado de "Discussions"

### :brown_circle: Fundamentos

- **Fundamentos de windows**
    - [THM Pt1](https://tryhackme.com/room/windowsfundamentals1xbx)
    - [THM Pt2](https://tryhackme.com/room/windowsfundamentals2x0x) 
    - [THM Pt3](https://tryhackme.com/room/windowsfundamentals3xzx) 
    - [HTB Windows Fundamentals](https://academy.hackthebox.com/module/details/49) (por si no quieres usar THM)

- **Fundamentos de Linux**
    - [HTB Linux Fundamentals](https://academy.hackthebox.com/module/details/18) 
    - [Curso por edureka](https://www.youtube.com/watch?v=bz0ZCUv5rYo) 
    - [Linux Basics For Hackers](https://www.kea.nu/files/textbooks/humblesec/linuxbasicsforhackers.pdf)
    
- **Fundamentos en Redes**
    - [THM: ¿Que es una red?](https://tryhackme.com/room/whatisnetworking)
    - [THM: Introduccion al networking](https://tryhackme.com/room/introtonetworking)
    - [HTB: Introduccion al networking](https://academy.hackthebox.com/module/details/34)
    - [Curso por un indio tryhard](https://www.youtube.com/watch?v=IPvYjXCsTg8)
    - [droix3d: Modelo TCP-IP](https://droix3d.github.io/posts/TCP-IP/)

- **Introduccion a PowerShell**
    - [Pequeña introduccion por Microsoft](https://learn.microsoft.com/en-us/training/modules/introduction-to-powershell/)
    - [PowerShell 101 por Microsoft](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/00-introduction?view=powershell-7.3)
    - [Lo mismo de arriba pero en video](https://www.youtube.com/watch?v=bPt6DH8NYPY)

- **Linux Shells (comandos y demas)** Esto podria ser complementario con la parte de ```Fudamentos en Linux```
    - [Practica por THM](https://tryhackme.com/room/linuxstrengthtraining)
    - [Overthewrite Bandit](https://overthewire.org/wargames/bandit/)

- **Sistemas operativos** 

    - [Operating System Concepts](https://os.ecci.ucr.ac.cr/slides/Abraham-Silberschatz-Operating-System-Concepts-10th-2018.pdf)


Esto es debatible, por que este libro aparte de darte conceptos basicos, te enseñara cosas sobre arquitectura de computadoras donde tendras que programar en C y ensamblador, y tomando en cuenta que esta guia lleva un orden, en este punto aun no se entra en materia de programacion.

Si solo quieres una pequeña introduccion sobre como funciona una compu, el CPU, la administracion de memoria, los procesos, etc, puedes leer hasta la parte **2.10** o hasta la pagina **102**

Adicionalmente puedes saltarte hasta el capítulo 10 (página 389) para conocer acerca del VAS (Virtual Adress Space)

### :green_circle: Introduccion a la programacion en C/C++

- **Logica de programacion**:

    - [Serie de videos en youtube](https://www.youtube.com/playlist?list=PLDLnmbUDWFUtFTqLf_lS99z2gmYU5ouRv)

- **Programacion en C/C++**

    - [Programacion ATS: C++](https://www.youtube.com/playlist?list=PLWtYZ2ejMVJlUu1rEHLC0i_oibctkl0Vh)
    - [Learn C The Hard Way](https://github.com/XWHQSJ/ebooks/blob/master/Cpp/C/Learn%20C%20the%20Hard%20Way.pdf)
    - [Learn-C](https://www.learn-c.org/)
    - [C cheatsheet?](https://learnxinyminutes.com/docs/c/)

A este punto ya podrias continuar con la lectura de ```Operating System Concepts``` por que ya tendras las bases de la programacion en C/C++, y desde mi punto de vista no seria mala idea empezar con programacion concurrente y para interactuar con el sistema operativo

### :large_blue_circle: Introduccion a ensamblador

- **Ensamblador x64 y x86 bits**

    - [Curso Neomatrix](https://www.youtube.com/playlist?list=PLZw5VfkTcc8Mzz6HS6-XNxfnEyHdyTlmP), Este es full introductorio, no es mala idea verlo primero

    - [Curso Solid y Ricardo Narvaja](https://www.youtube.com/playlist?list=PLn__CHOEZR1Ymxi2n4Q9G9I9kBYr6B4Ft), Que te puedo decir. orientado al reversing, full practico desde un depurador, tremenda obra audiovisual, obra maestra 10 de 10

    - [Open Security Training](https://opensecuritytraining.info/IntroX86.html), Esto nomas son como diapositivas aca rapidas sin tanta explicacion y videos

    - [Open Security Training v2](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch1001_x86-64_Asm+2021_v1/about), Lo mismo de arriba pero version 2 (desconozco si este es gratis, no me registre)

    - [0xInfection](https://0xinfection.github.io/reversing/), Infravalorado pero muy bueno, orientado de la explotacion binaria y reversing, full practico desde GNU debugger

### :orange_circle: Shellcodes

- **Desarrollo de shellcodes**

    - [Fundacion Sadosky](https://fundacion-sadosky.github.io/guia-escritura-exploits/buffer-overflow/2-shellcode.html), Considero que es de los mejores recursos en español para empezar a crear shellcodes

    - [Pentester 77](https://www.youtube.com/watch?v=9UZ4o-0LTSY&t=3376s), E bueno, todo muy practico y bastante visual

    - [cocomeloc](https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html), Creacion de shellcodes en windows (ejecuta calc.exe)

    - [Axcheron](https://axcheron.github.io/linux-shellcode-101-from-hell-to-shell/), Shellcode execve para bin/sh

    - [c4rta](https://ic4rta.github.io/2023/06/07/maldev-shellcodes/), Soy yo, te enseño a crear dos shellcodes, una para imprimir algo y otra para /bin/sh


### :purple_circle: Introduccion a la WinAPI o Win32 API

Este es un gran salto, la WinAPI es muy extensa, hay miles de funciones, y desde ahora te digo que no hay ninguna funcion exclusiva para el desarrollo de malware, **NINGUNA**, asi que lo que pasa en este punto es que debes de ver como puedes usar esas funciones para desarrollar malware, es decir, aplicarlas para otro fin del que fueron creadas, regularmente las funciones que se usan son las que tiene que ver con el manejo de procesos, subprocesos, y todo lo relacionado al VAS (Virtual Adress Space)

- **Programando con la WinAPI**

    - [Introduccion a la WinAPI](https://tryhackme.com/room/windowsapi)
    - [WinAPI process management](https://learn.microsoft.com/pdf?url=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fwindows%2Fwin32%2Fprocthread%2Ftoc.json), es un PDF de Windows con todas las funciones de procesos y sub procesos, son mas de 1100 paginas

- **Funciones recomedadas (no son todas)**
    - Persistencia
      - [RegCreateKeyEx](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa)
      - [RegOpenKeyEx](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa)
      - [RegSetValueEx](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa)

    - Cifrado (para ransomware)
      - [WinCrypt header](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/)
      - [CryptAcquireContext](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)
      - [CryptGenKey](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey)
      - [CryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey)

    - Manejo de procesos y subprocesos
      - [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
      - [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
      - [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
      - [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
      - [CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
      - [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)
      - [CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
      - [CreateMutex](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa), esta es interesante por que puedes crear una exclusión mutua para que el malware se ejecuté una sola vez y no vuelva a ejecutarse si la máquina ya fue infectada

    - Keyloggers
      - [GetAsyncKeyState](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate)
      - [SetWindowsHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)

### :red_circle: Desarrollo de malware

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
    - Reflective DLL injection
    - Process Hollowing
    - Shellcode via Inter-Process Mapped-View
    - Ghostwriting
    - Atom Bombing
    - Process Doppelgänging
    - Early Bird APC Queue
    - Fiber injection
    - PROPagate
    - Module Stomping
    - NLS Code Injection

- **AntiDBG (evadir depuradores)**

    - [Anti-Debug Checkpoint: AntiDBG techniques](https://anti-debug.checkpoint.com/techniques/debug-flags.html)
    - [Papi Noteworthy: AntiDBG techniques](https://github.com/LordNoteworthy/al-khaser/tree/master/al-khaser/AntiDebug)

- **AntiVM y Anti emulacion (evadir maquinas virtuales)**

    - [Cynet: AntiVM techniques](https://www.cynet.com/attack-techniques-hands-on/malware-anti-vm-techniques/)
    - [InfoSec Institute: AntiVM techniques](https://resources.infosecinstitute.com/topic/anti-debugging-and-anti-vm-techniques-and-anti-emulation/)
    - [Noteworthy: AntiVM techniques](https://github.com/LordNoteworthy/al-khaser/tree/master/al-khaser/AntiVM)
    - [DeepInstinct: AntiVM techniques](https://www.deepinstinct.com/blog/malware-evasion-techniques-part-2-anti-vm-blog)

- **Anti Disassembly**

    - [Preet Kamal: Anti disas techniques](https://1malware1.medium.com/anti-disassembly-techniques-e012338f2ae0)
    - [Unknown: Anti disas techniques](http://staff.ustc.edu.cn/~bjhua/courses/security/2014/readings/anti-disas.pdf)

-  **Timming Attacks/Ataques basados en temporizadores**

    - [Noteworthy](https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/TimingAttacks/timing.cpp)

- **Ofuscacion y Packers**

    - [IredTeam: Shellcode Encoders and Decoders](https://www.ired.team/offensive-security/code-injection-process-injection/writing-custom-shellcode-encoders-and-decoders)
    - [Lsec: Shellcode with XOR](https://medium.com/@lsecqt/encrypting-shellcode-with-xor-offensive-coding-in-c-5a42cb978d6e)
    - [malbot - Malware News: AES functions](https://malware.news/t/reverse-engineering-crypto-functions-aes/55413)
    - [UPX](https://upx.github.io/)
    - [The Enigma Protector](https://enigmaprotector.com/)
    - [c3rb3ru5d3d53c: Obfuscation introduction](https://www.youtube.com/watch?v=6aik01mTiDc)
 
 - **RATs y C2**
    - [Chetan Nayak: Welcome to the Dark Side: Part 1](https://niiconsulting.com/checkmate/2018/02/malware-development-welcome-dark-side-part-1/)
    - [Chetan Nayak: Welcome to the Dark Side: Part 2](https://niiconsulting.com/checkmate/2018/02/malware-development-welcome-dark-side-part-2-1/)
    - [Chetan Nayak: Welcome to the Dark Side: Part 2-2](https://niiconsulting.com/checkmate/2018/03/malware-development-welcome-dark-side-part-2-2/)
    - [Chetan Nayak: Welcome to the Dark Side: Part 3](https://niiconsulting.com/checkmate/2018/03/malware-development-welcome-dark-side-part-3/)
    - [Chetan Nayak: Welcome to the Dark Side: Part 4](https://niiconsulting.com/checkmate/2018/03/malware-development-welcome-to-the-dark-side-part-4/)

---
- **API nativa o NTAPI**:
Como practica, puedes implementar las mismas tecnicas mostradas anteriormente pero ahora usando la NTAPI

    - [ACCU Conference](https://www.youtube.com/watch?v=a0KozcRhotM)
    - [Sysinternals Freeware](https://web.archive.org/web/20121224002314/http://netcode.cz/img/83/nativeapi.html)
    - [Inside Native Applications - MSDN](https://learn.microsoft.com/en-us/sysinternals/resources/inside-native-applications)
    - [crow: NTAPI Injection](https://www.crow.rip/crows-nest/malware-development/process-injection/ntapi-injection)
      
- **Kernel Shellcodes**
    - [uf0: Windows Kernel Shellcodes - a compendium](https://www.matteomalvica.com/blog/2019/07/06/windows-kernel-shellcode/)
    - [ImproSec: Windows Kernel Shellcodes Pt1](https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-1)
    - [ImproSec: Windows Kernel Shellcodes Pt2](https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2)
    - [ImproSec: Windows Kernel Shellcodes Pt3](https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-3)
    - [ImproSec: Windows Kernel Shellcodes Pt4](https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-4-there-is-no-code)

---
- **Programacion y explotacion de drivers**
    
    - [MSDN: Drivers Introduction](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/)
    - [OSR](https://www.osr.com/getting-started-writing-windows-drivers/)
    - [Piotr Bania: Explotacion de drivers](https://www.piotrbania.com/all/articles/ewdd.pdf)
    - [Off By One Security: Modern Windows Kernel Exploitation](https://www.youtube.com/watch?v=nauAlHXrkIk)
    - [HackSys Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)
    - Bring Your Own Vulnerable Driver (no encontre tutoriales, pero basicamente ya debes de saber programar drivers, y encima con una vulnerabilidad intencionada, ej)
        - [Stack Overflow](https://blog.xpnsec.com/hevd-stack-overflow/)
        - [Pool Overflow](https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/)
        - [Use After Free](https://infosecwriteups.com/use-after-free-13544be5a921)
        - [Type Confusion](https://hackingportal.github.io/Type_Confusion/type_confusion.html)
        - [Integer Overflow/Underflow](https://ic4rta.github.io/integer-overflow/)
        - [Null Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
        - [Arbitrary Overwrites (Write-What-Where condition)](https://connormcgarr.github.io/Kernel-Exploitation-2/)
        - [RS2 Bitmap Necromancy](https://fuzzysecurity.com/tutorials/expDev/22.html)

---
- **Creacion de rootkits**
  
    - Seguridad y Explotacion del UEFI
        - [BlackHat: Breaking Firmware Trust From Pre-EFI: Exploiting Early Boot Phases](https://www.blackhat.com/us-22/briefings/schedule/index.html#breaking-firmware-trust-from-pre-efi-exploiting-early-boot-phases-27229)
        - [Binarly: Post sobre seguridad del UEFI](https://www.binarly.io/posts/index.html)
        - [BlackHat: Breaking Secure Bootloaders](https://www.youtube.com/watch?v=XvGcQgx9Jg8)
        - [BlackHat: Taking DMA Attacks to the Next Level](https://www.youtube.com/watch?v=QeIPcA8zsHk)
        - [BlackHat: Analyzing UEFI BIOSes from Attacker & Defender Viewpoints](https://www.youtube.com/watch?v=CGBpil0S5NI&t=1s)
        - [BlackHat: Attacking Intel BIOS](https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf)
        - [BlackHat: Introducing Ring -3 Rootkits](https://invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf)
        - [CanSecWest: Attacks on UEFI Security](https://web.archive.org/web/20150908083304/https://cansecwest.com/slides/2015/AttacksOnUEFI_Rafal.pptx)
        - [DEFCON: Hacking the Extensible Firmware Interface](https://www.youtube.com/watch?v=g-n42Q-Pxsg)
        - [ATT&CK: Vectores de ataque de un bootkit](https://attack.mitre.org/techniques/T1542/003/)
     
    - Analisis de Bootkits
        - [BlackLotus](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
        - [CosmicStrand](https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/)
        - [MoonBounce](https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/)
        - [ESPecter](https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/)
        - [FinSpy](https://securelist.com/finspy-unseen-findings/104322/)
        - [TrickBot](https://eclypsium.com/wp-content/uploads/TrickBot-Now-Offers-TrickBoot-Persist-Brick-Profit.pdf)
        - [MosaicRegressor](https://securelist.com/mosaicregressor/98849/)
        - [LoJax](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/)
     
    - Codigos fuente
        - [umap](https://github.com/btbd/umap)
        - [UEFI-Bootkit](https://github.com/ajkhoury/UEFI-Bootkit)
        - [SMM Backdoor](https://github.com/Cr4sh/SmmBackdoor)
        - [PEI Backdoor](https://github.com/Cr4sh/PeiBackdoor)
    
    - Inline Hooking
        - [MalwareTech](https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html) 
        - [SecureHat](https://blog.securehat.co.uk/process-injection/manually-implementing-inline-function-hooking)
        - [Ruben Revuelta](https://rrevueltab.medium.com/user-mode-rootkits-i-inline-hooking-66339e9332cb)
        - [InmuniWeb](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwjCiebDoIWAAxWgKEQIHbTyDhAQFnoECBYQAQ&url=https%3A%2F%2Fwww.immuniweb.com%2Fpublication%2Finline_hooking_in_windows.pdf&usg=AOvVaw39quiH9EVG15C5XmAdxLlA&opi=89978449)
    
    - SSDT Hooking
        - [Dejan Lukan](https://resources.infosecinstitute.com/topic/hooking-system-service-dispatch-table-ssdt/)
        - [Adlice](https://www.adlice.com/kernelmode-rootkits-part-1-ssdt-hooks/)
        - [m0uk4](https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/ssdt-hook)
        - [Samsclass](https://samsclass.info/126/proj/pDC16rk.htm)

    - IAT Hooking
        - [Ruben Revuelta](https://rrevueltab.medium.com/user-mode-rootkits-ii-iat-hooking-dll-injection-134457eb14b0)
        - [Adlice](https://www.adlice.com/userland-rootkits-part-1-iat-hooks/)
        - [Pentest Blog](https://pentest.blog/offensive-iat-hooking/)
        - [Guide Hacking](https://guidedhacking.com/threads/how-to-hook-import-address-table-iat-hooking.13555/)
        - [BlackHat](https://www.blackhat.com/presentations/bh-europe-06/bh-eu-06-Silberman-Butler.pdf)
        - [ReLearEx](https://relearex.wordpress.com/2017/12/26/hooking-series-part-i-import-address-table-hooking/)
     
    - IRP y DKOM Hooking
        - [Adlice](https://www.adlice.com/kernelmode-rootkits-part-2-irp-hooks/)
        - [Qiyana: codigo de exemplo](https://www.unknowncheats.me/forum/c-and-c-/403581-kernel-irp-hook.html)
        - [BlackHat](https://www.blackhat.com/presentations/win-usa-04/bh-win-04-butler.pdf)
        - [NixHacker: DKOM Manipulation](https://nixhacker.com/understanding-windows-dkom-direct-kernel-object-manipulation-attacks-eprocess/)
        - [INFILTRATE: Hiding and Hooking with Windows Extension Hosts](https://vimeo.com/335166152)

 [Sourcefire](https://www.youtube.com/playlist?list=PLgBE3-yjLAKXExnugTBonsPkLafL87k5m), "Minicurso" de desarrollo de rootkits

[RootKits and Bootkits](https://dl.ebooksworld.ir/motoman/No.Starch.Press.Rootkits.and.Bootkits.www.EBooksWorld.ir.pdf), es muy buen libro, ya que te enseñan tecnicas que han usados rootkits para evadir AV/EDRs, sobreescribir la UEFI y BIOS, almacenarse en el chipset de la BIOS, escalar de ring 3 a ring 0, etc

### Usuarios que han contribuido
<a href="https://github.com/ic4rta" target="_blank" rel="noreferrer"> <img src="https://avatars.githubusercontent.com/ic4rta" width="60" height="60"/></a>
<a href="https://github.com/droix3d" target="_blank" rel="noreferrer"> <img src="https://avatars.githubusercontent.com/u/109915316?v=4" width="60" height="60"/></a>
<a href="https://github.com/NotAndeer" target="_blank" rel="noreferrer"> <img src="https://avatars.githubusercontent.com/NotAndeer" width="60" height="60"/></a>

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
