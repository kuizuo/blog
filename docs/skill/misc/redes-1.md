---
id: redes-1
slug: /redes-1
title: Redes
date: 13-03-2025
authors: Eliziane
tags: [networking, ipv4, sistemas, redes, protocolos]
keywords: [redes, ip, multicast, broadcast, sistemas, ipv4]
---

# Redes

### IP e WIFI

**IPV4** => 0.0.0/16

> **O que é IP?**
> IP é o endereço de uma máquina.

Exemplo de IP:

- 192.168.0.1
- 127.0.0.1

Existem IPs comuns ou muito conhecidos por conta de:

1. Classificação de IP
2. IP reservado

#### **IP Reservado**

Exemplos de IPs reservados e utilizados no dia a dia:

- 0.0.0.0/8 ⇒ Endereço de Internet
- 10.0.0.0/8 ⇒ RFC 1918
- 127.0.0.1 ⇒ Endereço de Loopback (a máquina aponta para si mesma)
- 240.0.0.0/4 ⇒ Multicast
- 255.255.255 ⇒ Broadcast

#### **Classificação de IP:**

> As classes servem para definir a quantidade de máquinas em uma rede.

**Classes:**

1. 0 a 127 ⇒ 2^24 (16.777.216) (quantidade de máquinas)
2. 128 a 191 ⇒ 2^16 (65.536)
3. 192 a 223 ⇒ 2^8 (256)
4. 224 a 239 ⇒ nenhum
5. 240 a 255 ⇒ nenhum

<aside>
💡 **Obs.:** As classes A e B são as maiores provedoras.
</aside>

<aside>
💡 **Obs.:** As classes A e B não vão interagir entre si a menos que seja feita uma configuração para isso.
</aside>

Para verificar a classe, precisamos olhar o início do IP:

Ex:

- **0**.0.0.0/8 ⇒ Classe A
- **10**.0.0.0/8 ⇒ Classe A
- **127**.0.0.1 ⇒ Classe A
- **240**.0.0.0/4 ⇒ Classe E
- **255**.255.255 ⇒ Classe E

<aside>
💡 **Obs.:** 255 é o limite máximo para alocação de máquinas.
</aside>

#### **Máscara**

O roteador utiliza a máscara para identificar e separar o que é endereço e o que é IP, sendo a máscara sobreposta ao IP.

**Máscaras:**

- 0.0.0.0
- 255.0.0.0
- 255.255.0.0
- 255.255.255.0
- 255.255.255.255

#### **Protocolos**

Pacotes = 📦

- **Multicast:** mais simples. Envia o 📦 para um número menor de máquinas.
- **Broadcast:** Quando um 📦 é enviado para todos, podendo ser lido ou não pelos destinatários.
- **Anycast:** O 📦 é enviado para aquele que está mais próximo, podendo ser uma máquina ou um grupo de máquinas.
- **Unicast:** 1 para 1. O 📦 é enviado para apenas uma máquina.

> **IPs especiais:**

> **Restritos:**
> 127.0.0.0
> 169.0.0.0

**Internos (privados):**

- 10.0.0/8
- 172.168.0.0/12
- 192.168.0.0/16

> **APIPA (Automatic Private IP Addressing):**

APIPA é uma funcionalidade do Windows que permite a um computador atribuir automaticamente a si mesmo um endereço IP na ausência de um servidor DHCP. Geralmente, os endereços IP APIPA estão na faixa de 169.254.0.1 a 169.254.255.254.

### Wifi

**Rede Wi-Fi**

- Emite ondas pelo ar.
- A informação é transmitida por binários 0 e 1.

**Padrões de Wifi:**

- Rede B ⇒ 11 Mbps 2,4 GHz
- Rede G ⇒ 54 Mbps 2,4 GHz
- Rede N ⇒ 100 Mbps 2,4 GHz
- Rede AC ⇒ 13 Gbps 2,4 GHz ou 5,5 GHz
