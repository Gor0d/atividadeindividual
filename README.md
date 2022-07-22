### atividadeindividual ###
- Esse repositório tem como objetivo versionar a atividade proposta pela PB Compass - DevSecOps!

Especificação das máquinas:
# Servidor: #
- Memória RAM: 11 gb
- Memória HD: 113 GB (101 GB da VDI1 e 12 gb da VDI2).

# Cliente # 
- Memória RAM: 11 GB
- Memória HD: 101 GB

##### Instalação do Linux #####
- Utilize a última versão estável disponibilizada do Oracle Linux: OracleLinux-R8-U6-x86_64-dvd.iso

- Particionamento do disco - LVMs
Na instalação do SO Oracle Linux, em INSTALLATION DESTINATION, selecionar o LOCAL STANDARD DISKS, e em STORAGE CONFIGURATION selecionar a opção CUSTOM. Clique em DONE.

Surgirá uma nova tela MANUAL PARTITIONING. Inclua 6 repartições: /boot xfs /swap swap /home xfs /var xfs /tmp xfs / xfs

#### No terminal ####
# Antes de tudo! #
Importante utilizar o "sudo yum update" para começar a baixar outras ferramentas para evitar problemas futuros com atualizações!
Instale como editor de texto o "Nano"! Para isso realize o "sudo yum install nano" e selecione "Y" para prosseguir a instalação. 
Rede da máquina virtual em CIDR/24
Instale o pacote net-tools e network-scripts: sudo yum install net-tools e/ou sudo dnf install network-scripts

Verifique a máscara de rede (255.255.255.0): if config -a

### Configurando Hostname ###
Edite o arquivo /etc/hosts: sudo vi /etc/hosts

Reinicie a máquina: reboot

### DNS com o nome kafkadockerlab ###
Edite o arquivo /etc/hosts: sudo nano /etc/hosts

Inclua uma nova linha com o ip da máquina virtual e o nome "kafkadockerlab": 192.168.100.65 - kafkadockerlab

Reinicie a máquina: reboot

# COMO "SETAR" O IP FIXO? #

Verifique o nome da sua placa de rede, o seu IP e a sua mascara de rede: ifconfig -a

Edite o arquivo ifcfg-nome_da_sua_placa: sudo nano /etc/sysconfig/network-scripts/ifcfg-enp0s3

Adicione as seguintes linhas: IPADDR= 192.168.100.65 NETMASK=255.255.255.0 DNS1=192.168.0.1 e DNS2= 8.8.8.8

Altere a linha do BOOTPROTO, substituindo o "dhcp" para "none".

 # Configurando SSH #
Instale o software SSH: sudo yum install openssh-server

Ative o SSH para iniciá-lo automaticamente junto ao sistema: sudo systemctl enable sshd

Bloqueando o acesso SSH para o root
Edite o arquivo sshd_config: sudo nano /etc/ssh/sshd_config

Altere a linha "PermitRootLogin", substituindo o "yes" por "no".
