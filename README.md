# Atividade Individual #
- Esse repositório tem como objetivo versionar e documentar a atividade proposta pela PB Compass - DevSecOps!
- Feito por: Emerson Gabriel da Silva Guimarães

# Especificação das máquinas: #
# Servidor: #
- Memória RAM: 11 gb
- Memória HD: 113 GB (101 GB da VDI1 e 12 gb da VDI2).

# Cliente # 
- Memória RAM: 11 GB
- Memória HD: 101 GB

# Instalação do Linux #
- Utilize a última versão estável disponibilizada do Oracle Linux: OracleLinux-R8-U6-x86_64-dvd.iso

# Particionamento do disco - LVMs #
Na instalação do SO Oracle Linux, em INSTALLATION DESTINATION, selecionar o LOCAL STANDARD DISKS, e em STORAGE CONFIGURATION selecionar a opção CUSTOM. Clique em DONE.

- Surgirá uma nova tela MANUAL PARTITIONING. Inclua 6 repartições, no processo nós distribuimos a memória disponpível em:

- /boot xfs - 10 gb
- /swap swap - 10 gb
- /home xfs - 10 gb
- /var xfs - 10 gb
- /tmp xfs - 10 gb
- /  xfs - 50 gb

- Na segunda máquina virtual, a memória repartida é idêntica a primeira, com a redução de espaço na partição "/" com 40 GB disponíveis. 

Após apertar em "Done", aparecerá um campo chamado "Summary of changes", aceite todo o processo de mudança e aguarde o término desta para prosseguir ao próximo passo.

# Configurando a rede # 
No campo "Network & Host name", habilite a conexão da internet no campo demarcado como "OFF", clique nela para selecionar e espere ficar azul, indicando a mudança para "ON". Após esse processo podemos também alterar o hostname diretamente, no canto inferior esquerdo da tela e alterar o "localhost".

#Criando usuário#
Ao retornar no menu principal de instalação do Linux, você notará nos campos inferiores sobre "Root Password" e "User Creation". Para criar um usuário para acessar o 
terminal, acesse "User creation". 

- No campo de "Nome completo", você poderá adicionar o seu nome normalmente e automaticamente gera um nome de usuário baseado com o que você digitou. 
- Após isso, terá 2 caixas de marcação com opções de marcar o usuário como administrador e tornar como obrigatório a opção de acesso com senha, marque os 2 campos e vá para o próximo passo que é de "Senha'. Pense em uma senha segura e fácil de utilizar e caso não tão grande, o programa pede para você confirmar 2 vezes essa senha ao clicar em "Done".
- Terminando esse processo, você pode ir diretamente ao menu de instalação e clicar em "Begin Installation".

# No terminal #
# Antes de tudo! #
Importante utilizar o "sudo yum update" para começar a baixar outras ferramentas para evitar problemas futuros com atualizações!
Instale como editor de texto o "Nano"! Para isso realize o "sudo yum install nano" e selecione "Y" para prosseguir a instalação. 
Rede da máquina virtual em CIDR/24
Instale o pacote net-tools e network-scripts: sudo yum install net-tools e/ou sudo dnf install network-scripts

# Verifique a máscara de rede (255.255.255.0): if config -a #

# Configurando Hostname #
Edite o arquivo /etc/hosts: sudo nano /etc/hostname

Reinicie a máquina: reboot

# DNS com o nome kafkadockerlab #
Edite o arquivo /etc/hosts: sudo nano /etc/hosts

Inclua uma nova linha com o ip da máquina virtual e o nome "kafkadockerlab": 192.168.100.65 - kafkadockerlab

Reinicie a máquina: reboot

# Como setar o IP Fixo? #

Verifique o nome da sua placa de rede, o seu IP e a sua mascara de rede: ifconfig -a

Edite o arquivo ifcfg-nome_da_sua_placa: sudo nano /etc/sysconfig/network-scripts/ifcfg-enp0s3

Adicione as seguintes linhas: IPADDR= 192.168.100.65 NETMASK=255.255.255.0 DNS1=192.168.0.1 e DNS2= 8.8.8.8

Altere a linha do BOOTPROTO, substituindo o "dhcp" para "none".

 # Configurando SSH #
Instale o software SSH: sudo yum install openssh-server

Ative o SSH para iniciá-lo automaticamente junto ao sistema: sudo systemctl enable sshd

# Bloqueando o acesso SSH para o root #
Edite o arquivo sshd_config: sudo nano /etc/ssh/sshd_config

Altere a linha "PermitRootLogin", substituindo o "yes" por "no".
