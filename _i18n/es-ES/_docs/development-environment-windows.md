## (Recomendado) Configuración de invitado de VirtualBox

En este momento, la única configuración plenamente compatible para desarrollar motores sobre Windows es dentro de un invitado de VirtualBox.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong> Las recomendaciones aquí incluidas son el resultado de un trabajo minucioso. Te recomendamos encarecidamente llevar a cabo las pruebas usando los parámetros exactos que se indican. Nos resultará más difícil prestarte ayuda si empleas cualquier otra configuración.
  </p>
</div>

### Requisitos del sistema

El desarrollo de motores sobre Windows impone unas exigencias nada despreciables para el host de desarrollo:

- Windows 10 (probado con Windows 10 Pro, versión 1809)
- Compatibilidad con VT-x habilitada en la BIOS
- Mínimo de 16 GB de RAM
- Mínimo de 4 núcleos de CPU
- Mínimo de 100 GB de espacio en disco

Usaremos VirtualBox. **VirtualBox deberá ser el propietario exclusivo de tu hipervisor**. Ello implica que no puedes ejecutar:

- Hyper-V,
- Windows Credential Guard,
- Windows Device Guard,
- VMWare Workstation o Player, o
- cualquier otro producto que use extensiones para hipervisor.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong> La virtualización anidada NO es una configuración compatible en la actualidad.
  </p>
  
  <p>
    Estas instrucciones asumen que la instalación host de Windows se ejecuta "en limpio". Próximamente se incluirán instrucciones específicas para desarrollar bajo un hipervisor (por ejemplo, AWS).
  </p>
</div>

### Requisitos previos

- [Descarga e instala VirtualBox](https://www.virtualbox.org/wiki/Downloads). En nuestras pruebas hemos usado VirtualBox 5.2.22.
- [Descarga la imagen ISO de Windows 10 Pro](https://www.microsoft.com/en-us/software-download/windows10ISO). Usa Media Creation Tool para crear una imagen .iso. En nuestras pruebas hemos usado Windows 10 Pro en su compilación 10240.

### Crea un invitado de Windows

Usa VirtualBox para crear una máquina virtual de Windows usando los siguientes parámetros:

- Nombre: `polyswarm_win`
- Tipo: Microsoft Windows
- Versión: Windows 10 (64 bits)
- RAM: 4 GB o más
- CPU: 2 núcleos o más
- Memoria de vídeo: 128 MB
- Espacio en disco: 50 GB o más

Usa la configuración por defecto para las demás opciones. Sobre todo, **NO habilites la aceleración 3D**.

### Instala Windows 10

Usa la ISO que has descargado para instalar Windows en la máquina virtual.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong> No se recomienda realizar actualizaciones de Windows en una máquina virtual de VirtualBox, ya que es muy probable que la dejen en un estado imposible de arrancar. Recomendamos <a href="https://www.thewindowsclub.com/turn-off-windows-update-in-windows-10">deshabilitar Windows Update</a> tan pronto como instales Windows en ella.
  </p>
</div>

### Instala adiciones de invitados de VirtualBox

Las adiciones de invitados ("Guest Additions") son necesarias para disfrutar de las funciones de portapapeles compartido o copiar y pegar entre el invitado y el host.

[Consulta el manual de VirtualBox](https://www.virtualbox.org/manual/ch04.html).

### Creación de invitado completada

Una vez instaladas las adiciones de invitados, ya estás listo para [Configurar Windows](#configure-windows) de cara al desarrollo dentro de la máquina virtual.

## Configuración personalizada (no compatible)

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong> Por ahora, el desarrollo de motores en Windows fuera de una máquina virtual VirtualBox te impedirá ejecutar pruebas de integración. We strongly recommend that you conduct development inside of a Windows VirtualBox Guest (described above) at this time.
  </p>
</div>

Minimum system requirements:

- Windows 10*
- Mínimo de 4 núcleos de CPU
- 4GB of RAM

*Older versions of Windows may work, but are untested (and unsupported) at this time.

## Configure Windows

We'll need to use Administrator privilege to make several changes to default Windows settings. We'll need an "elevated" / "privileged" PowerShell console:

- search "PowerShell" in the desktop search bar
- right click on "Windows PowerShell"
- select "Run as administrator".

Run the following in this privileged PowerShell console.

1. Permit script execution (necessary for installing Chocolatey & using virtualenvs):
    
    ```powershell
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
    ```

2. Force PowerShell to use TLSv2 (required of some dependancies):
    
    ```powershell
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    ```

## Install Chocolatey & Prerequisities

Chocolatey is a package manager for Windows. We'll use it to help with installing some prerequisites.

Run the following in a *privileged* PowerShell console.

1. Install Chocolatey:
    
    ```powershell
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    ```

2. Use Chocolatey to install prerequisites (do these one at a time):
    
    ```powershell
    choco install -y python --version 3.5.4
    choco install -y git
    choco install -y visualcpp-build-tools --version 14.0.25420.1
    ```

## Disable Anti-Malware Products

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    We strongly recommend disabling all anti-malware products in your development environment - including the built-in Windows Defender.
    Below, we describe disabling Windows Defender.
    Disabling third party solutions is left as an exercise for the reader.
  </p>
</div>

PolySwarm engines should expect to come into contact with malware. Existing anti-malware engines, including the built-in Windows Defender, can easily get in our way, quarantining or deleting files during development.

Disabling Windows Defender is a two step process.

1. Run the following command in a privileged PowerShell:
    
    ```powershell
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1
    ```

2. Reboot Windows.

## Set up a Virtual Environment (virtualenv)

If you plan to use this Windows installation for other purposes, we recommend that you create a PolySwarm virtualenv so as to keep the system-wide Python packages clean:

```bash
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

## Instala las bibliotecas de `polyswarm-client`

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    If you're using a virtualenv (see above), ensure that you activate it before installing `polyswarm-client`.
  </p>
</div>

Installing `polyswarm-client` is as simple as:

```bash
pip install polyswarm-client
```

## Verificar la instalación

You should now have a working development environment!

To verify, simply try importing `polyswarmclient`:

```bash
$ python
Python 3.5.4 (v3.5.4:3f56838, Aug  8 2017, 02:17:05) [MSC v.1900 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import polyswarmclient
>>>
```

You should be able to import `polyswarmclient` without issue.

Next, we'll walk you through building your very own PolySwarm Microengine, capable of detecting the EICAR test file.

[Make a "Hello World" Microengine →](/microengines-scratch-to-eicar/)