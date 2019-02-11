## (Recomendado) Configuración de invitado de VirtualBox

En este momento, la única configuración plenamente compatible para desarrollar motores sobre Windows es dentro de un invitado de VirtualBox.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong> Las recomendaciones aquí incluidas son el resultado de un trabajo minucioso. Te recomendamos encarecidamente llevar a cabo las pruebas usando los parámetros exactos que se indican. Nos resultará más difícil prestarte ayuda si empleas cualquier otra configuración.
  </p>
</div>

### Requisitos del sistema

El desarrollo de motores sobre Windows impone unas exigencias nada despreciables para el host de desarrollo:

- Windows 10 (probado con Windows 10 Pro, versión 1809).
- Compatibilidad con VT-x habilitada en la BIOS.
- Mínimo de 16 GB de RAM.
- Mínimo de 4 núcleos de CPU.
- Mínimo de 100 GB de espacio en disco.

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
    <strong>Aviso:</strong> Por ahora, el desarrollo de motores en Windows fuera de una máquina virtual VirtualBox te impedirá ejecutar pruebas de integración. Te recomendamos encarecidamente que, por el momento, lleves a cabo el desarrollo dentro de un invitado Windows de VirtualBox tal y como se ha descrito anteriormente.
  </p>
</div>

Requisitos mínimos del sistema:

- Windows 10*.
- Mínimo de 4 núcleos de CPU.
- 4 GB de RAM.

*Es posible que funcionen versiones anteriores de Windows pero, por ahora, no se han probado ni se ofrece ayuda con ellas.

## Configura Windows

Necesitamos privilegios de Administrador para realizar varios cambios en la configuración por defecto de Windows. Para ello, abriremos una consola PowerShell "con privilegios"/"elevada":

- busca "PowerShell" en la barra de búsqueda del escritorio;
- haz clic con el botón derecho en "Windows PowerShell";
- selecciona "Ejecutar como administrador".

Ejecuta lo siguiente en esa consola PowerShell con privilegios:

1. Autoriza la ejecución de scripts (necesaria para instalar Chocolatey y usar entornos virtuales):
    
    ```powershell
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
    ```

2. Obliga a PowerShell a usar TLSv2 (requerido por algunas dependencias):
    
    ```powershell
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    ```

## Instala Chocolatey y los requisitos previos

Chocolatey es un gestor de paquetes para Windows. Lo emplearemos para facilitar la instalación de algunos requisitos previos.

Ejecuta lo siguiente en una consola PowerShell *con privilegios*.

1. Instala Chocolatey:
    
    ```powershell
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    ```

2. Usa Chocolatey para instalar los requisitos previos (de uno en uno):
    
    ```powershell
    choco install -y python --version 3.5.4
    choco install -y git
    choco install -y visualcpp-build-tools --version 14.0.25420.1
    ```

## Deshabilita cualquier protección contra código malicioso

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong> Te recomendamos encarecidamente deshabilitar todos los productos de protección contra código malicioso, incluida la instalación de Windows Defender integrada. A continuación, indicamos cómo deshabilitar Windows Defender. Se deja al lector el trabajo de deshabilitar cualquier otra solución de terceros.
  </p>
</div>

Se entiende que los motores de PolySwarm deben entrar en contacto con el código malicioso. Cualquier otro sistema de protección contra código malicioso, incluida la instalación de Windows Defender integrada, podría fácilmente interferir y poner en cuarentena o borrar archivos durante el desarrollo.

Deshabilitar Windows Defender consta de dos pasos:

1. Ejecuta el siguiente comando en un PowerShell con privilegios:
    
    ```powershell
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1
    ```

2. Reinicia Windows.

## Configura un entorno virtual (virtualenv)

Si piensas usar esta instalación de Windows para otros fines, te recomendamos mantener limpios los paquetes de Python que afectan a todo el sistema creando un entorno virtual virtualenv de PolySwarm:

```bash
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

## Instala las bibliotecas de `polyswarm-client`

<div class="m-flag">
  <p>
    <strong>Información:</strong> Si estás usando un entorno virtual (ver arriba), asegúrate de activarlo antes de instalar "polyswarm-client".
  </p>
</div>

Instalar `polyswarm-client` es muy sencillo:

```bash
pip install polyswarm-client
```

## Verificar la instalación

¡Ahora ya deberías tener un entorno de desarrollo funcional!

Para comprobarlo, intenta importar `polyswarmclient`:

```bash
$ python
Python 3.5.4 (v3.5.4:3f56838, Aug  8 2017, 02:17:05) [MSC v.1900 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import polyswarmclient
>>>
```

La importación de `polyswarmclient` debería llevarse a cabo sin problemas.

A continuación, te guiaremos en la creación de tu propio micromotor de PolySwarm, capaz de detectar el archivo de prueba EICAR.

[Crea un micromotor "Hola mundo" →](/microengines-scratch-to-eicar/)