Template: samba/run_mode
Type: select
Default: daemons
Choices: daemons, inetd
Choices-es: demonios, inetd
Description: How do you want to run Samba?
 The Samba services (nmbd and smbd) can run as normal daemons or 
 from inetd. Running as daemons is the recommended approach.
Description-es: �C�mo quiere que Samba se ejecute?
 Los servicios Samba (nmbd y smbd) pueden ejecutarse como demonios
 normales o desde el inetd.  Se recomienda que se ejecuten como demonios
 independientes.

Template: samba/generate_smbpasswd
Type: boolean
Default: false
Description: Create samba password file, /etc/samba/smbpasswd?
 To be compatible with the defaults in most versions of Windows,
 Samba must be configured to use encrypted passwords.  This requires
 user passwords to be stored in a file separate from /etc/passwd.
 This file can be created automatically, but the passwords must
 be added manually (by you or the user) by running smbpasswd,
 and you must arrange to keep it up-to-date in the future.  If
 you do not create it, you will have to reconfigure samba
 (and probably your client machines) to use plaintext passwords.
 See /usr/share/doc/samba-doc/htmldocs/ENCRYPTION.html from the 
 samba-doc package for more details.
Description-es: �Crear el fichero de contrase�as /etc/samba/smbpasswd?
 Para manterner compatibilidad con el comportamiento por defecto de la
 mayoria de los sistemas Windows, hay que configurar Samba para que use
 contrase�as encriptadas, lo cual requiere la creaci�n de un fichero
 distinto del /etc/passwd donde se guarden las contrase�as de los usuarios.
 El fichero se puede crear automaticamente, aunque es necesario a�adir
 las contrase�as manualmente (por usted o por el usuario) usando
 el programa `smbpasswd', y usted debe hacer arreglos para mantener las
 contrase�as al d�a.  Si no se crea este fichero, es imprescindible
 configurar Samba (y posiblemente los ordenadores Windows) para usar
 contrase�as no cifradas.  V�a
 /usr/share/doc/samba-doc/htmldocs/ENCRYPTION.html del paquete samba-doc
 para m�s informaci�n.

Template: samba/log_files_moved
Type: note
Description: Samba's log files have moved.
 Starting with the first packages of Samba 2.2 for Debian the log
 files for both Samba daemons (nmbd and smbd) are now stored in
 /var/log/samba/. The names of the files are log.nmbd and log.smbd,
 for nmbd and smbd respectively.
 .
 The old log files that were in /var/log/ will be moved to
 the new location for you.
Description-es: Se han movido los ficheros de registro de Samba.
 A partir de los primeros paquetes de Samba 2.2 para Debian,
 los ficheros de registro para los dos demonios del Samba (nmbd y smbd)
 se encuentran en /var/log/samba/.  Los nombres de estos ficheros
 son log.nmbd y log.smbd, para nmbd y smbd respectivamente.
