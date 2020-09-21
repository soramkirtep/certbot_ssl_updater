echo off

::SchTasks /Create /RU [your_user] /RP [your_password] /SC DAILY /TN "certbot_ssl_updater" /TR "%JBOSS_HOME%\..\scripts\certbot_ssl_updater\run.bat %JBOSS_HOME%\..\scripts\certbot_ssl_updater\ python" /ST 01:20 /RL HIGHEST /F
cd %JBOSS_HOME%\..\scripts\certbot_ssl_updater\
C:\Python\Python38-32\python.exe main.py
pause
exit


