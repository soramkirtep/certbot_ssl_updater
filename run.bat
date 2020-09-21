REM install (in this order) python, add path to python in env var, openssl, certbot
REM install pip "python %JBOSS_HOME%\..\scripts\certbot_ssl_updater\materials\get-pip.py"
REM install "pip install -r %JBOSS_HOME%\..\scripts\certbot_ssl_updater\requirements.txt"
REM edit main.conf
REM runs certbot_ssl_updater\run.bat
echo off

::SchTasks /Create /RU [your_user] /RP [your_password] /SC DAILY /TN "certbot_ssl_updater" /TR "%JBOSS_HOME%\..\scripts\certbot_ssl_updater\run.bat %JBOSS_HOME%\..\scripts\certbot_ssl_updater\ python" /ST 01:20 /RL HIGHEST /F
cd %1
%2 main.py

exit


