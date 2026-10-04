Шаблоны server.json XRay — дословно из исходников amnezia-client, без чужих
секретов (переменные $XRAY_* подставляет fakesrv.NewXRay случайными значениями):

server.master.json — master, client/server_scripts/xray/configure_container.sh
  (heredoc `cat > /opt/amnezia/xray/server.json`) — форма серверов, поставленных
  выпусками приложения до dev.
server.dev.json    — dev 94b51df, client/core/configurators/xrayConfigurator.cpp:371-458
  (writeServerConfigForSetup, transport raw, security reality) так, как его
  сериализует QJsonDocument::toJson: ключи по алфавиту, отступ 4 пробела.
