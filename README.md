# SimpleAESCipher

### Курсовая работа

Программа для шифрования различных файлов в режиме AES CTR использующая PKCSPadding7, написанная для курсовой работы.
Имеет простой интерфейс написанный с использованием javaFX, также использует Preferences API для хранения значения Nonce,
который является частью режима шифрования CTR.

Добавлена возможность создавать и проверять коды аутентификации сообщений (message authentication code): ECBC и HMAC(MD5).

В качестве ключа можно использовать как различные символьные комбинации так и отдельные файлы.
