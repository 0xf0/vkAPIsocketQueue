# vkAPIsocketQueue
+ Заебались получать от VK API ошибку #6 (Слишком много запросов в секунду)? (https://vk.com/dev/api_requests)
+ Вы криворукий болван и не знаете, что с этим делать?
+ Вам нужен простой метод для выполнения запросов к VK API?
Тогда этот высер для вас!

## Как юзать
Пример в test.py, нужно только вставить ваш token и id для проверки.
Дальше сами разберетесь (или нет). Для того, чтобы узнать, как получить токен от вк, придется заглянуть в get_vk_token.py.

**Требования**: python 3, [_requests_](http://docs.python-requests.org/en/master/user/install/#install), _ssl-сертификат_

##  Как сделать сертификат
Генерим приватный ключ:

`openssl genrsa -des3 -out server.key 1024`

Попутно будет предложено ввести пароль к ключу и подтверждение пароля, вводим. Создаем запрос на сертификат:

`openssl req -new -key server.key -out server.csr`

При генерации запроса нам нужно будет ввести пароль ключа и заполнить информацию о компании, городе, стране и т.д. Заполняем. Для того, чтобы можно было использовать ключ без пароля, копируем его и распароливаем:

`cp server.key server.key.org`

`openssl rsa -in server.key.org -out server.key`

Наконец, создаем самоподписанный сертификат:

`openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt`

## Копирайты-хуетирайты, лицензии-хуилицензии
Говнокод выпущен под [WTFPL – Do What the Fuck You Want to Public License](LICENSE.txt).